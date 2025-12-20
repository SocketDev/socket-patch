import * as fs from 'fs/promises'
import * as path from 'path'
import * as os from 'os'
import type { CommandModule } from 'yargs'
import {
  PatchManifestSchema,
  DEFAULT_PATCH_MANIFEST_PATH,
  type PatchManifest,
  type PatchRecord,
} from '../schema/manifest-schema.js'
import {
  findNodeModules,
  findPackagesForPatches,
} from '../patch/apply.js'
import { rollbackPackagePatch } from '../patch/rollback.js'
import type { RollbackResult } from '../patch/rollback.js'
import {
  fetchBlobsByHash,
  formatFetchResult,
} from '../utils/blob-fetcher.js'
import { getGlobalPrefix } from '../utils/global-packages.js'
import { getAPIClientFromEnv } from '../utils/api-client.js'
import {
  trackPatchRolledBack,
  trackPatchRollbackFailed,
} from '../utils/telemetry.js'

interface RollbackArgs {
  identifier?: string
  cwd: string
  'dry-run': boolean
  silent: boolean
  'manifest-path': string
  offline: boolean
  global: boolean
  'global-prefix'?: string
  'one-off': boolean
  org?: string
  'api-url'?: string
  'api-token'?: string
}

interface PatchToRollback {
  purl: string
  patch: PatchRecord
}

/**
 * Find patches to rollback based on identifier
 * - If identifier starts with 'pkg:' -> treat as PURL
 * - Otherwise -> treat as UUID
 * - If no identifier -> return all patches
 */
function findPatchesToRollback(
  manifest: PatchManifest,
  identifier?: string,
): PatchToRollback[] {
  if (!identifier) {
    // Rollback all patches
    return Object.entries(manifest.patches).map(([purl, patch]) => ({
      purl,
      patch,
    }))
  }

  const patches: PatchToRollback[] = []

  if (identifier.startsWith('pkg:')) {
    // Search by PURL - exact match
    const patch = manifest.patches[identifier]
    if (patch) {
      patches.push({ purl: identifier, patch })
    }
  } else {
    // Search by UUID - search through all patches
    for (const [purl, patch] of Object.entries(manifest.patches)) {
      if (patch.uuid === identifier) {
        patches.push({ purl, patch })
      }
    }
  }

  return patches
}

/**
 * Get the set of beforeHash blobs needed for rollback.
 * These are different from the afterHash blobs needed for apply.
 */
function getBeforeHashBlobs(manifest: PatchManifest): Set<string> {
  const blobs = new Set<string>()
  for (const patchRecord of Object.values(manifest.patches)) {
    const record = patchRecord as PatchRecord
    for (const fileInfo of Object.values(record.files)) {
      blobs.add(fileInfo.beforeHash)
    }
  }
  return blobs
}

/**
 * Check which beforeHash blobs are missing from disk.
 */
async function getMissingBeforeBlobs(
  manifest: PatchManifest,
  blobsPath: string,
): Promise<Set<string>> {
  const beforeBlobs = getBeforeHashBlobs(manifest)
  const missingBlobs = new Set<string>()

  for (const hash of beforeBlobs) {
    const blobPath = path.join(blobsPath, hash)
    try {
      await fs.access(blobPath)
    } catch {
      missingBlobs.add(hash)
    }
  }

  return missingBlobs
}

async function rollbackPatches(
  cwd: string,
  manifestPath: string,
  identifier: string | undefined,
  dryRun: boolean,
  silent: boolean,
  offline: boolean,
  useGlobal: boolean,
  globalPrefix?: string,
): Promise<{ success: boolean; results: RollbackResult[] }> {
  // Read and parse manifest
  const manifestContent = await fs.readFile(manifestPath, 'utf-8')
  const manifestData = JSON.parse(manifestContent)
  const manifest = PatchManifestSchema.parse(manifestData)

  // Find .socket directory (contains blobs)
  const socketDir = path.dirname(manifestPath)
  const blobsPath = path.join(socketDir, 'blobs')

  // Ensure blobs directory exists
  await fs.mkdir(blobsPath, { recursive: true })

  // Find patches to rollback
  const patchesToRollback = findPatchesToRollback(manifest, identifier)

  if (patchesToRollback.length === 0) {
    if (identifier) {
      throw new Error(`No patch found matching identifier: ${identifier}`)
    }
    if (!silent) {
      console.log('No patches found in manifest')
    }
    return { success: true, results: [] }
  }

  // Create a filtered manifest containing only the patches we want to rollback
  const filteredManifest: PatchManifest = {
    patches: Object.fromEntries(
      patchesToRollback.map(p => [p.purl, p.patch]),
    ),
  }

  // Check for and download missing beforeHash blobs (unless offline)
  // Rollback needs the original (beforeHash) blobs, not the patched (afterHash) blobs
  const missingBlobs = await getMissingBeforeBlobs(filteredManifest, blobsPath)
  if (missingBlobs.size > 0) {
    if (offline) {
      if (!silent) {
        console.error(
          `Error: ${missingBlobs.size} blob(s) are missing and --offline mode is enabled.`,
        )
        console.error('Run "socket-patch repair" to download missing blobs.')
      }
      return { success: false, results: [] }
    }

    if (!silent) {
      console.log(`Downloading ${missingBlobs.size} missing blob(s)...`)
    }

    // Use fetchBlobsByHash to download the specific beforeHash blobs
    const fetchResult = await fetchBlobsByHash(missingBlobs, blobsPath, undefined, {
      onProgress: silent
        ? undefined
        : (hash, index, total) => {
            process.stdout.write(
              `\r  Downloading ${index}/${total}: ${hash.slice(0, 12)}...`.padEnd(60),
            )
          },
    })

    if (!silent) {
      // Clear progress line
      process.stdout.write('\r' + ' '.repeat(60) + '\r')
      console.log(formatFetchResult(fetchResult))
    }

    // Re-check which blobs are still missing after download
    const stillMissing = await getMissingBeforeBlobs(filteredManifest, blobsPath)
    if (stillMissing.size > 0) {
      if (!silent) {
        console.error(`${stillMissing.size} blob(s) could not be downloaded. Cannot rollback.`)
      }
      return { success: false, results: [] }
    }
  }

  // Find node_modules directories
  let nodeModulesPaths: string[]
  if (useGlobal || globalPrefix) {
    try {
      nodeModulesPaths = [getGlobalPrefix(globalPrefix)]
      if (!silent) {
        console.log(`Using global npm packages at: ${nodeModulesPaths[0]}`)
      }
    } catch (error) {
      if (!silent) {
        console.error('Failed to find global npm packages:', error instanceof Error ? error.message : String(error))
      }
      return { success: false, results: [] }
    }
  } else {
    nodeModulesPaths = await findNodeModules(cwd)
  }

  if (nodeModulesPaths.length === 0) {
    if (!silent) {
      console.error(useGlobal || globalPrefix ? 'No global npm packages found' : 'No node_modules directories found')
    }
    return { success: false, results: [] }
  }

  // Find all packages that need rollback
  const allPackages = new Map<string, string>()
  for (const nmPath of nodeModulesPaths) {
    const packages = await findPackagesForPatches(nmPath, filteredManifest)
    for (const [purl, location] of packages) {
      if (!allPackages.has(purl)) {
        allPackages.set(purl, location.path)
      }
    }
  }

  if (allPackages.size === 0) {
    if (!silent) {
      console.log('No packages found that match patches to rollback')
    }
    return { success: true, results: [] }
  }

  // Rollback patches for each package
  const results: RollbackResult[] = []
  let hasErrors = false

  for (const [purl, pkgPath] of allPackages) {
    const patch = filteredManifest.patches[purl]
    if (!patch) continue

    const result = await rollbackPackagePatch(
      purl,
      pkgPath,
      patch.files,
      blobsPath,
      dryRun,
    )

    results.push(result)

    if (!result.success) {
      hasErrors = true
      if (!silent) {
        console.error(`Failed to rollback ${purl}: ${result.error}`)
      }
    }
  }

  return { success: !hasErrors, results }
}

export const rollbackCommand: CommandModule<{}, RollbackArgs> = {
  command: 'rollback [identifier]',
  describe: 'Rollback patches to restore original files',
  builder: yargs => {
    return yargs
      .positional('identifier', {
        describe:
          'Package PURL (e.g., pkg:npm/package@version) or patch UUID to rollback. Omit to rollback all patches.',
        type: 'string',
      })
      .option('cwd', {
        describe: 'Working directory',
        type: 'string',
        default: process.cwd(),
      })
      .option('dry-run', {
        alias: 'd',
        describe: 'Verify rollback can be performed without modifying files',
        type: 'boolean',
        default: false,
      })
      .option('silent', {
        alias: 's',
        describe: 'Only output errors',
        type: 'boolean',
        default: false,
      })
      .option('manifest-path', {
        alias: 'm',
        describe: 'Path to patch manifest file',
        type: 'string',
        default: DEFAULT_PATCH_MANIFEST_PATH,
      })
      .option('offline', {
        describe: 'Do not download missing blobs, fail if any are missing',
        type: 'boolean',
        default: false,
      })
      .option('global', {
        alias: 'g',
        describe: 'Rollback patches from globally installed npm packages',
        type: 'boolean',
        default: false,
      })
      .option('global-prefix', {
        describe: 'Custom path to global node_modules (overrides auto-detection, useful for yarn/pnpm)',
        type: 'string',
      })
      .option('one-off', {
        describe: 'Rollback a patch by fetching beforeHash blobs from API (no manifest required)',
        type: 'boolean',
        default: false,
      })
      .option('org', {
        describe: 'Organization slug (required for --one-off when using SOCKET_API_TOKEN)',
        type: 'string',
      })
      .option('api-url', {
        describe: 'Socket API URL (overrides SOCKET_API_URL env var)',
        type: 'string',
      })
      .option('api-token', {
        describe: 'Socket API token (overrides SOCKET_API_TOKEN env var)',
        type: 'string',
      })
      .example('$0 rollback', 'Rollback all patches')
      .example(
        '$0 rollback pkg:npm/lodash@4.17.21',
        'Rollback patches for a specific package',
      )
      .example(
        '$0 rollback 12345678-1234-1234-1234-123456789abc',
        'Rollback a patch by UUID',
      )
      .example('$0 rollback --dry-run', 'Preview what would be rolled back')
      .example('$0 rollback --global', 'Rollback patches from global npm packages')
      .example(
        '$0 rollback pkg:npm/lodash@4.17.21 --one-off --global',
        'Rollback global package by fetching blobs from API',
      )
      .check(argv => {
        if (argv['one-off'] && !argv.identifier) {
          throw new Error('--one-off requires an identifier (UUID or PURL)')
        }
        return true
      })
  },
  handler: async argv => {
    // Get API credentials for authenticated telemetry (optional).
    const apiToken = argv['api-token'] || process.env['SOCKET_API_TOKEN']
    const orgSlug = argv.org || process.env['SOCKET_ORG_SLUG']

    try {
      // Handle one-off mode (no manifest required)
      if (argv['one-off']) {
        const success = await rollbackOneOff(
          argv.identifier!,
          argv.cwd,
          argv.global,
          argv['global-prefix'],
          argv['dry-run'],
          argv.silent,
          argv.org,
          argv['api-url'],
          argv['api-token'],
        )

        // Track telemetry for one-off rollback.
        if (success) {
          await trackPatchRolledBack(1, apiToken, orgSlug)
        } else {
          await trackPatchRollbackFailed(
            new Error('One-off rollback failed'),
            apiToken,
            orgSlug,
          )
        }

        process.exit(success ? 0 : 1)
      }

      const manifestPath = path.isAbsolute(argv['manifest-path'])
        ? argv['manifest-path']
        : path.join(argv.cwd, argv['manifest-path'])

      // Check if manifest exists
      try {
        await fs.access(manifestPath)
      } catch {
        if (!argv.silent) {
          console.error(`Manifest not found at ${manifestPath}`)
        }
        process.exit(1)
      }

      const { success, results } = await rollbackPatches(
        argv.cwd,
        manifestPath,
        argv.identifier,
        argv['dry-run'],
        argv.silent,
        argv.offline,
        argv.global,
        argv['global-prefix'],
      )

      // Print results if not silent
      if (!argv.silent && results.length > 0) {
        const rolledBack = results.filter(r => r.success && r.filesRolledBack.length > 0)
        const alreadyOriginal = results.filter(r =>
          r.success && r.filesVerified.every(f => f.status === 'already-original'),
        )
        const failed = results.filter(r => !r.success)

        if (argv['dry-run']) {
          console.log('\nRollback verification complete:')
          const canRollback = results.filter(r => r.success)
          console.log(`  ${canRollback.length} package(s) can be rolled back`)
          if (alreadyOriginal.length > 0) {
            console.log(
              `  ${alreadyOriginal.length} package(s) already in original state`,
            )
          }
          if (failed.length > 0) {
            console.log(`  ${failed.length} package(s) cannot be rolled back`)
          }
        } else {
          if (rolledBack.length > 0 || alreadyOriginal.length > 0) {
            console.log('\nRolled back packages:')
            for (const result of rolledBack) {
              console.log(`  ${result.packageKey}`)
            }
            for (const result of alreadyOriginal) {
              console.log(`  ${result.packageKey} (already original)`)
            }
          }
          if (failed.length > 0) {
            console.log('\nFailed to rollback:')
            for (const result of failed) {
              console.log(`  ${result.packageKey}: ${result.error}`)
            }
          }
        }
      }

      // Track telemetry event.
      const rolledBackCount = results.filter(r => r.success && r.filesRolledBack.length > 0).length
      if (success) {
        await trackPatchRolledBack(rolledBackCount, apiToken, orgSlug)
      } else {
        await trackPatchRollbackFailed(
          new Error('One or more rollbacks failed'),
          apiToken,
          orgSlug,
        )
      }

      process.exit(success ? 0 : 1)
    } catch (err) {
      // Track telemetry for unexpected errors.
      const error = err instanceof Error ? err : new Error(String(err))
      await trackPatchRollbackFailed(error, apiToken, orgSlug)

      if (!argv.silent) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        console.error(`Error: ${errorMessage}`)
      }
      process.exit(1)
    }
  },
}

/**
 * Parse a PURL to extract the package directory path and version
 */
function parsePurl(purl: string): { packageDir: string; version: string } | null {
  const match = purl.match(/^pkg:npm\/(.+)@([^@]+)$/)
  if (!match) return null
  return { packageDir: match[1], version: match[2] }
}

/**
 * Rollback a patch without using the manifest (one-off mode)
 * Downloads beforeHash blobs from API on demand
 */
async function rollbackOneOff(
  identifier: string,
  cwd: string,
  useGlobal: boolean,
  globalPrefix: string | undefined,
  dryRun: boolean,
  silent: boolean,
  orgSlug: string | undefined,
  apiUrl: string | undefined,
  apiToken: string | undefined,
): Promise<boolean> {
  // Override environment variables if CLI options are provided
  if (apiUrl) {
    process.env.SOCKET_API_URL = apiUrl
  }
  if (apiToken) {
    process.env.SOCKET_API_TOKEN = apiToken
  }

  // Get API client
  const { client: apiClient, usePublicProxy } = getAPIClientFromEnv()

  // Validate that org is provided when using authenticated API
  if (!usePublicProxy && !orgSlug) {
    throw new Error(
      '--org is required when using SOCKET_API_TOKEN. Provide an organization slug.',
    )
  }

  const effectiveOrgSlug = usePublicProxy ? null : orgSlug ?? null

  if (!silent) {
    console.log(`Fetching patch data for: ${identifier}`)
  }

  // Fetch the patch (can be UUID or PURL)
  let patch
  if (identifier.startsWith('pkg:')) {
    // Search by PURL
    const searchResponse = await apiClient.searchPatchesByPackage(effectiveOrgSlug, identifier)
    if (searchResponse.patches.length === 0) {
      throw new Error(`No patch found for PURL: ${identifier}`)
    }
    patch = await apiClient.fetchPatch(effectiveOrgSlug, searchResponse.patches[0].uuid)
  } else {
    // Assume UUID
    patch = await apiClient.fetchPatch(effectiveOrgSlug, identifier)
  }

  if (!patch) {
    throw new Error(`Could not fetch patch: ${identifier}`)
  }

  // Determine node_modules path
  let nodeModulesPath: string
  if (useGlobal || globalPrefix) {
    try {
      nodeModulesPath = getGlobalPrefix(globalPrefix)
      if (!silent) {
        console.log(`Using global npm packages at: ${nodeModulesPath}`)
      }
    } catch (error) {
      throw new Error(
        `Failed to find global npm packages: ${error instanceof Error ? error.message : String(error)}`,
      )
    }
  } else {
    nodeModulesPath = path.join(cwd, 'node_modules')
  }

  // Parse PURL to get package directory
  const parsed = parsePurl(patch.purl)
  if (!parsed) {
    throw new Error(`Invalid PURL format: ${patch.purl}`)
  }

  const pkgPath = path.join(nodeModulesPath, parsed.packageDir)

  // Verify package exists
  try {
    const pkgJsonPath = path.join(pkgPath, 'package.json')
    const pkgJsonContent = await fs.readFile(pkgJsonPath, 'utf-8')
    const pkgJson = JSON.parse(pkgJsonContent)
    if (pkgJson.version !== parsed.version) {
      if (!silent) {
        console.log(`Note: Installed version ${pkgJson.version} differs from patch version ${parsed.version}`)
      }
    }
  } catch {
    throw new Error(`Package not found: ${parsed.packageDir}`)
  }

  // Create temporary directory for blobs
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'socket-patch-'))
  const tempBlobsDir = path.join(tempDir, 'blobs')
  await fs.mkdir(tempBlobsDir, { recursive: true })

  try {
    // Download beforeHash blobs
    const beforeHashes = new Set<string>()
    for (const fileInfo of Object.values(patch.files)) {
      if (fileInfo.beforeHash) {
        beforeHashes.add(fileInfo.beforeHash)
      }
      // Also save beforeBlobContent if available
      if (fileInfo.beforeBlobContent && fileInfo.beforeHash) {
        const blobBuffer = Buffer.from(fileInfo.beforeBlobContent, 'base64')
        await fs.writeFile(path.join(tempBlobsDir, fileInfo.beforeHash), blobBuffer)
        beforeHashes.delete(fileInfo.beforeHash)
      }
    }

    // Fetch any missing beforeHash blobs
    if (beforeHashes.size > 0) {
      if (!silent) {
        console.log(`Downloading ${beforeHashes.size} blob(s) for rollback...`)
      }
      const fetchResult = await fetchBlobsByHash(beforeHashes, tempBlobsDir, undefined, {
        onProgress: silent
          ? undefined
          : (hash, index, total) => {
              process.stdout.write(
                `\r  Downloading ${index}/${total}: ${hash.slice(0, 12)}...`.padEnd(60),
              )
            },
      })
      if (!silent) {
        process.stdout.write('\r' + ' '.repeat(60) + '\r')
        console.log(formatFetchResult(fetchResult))
      }
      if (fetchResult.failed > 0) {
        throw new Error('Some blobs could not be downloaded. Cannot rollback.')
      }
    }

    // Build files record
    const files: Record<string, { beforeHash: string; afterHash: string }> = {}
    for (const [filePath, fileInfo] of Object.entries(patch.files)) {
      if (fileInfo.beforeHash && fileInfo.afterHash) {
        files[filePath] = {
          beforeHash: fileInfo.beforeHash,
          afterHash: fileInfo.afterHash,
        }
      }
    }

    if (dryRun) {
      if (!silent) {
        console.log(`\nDry run: Would rollback ${patch.purl}`)
        console.log(`  Files: ${Object.keys(files).length}`)
      }
      return true
    }

    // Perform rollback
    const result = await rollbackPackagePatch(
      patch.purl,
      pkgPath,
      files,
      tempBlobsDir,
      false,
    )

    if (result.success) {
      if (!silent) {
        if (result.filesRolledBack.length > 0) {
          console.log(`\nRolled back ${patch.purl}`)
        } else if (result.filesVerified.every(f => f.status === 'already-original')) {
          console.log(`\n${patch.purl} is already in original state`)
        }
      }
      return true
    } else {
      throw new Error(result.error || 'Unknown rollback error')
    }
  } finally {
    // Clean up temp directory
    await fs.rm(tempDir, { recursive: true, force: true })
  }
}

// Export the rollback function for use by other commands (e.g., remove)
export { rollbackPatches, findPatchesToRollback }

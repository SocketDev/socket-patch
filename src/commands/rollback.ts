import * as fs from 'fs/promises'
import * as path from 'path'
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

interface RollbackArgs {
  identifier?: string
  cwd: string
  'dry-run': boolean
  silent: boolean
  'manifest-path': string
  offline: boolean
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

  // Find all node_modules directories
  const nodeModulesPaths = await findNodeModules(cwd)

  if (nodeModulesPaths.length === 0) {
    if (!silent) {
      console.error('No node_modules directories found')
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
  },
  handler: async argv => {
    try {
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

      process.exit(success ? 0 : 1)
    } catch (err) {
      if (!argv.silent) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        console.error(`Error: ${errorMessage}`)
      }
      process.exit(1)
    }
  },
}

// Export the rollback function for use by other commands (e.g., remove)
export { rollbackPatches, findPatchesToRollback }

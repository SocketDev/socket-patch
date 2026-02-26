import * as fs from 'fs/promises'
import * as path from 'path'
import type { CommandModule } from 'yargs'
import {
  PatchManifestSchema,
  DEFAULT_PATCH_MANIFEST_PATH,
} from '../schema/manifest-schema.js'
import { applyPackagePatch } from '../patch/apply.js'
import type { ApplyResult } from '../patch/apply.js'
import {
  cleanupUnusedBlobs,
  formatCleanupResult,
} from '../utils/cleanup-blobs.js'
import {
  getMissingBlobs,
  fetchMissingBlobs,
  formatFetchResult,
} from '../utils/blob-fetcher.js'
import { NpmCrawler, PythonCrawler } from '../crawlers/index.js'
import {
  isPyPIPurl,
  isNpmPurl,
  stripPurlQualifiers,
} from '../utils/purl-utils.js'
import { verifyFilePatch } from '../patch/apply.js'
import {
  trackPatchApplied,
  trackPatchApplyFailed,
} from '../utils/telemetry.js'

interface ApplyArgs {
  cwd: string
  'dry-run': boolean
  silent: boolean
  'manifest-path': string
  offline: boolean
  global: boolean
  'global-prefix'?: string
  ecosystems?: string[]
}

async function applyPatches(
  cwd: string,
  manifestPath: string,
  dryRun: boolean,
  silent: boolean,
  offline: boolean,
  useGlobal: boolean,
  globalPrefix?: string,
  ecosystems?: string[],
): Promise<{ success: boolean; results: ApplyResult[] }> {
  // Read and parse manifest
  const manifestContent = await fs.readFile(manifestPath, 'utf-8')
  const manifestData = JSON.parse(manifestContent)
  const manifest = PatchManifestSchema.parse(manifestData)

  // Find .socket directory (contains blobs)
  const socketDir = path.dirname(manifestPath)
  const blobsPath = path.join(socketDir, 'blobs')

  // Ensure blobs directory exists
  await fs.mkdir(blobsPath, { recursive: true })

  // Check for and download missing blobs (unless offline)
  const missingBlobs = await getMissingBlobs(manifest, blobsPath)
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

    const fetchResult = await fetchMissingBlobs(manifest, blobsPath, undefined, {
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

    if (fetchResult.failed > 0) {
      if (!silent) {
        console.error('Some blobs could not be downloaded. Cannot apply patches.')
      }
      return { success: false, results: [] }
    }
  }

  // Partition manifest PURLs by ecosystem
  const manifestPurls = Object.keys(manifest.patches)
  let npmPurls = manifestPurls.filter(p => isNpmPurl(p))
  let pypiPurls = manifestPurls.filter(p => isPyPIPurl(p))

  // Filter by ecosystem if specified
  if (ecosystems && ecosystems.length > 0) {
    if (!ecosystems.includes('npm')) npmPurls = []
    if (!ecosystems.includes('pypi')) pypiPurls = []
  }

  const crawlerOptions = {
    cwd,
    global: useGlobal,
    globalPrefix,
  }

  // allPackages maps purl -> package path on disk
  const allPackages = new Map<string, string>()

  // Find npm packages
  if (npmPurls.length > 0) {
    const npmCrawler = new NpmCrawler()
    try {
      const nodeModulesPaths = await npmCrawler.getNodeModulesPaths(crawlerOptions)
      if ((useGlobal || globalPrefix) && !silent && nodeModulesPaths.length > 0) {
        console.log(`Using global npm packages at: ${nodeModulesPaths[0]}`)
      }
      for (const nmPath of nodeModulesPaths) {
        const packages = await npmCrawler.findByPurls(nmPath, npmPurls)
        for (const [purl, location] of packages) {
          if (!allPackages.has(purl)) {
            allPackages.set(purl, location.path)
          }
        }
      }
    } catch (error) {
      if (!silent) {
        console.error('Failed to find npm packages:', error instanceof Error ? error.message : String(error))
      }
    }
  }

  // Find Python packages
  if (pypiPurls.length > 0) {
    const pythonCrawler = new PythonCrawler()
    try {
      // Strip qualifiers for on-disk lookup
      const basePypiPurls = [...new Set(pypiPurls.map(stripPurlQualifiers))]
      const sitePackagesPaths = await pythonCrawler.getSitePackagesPaths(crawlerOptions)
      for (const spPath of sitePackagesPaths) {
        const packages = await pythonCrawler.findByPurls(spPath, basePypiPurls)
        for (const [purl, location] of packages) {
          if (!allPackages.has(purl)) {
            allPackages.set(purl, location.path)
          }
        }
      }
    } catch (error) {
      if (!silent) {
        console.error('Failed to find Python packages:', error instanceof Error ? error.message : String(error))
      }
    }
  }

  if (allPackages.size === 0 && npmPurls.length === 0 && pypiPurls.length === 0) {
    if (!silent) {
      console.error(useGlobal || globalPrefix ? 'No global packages found' : 'No package directories found')
    }
    return { success: false, results: [] }
  }

  if (allPackages.size === 0) {
    if (!silent) {
      console.log('No packages found that match available patches')
    }
    return { success: true, results: [] }
  }

  // Apply patches to each package
  const results: ApplyResult[] = []
  let hasErrors = false

  // Group pypi manifest PURLs by their base (qualifier-stripped) PURL
  const pypiQualifiedGroups = new Map<string, string[]>()
  for (const purl of pypiPurls) {
    const base = stripPurlQualifiers(purl)
    const group = pypiQualifiedGroups.get(base)
    if (group) {
      group.push(purl)
    } else {
      pypiQualifiedGroups.set(base, [purl])
    }
  }

  // Track which base pypi PURLs have been successfully patched
  const appliedBasePurls = new Set<string>()

  for (const [purl, pkgPath] of allPackages) {
    if (isPyPIPurl(purl)) {
      // For pypi PURLs, try each qualified variant and use hash verification
      const basePurl = stripPurlQualifiers(purl)
      if (appliedBasePurls.has(basePurl)) continue

      const variants = pypiQualifiedGroups.get(basePurl) ?? [basePurl]
      let applied = false

      for (const variantPurl of variants) {
        const patch = manifest.patches[variantPurl]
        if (!patch) continue

        // Check if this variant's beforeHash matches the file on disk
        const firstFile = Object.entries(patch.files)[0]
        if (firstFile) {
          const [fileName, fileInfo] = firstFile
          const verify = await verifyFilePatch(pkgPath, fileName, fileInfo)
          if (verify.status === 'hash-mismatch') {
            // This variant doesn't match, try next
            continue
          }
        }

        const result = await applyPackagePatch(
          variantPurl,
          pkgPath,
          patch.files,
          blobsPath,
          dryRun,
        )
        results.push(result)

        if (result.success) {
          applied = true
          appliedBasePurls.add(basePurl)
          break
        }
      }

      if (!applied) {
        hasErrors = true
        if (!silent) {
          console.error(`Failed to patch ${basePurl}: no matching variant found`)
        }
      }
    } else {
      // npm PURLs: direct lookup
      const patch = manifest.patches[purl]
      if (!patch) continue

      const result = await applyPackagePatch(
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
          console.error(`Failed to patch ${purl}: ${result.error}`)
        }
      }
    }
  }

  // Clean up unused blobs after applying patches
  if (!silent) {
    const cleanupResult = await cleanupUnusedBlobs(manifest, blobsPath, dryRun)
    if (cleanupResult.blobsRemoved > 0) {
      console.log(`\n${formatCleanupResult(cleanupResult, dryRun)}`)
    }
  }

  return { success: !hasErrors, results }
}

export const applyCommand: CommandModule<{}, ApplyArgs> = {
  command: 'apply',
  describe: 'Apply security patches to dependencies',
  builder: yargs => {
    return yargs
      .option('cwd', {
        describe: 'Working directory',
        type: 'string',
        default: process.cwd(),
      })
      .option('dry-run', {
        alias: 'd',
        describe: 'Verify patches can be applied without modifying files',
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
        describe: 'Apply patches to globally installed npm packages',
        type: 'boolean',
        default: false,
      })
      .option('global-prefix', {
        describe: 'Custom path to global node_modules (overrides auto-detection, useful for yarn/pnpm)',
        type: 'string',
      })
      .option('ecosystems', {
        describe: 'Restrict patching to specific ecosystems (comma-separated)',
        type: 'array',
        choices: ['npm', 'pypi'],
      })
      .example('$0 apply', 'Apply all patches to local packages')
      .example('$0 apply --global', 'Apply patches to global npm packages')
      .example('$0 apply --global-prefix /custom/path', 'Apply patches to custom global location')
      .example('$0 apply --dry-run', 'Preview patches without applying')
  },
  handler: async argv => {
    // Get API credentials for authenticated telemetry (optional).
    const apiToken = process.env['SOCKET_API_TOKEN']
    const orgSlug = process.env['SOCKET_ORG_SLUG']

    try {
      const manifestPath = path.isAbsolute(argv['manifest-path'])
        ? argv['manifest-path']
        : path.join(argv.cwd, argv['manifest-path'])

      // Check if manifest exists - exit successfully if no .socket folder is set up
      try {
        await fs.access(manifestPath)
      } catch {
        // No manifest means no patches to apply - this is a successful no-op
        if (!argv.silent) {
          console.log('No .socket folder found, skipping patch application.')
        }
        process.exit(0)
      }

      const { success, results } = await applyPatches(
        argv.cwd,
        manifestPath,
        argv['dry-run'],
        argv.silent,
        argv.offline,
        argv.global,
        argv['global-prefix'],
        argv.ecosystems,
      )

      // Print results if not silent
      if (!argv.silent && results.length > 0) {
        const patched = results.filter(r => r.success)
        const alreadyPatched = results.filter(r =>
          r.filesVerified.every(f => f.status === 'already-patched'),
        )

        if (argv['dry-run']) {
          console.log(`\nPatch verification complete:`)
          console.log(`  ${patched.length} package(s) can be patched`)
          if (alreadyPatched.length > 0) {
            console.log(`  ${alreadyPatched.length} package(s) already patched`)
          }
        } else {
          console.log(`\nPatched packages:`)
          for (const result of patched) {
            if (result.filesPatched.length > 0) {
              console.log(`  ${result.packageKey}`)
            } else if (
              result.filesVerified.every(f => f.status === 'already-patched')
            ) {
              console.log(`  ${result.packageKey} (already patched)`)
            }
          }
        }
      }

      // Track telemetry event.
      const patchedCount = results.filter(r => r.success && r.filesPatched.length > 0).length
      if (success) {
        await trackPatchApplied(patchedCount, argv['dry-run'], apiToken, orgSlug)
      } else {
        await trackPatchApplyFailed(
          new Error('One or more patches failed to apply'),
          argv['dry-run'],
          apiToken,
          orgSlug,
        )
      }

      process.exit(success ? 0 : 1)
    } catch (err) {
      // Track telemetry for unexpected errors.
      const error = err instanceof Error ? err : new Error(String(err))
      await trackPatchApplyFailed(error, argv['dry-run'], apiToken, orgSlug)

      if (!argv.silent) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        console.error(`Error: ${errorMessage}`)
      }
      process.exit(1)
    }
  },
}

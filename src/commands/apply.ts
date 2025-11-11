import * as fs from 'fs/promises'
import * as path from 'path'
import type { CommandModule } from 'yargs'
import {
  PatchManifestSchema,
  DEFAULT_PATCH_MANIFEST_PATH,
} from '../schema/manifest-schema.js'
import {
  findNodeModules,
  findPackagesForPatches,
  applyPackagePatch,
} from '../patch/apply.js'
import type { ApplyResult } from '../patch/apply.js'
import {
  cleanupUnusedBlobs,
  formatCleanupResult,
} from '../utils/cleanup-blobs.js'

interface ApplyArgs {
  cwd: string
  'dry-run': boolean
  silent: boolean
  'manifest-path': string
}

async function applyPatches(
  cwd: string,
  manifestPath: string,
  dryRun: boolean,
  silent: boolean,
): Promise<{ success: boolean; results: ApplyResult[] }> {
  // Read and parse manifest
  const manifestContent = await fs.readFile(manifestPath, 'utf-8')
  const manifestData = JSON.parse(manifestContent)
  const manifest = PatchManifestSchema.parse(manifestData)

  // Find .socket directory (contains blobs)
  const socketDir = path.dirname(manifestPath)
  const blobsPath = path.join(socketDir, 'blobs')

  // Verify blobs directory exists
  try {
    await fs.access(blobsPath)
  } catch {
    throw new Error(`Blobs directory not found at ${blobsPath}`)
  }

  // Find all node_modules directories
  const nodeModulesPaths = await findNodeModules(cwd)

  if (nodeModulesPaths.length === 0) {
    if (!silent) {
      console.error('No node_modules directories found')
    }
    return { success: false, results: [] }
  }

  // Find all packages that need patching
  const allPackages = new Map<string, string>()
  for (const nmPath of nodeModulesPaths) {
    const packages = await findPackagesForPatches(nmPath, manifest)
    for (const [purl, location] of packages) {
      if (!allPackages.has(purl)) {
        allPackages.set(purl, location.path)
      }
    }
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

  for (const [purl, pkgPath] of allPackages) {
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

      const { success, results } = await applyPatches(
        argv.cwd,
        manifestPath,
        argv['dry-run'],
        argv.silent,
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

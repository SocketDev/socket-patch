import * as fs from 'fs/promises'
import * as path from 'path'
import type { CommandModule } from 'yargs'
import {
  PatchManifestSchema,
  DEFAULT_PATCH_MANIFEST_PATH,
  type PatchManifest,
} from '../schema/manifest-schema.js'
import {
  cleanupUnusedBlobs,
  formatCleanupResult,
} from '../utils/cleanup-blobs.js'
import { rollbackPatches } from './rollback.js'

interface RemoveArgs {
  identifier: string
  cwd: string
  'manifest-path': string
  'skip-rollback': boolean
  global: boolean
  'global-prefix'?: string
}

async function removePatch(
  identifier: string,
  manifestPath: string,
): Promise<{ removed: string[]; notFound: boolean; manifest: PatchManifest }> {
  // Read and parse manifest
  const manifestContent = await fs.readFile(manifestPath, 'utf-8')
  const manifestData = JSON.parse(manifestContent)
  const manifest = PatchManifestSchema.parse(manifestData)

  const removed: string[] = []
  let foundMatch = false

  // Check if identifier is a PURL (contains "pkg:")
  if (identifier.startsWith('pkg:')) {
    // Remove by PURL
    if (manifest.patches[identifier]) {
      removed.push(identifier)
      delete manifest.patches[identifier]
      foundMatch = true
    }
  } else {
    // Remove by UUID - search through all patches
    for (const [purl, patch] of Object.entries(manifest.patches)) {
      if (patch.uuid === identifier) {
        removed.push(purl)
        delete manifest.patches[purl]
        foundMatch = true
      }
    }
  }

  if (foundMatch) {
    // Write updated manifest
    await fs.writeFile(
      manifestPath,
      JSON.stringify(manifest, null, 2) + '\n',
      'utf-8',
    )
  }

  return { removed, notFound: !foundMatch, manifest }
}

export const removeCommand: CommandModule<{}, RemoveArgs> = {
  command: 'remove <identifier>',
  describe: 'Remove a patch from the manifest by PURL or UUID (rolls back files first)',
  builder: yargs => {
    return yargs
      .positional('identifier', {
        describe: 'Package PURL (e.g., pkg:npm/package@version) or patch UUID',
        type: 'string',
        demandOption: true,
      })
      .option('cwd', {
        describe: 'Working directory',
        type: 'string',
        default: process.cwd(),
      })
      .option('manifest-path', {
        alias: 'm',
        describe: 'Path to patch manifest file',
        type: 'string',
        default: DEFAULT_PATCH_MANIFEST_PATH,
      })
      .option('skip-rollback', {
        describe: 'Skip rolling back files before removing (only update manifest)',
        type: 'boolean',
        default: false,
      })
      .option('global', {
        alias: 'g',
        describe: 'Remove patches from globally installed npm packages',
        type: 'boolean',
        default: false,
      })
      .option('global-prefix', {
        describe: 'Custom path to global node_modules (overrides auto-detection, useful for yarn/pnpm)',
        type: 'string',
      })
      .example(
        '$0 remove pkg:npm/lodash@4.17.21',
        'Rollback and remove a patch by PURL',
      )
      .example(
        '$0 remove 12345678-1234-1234-1234-123456789abc',
        'Rollback and remove a patch by UUID',
      )
      .example(
        '$0 remove pkg:npm/lodash@4.17.21 --skip-rollback',
        'Remove from manifest without rolling back files',
      )
      .example(
        '$0 remove pkg:npm/lodash@4.17.21 --global',
        'Remove and rollback from global npm packages',
      )
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
        console.error(`Manifest not found at ${manifestPath}`)
        process.exit(1)
      }

      // First, rollback the patch if not skipped
      if (!argv['skip-rollback']) {
        console.log(`Rolling back patch before removal...`)
        const { success: rollbackSuccess, results: rollbackResults } =
          await rollbackPatches(
            argv.cwd,
            manifestPath,
            argv.identifier,
            false, // not dry run
            false, // not silent
            false, // not offline
            argv.global,
            argv['global-prefix'],
          )

        if (!rollbackSuccess) {
          console.error(
            '\nRollback failed. Use --skip-rollback to remove from manifest without restoring files.',
          )
          process.exit(1)
        }

        // Report rollback results
        const rolledBack = rollbackResults.filter(
          r => r.success && r.filesRolledBack.length > 0,
        )
        const alreadyOriginal = rollbackResults.filter(
          r =>
            r.success &&
            r.filesVerified.every(f => f.status === 'already-original'),
        )

        if (rolledBack.length > 0) {
          console.log(`Rolled back ${rolledBack.length} package(s)`)
        }
        if (alreadyOriginal.length > 0) {
          console.log(
            `${alreadyOriginal.length} package(s) already in original state`,
          )
        }
        if (rollbackResults.length === 0) {
          console.log('No packages found to rollback (not installed)')
        }
        console.log()
      }

      // Now remove from manifest
      const { removed, notFound, manifest } = await removePatch(
        argv.identifier,
        manifestPath,
      )

      if (notFound) {
        console.error(`No patch found matching identifier: ${argv.identifier}`)
        process.exit(1)
      }

      console.log(`Removed ${removed.length} patch(es) from manifest:`)
      for (const purl of removed) {
        console.log(`  - ${purl}`)
      }

      console.log(`\nManifest updated at ${manifestPath}`)

      // Clean up unused blobs after removing patches
      const socketDir = path.dirname(manifestPath)
      const blobsPath = path.join(socketDir, 'blobs')
      const cleanupResult = await cleanupUnusedBlobs(manifest, blobsPath, false)
      if (cleanupResult.blobsRemoved > 0) {
        console.log(`\n${formatCleanupResult(cleanupResult, false)}`)
      }

      process.exit(0)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      console.error(`Error: ${errorMessage}`)
      process.exit(1)
    }
  },
}

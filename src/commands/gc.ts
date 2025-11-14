import * as fs from 'fs/promises'
import * as path from 'path'
import type { CommandModule } from 'yargs'
import {
  PatchManifestSchema,
  DEFAULT_PATCH_MANIFEST_PATH,
} from '../schema/manifest-schema.js'
import {
  cleanupUnusedBlobs,
  formatCleanupResult,
} from '../utils/cleanup-blobs.js'

interface GCArgs {
  cwd: string
  'manifest-path': string
  'dry-run': boolean
}

async function garbageCollect(
  manifestPath: string,
  dryRun: boolean,
): Promise<void> {
  // Read and parse manifest
  const manifestContent = await fs.readFile(manifestPath, 'utf-8')
  const manifestData = JSON.parse(manifestContent)
  const manifest = PatchManifestSchema.parse(manifestData)

  // Find .socket directory (contains blobs)
  const socketDir = path.dirname(manifestPath)
  const blobsPath = path.join(socketDir, 'blobs')

  // Run cleanup
  const cleanupResult = await cleanupUnusedBlobs(manifest, blobsPath, dryRun)

  // Display results
  if (cleanupResult.blobsChecked === 0) {
    console.log('No blobs directory found, nothing to clean up.')
  } else if (cleanupResult.blobsRemoved === 0) {
    console.log(
      `Checked ${cleanupResult.blobsChecked} blob(s), all are in use.`,
    )
  } else {
    console.log(formatCleanupResult(cleanupResult, dryRun))

    if (!dryRun) {
      console.log('\nGarbage collection complete.')
    }
  }
}

export const gcCommand: CommandModule<{}, GCArgs> = {
  command: 'gc',
  describe: 'Clean up unused blob files from .socket/blobs directory',
  builder: yargs => {
    return yargs
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
      .option('dry-run', {
        alias: 'd',
        describe: 'Show what would be removed without actually removing',
        type: 'boolean',
        default: false,
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
        console.error(`Manifest not found at ${manifestPath}`)
        process.exit(1)
      }

      await garbageCollect(manifestPath, argv['dry-run'])
      process.exit(0)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      console.error(`Error: ${errorMessage}`)
      process.exit(1)
    }
  },
}

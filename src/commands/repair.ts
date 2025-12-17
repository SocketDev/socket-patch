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
import {
  fetchMissingBlobs,
  formatFetchResult,
  getMissingBlobs,
} from '../utils/blob-fetcher.js'

interface RepairArgs {
  cwd: string
  'manifest-path': string
  'dry-run': boolean
  offline: boolean
  'download-only': boolean
}

async function repair(
  manifestPath: string,
  dryRun: boolean,
  offline: boolean,
  downloadOnly: boolean,
): Promise<void> {
  // Read and parse manifest
  const manifestContent = await fs.readFile(manifestPath, 'utf-8')
  const manifestData = JSON.parse(manifestContent)
  const manifest = PatchManifestSchema.parse(manifestData)

  // Find .socket directory (contains blobs)
  const socketDir = path.dirname(manifestPath)
  const blobsPath = path.join(socketDir, 'blobs')

  // Step 1: Check for and download missing blobs (unless offline)
  if (!offline) {
    const missingBlobs = await getMissingBlobs(manifest, blobsPath)

    if (missingBlobs.size > 0) {
      console.log(`Found ${missingBlobs.size} missing blob(s)`)

      if (dryRun) {
        console.log('\nDry run - would download:')
        for (const hash of Array.from(missingBlobs).slice(0, 10)) {
          console.log(`  - ${hash.slice(0, 12)}...`)
        }
        if (missingBlobs.size > 10) {
          console.log(`  ... and ${missingBlobs.size - 10} more`)
        }
      } else {
        console.log('\nDownloading missing blobs...')

        const fetchResult = await fetchMissingBlobs(manifest, blobsPath, undefined, {
          onProgress: (hash, index, total) => {
            process.stdout.write(
              `\r  Downloading ${index}/${total}: ${hash.slice(0, 12)}...`.padEnd(60),
            )
          },
        })

        // Clear progress line
        process.stdout.write('\r' + ' '.repeat(60) + '\r')

        console.log(formatFetchResult(fetchResult))
      }
    } else {
      console.log('All blobs are present locally.')
    }
  } else {
    // Offline mode - just check for missing blobs
    const missingBlobs = await getMissingBlobs(manifest, blobsPath)
    if (missingBlobs.size > 0) {
      console.log(
        `Warning: ${missingBlobs.size} blob(s) are missing (offline mode - not downloading)`,
      )
      for (const hash of Array.from(missingBlobs).slice(0, 5)) {
        console.log(`  - ${hash.slice(0, 12)}...`)
      }
      if (missingBlobs.size > 5) {
        console.log(`  ... and ${missingBlobs.size - 5} more`)
      }
    } else {
      console.log('All blobs are present locally.')
    }
  }

  // Step 2: Clean up unused blobs (unless download-only)
  if (!downloadOnly) {
    console.log('')
    const cleanupResult = await cleanupUnusedBlobs(manifest, blobsPath, dryRun)

    if (cleanupResult.blobsChecked === 0) {
      console.log('No blobs directory found, nothing to clean up.')
    } else if (cleanupResult.blobsRemoved === 0) {
      console.log(
        `Checked ${cleanupResult.blobsChecked} blob(s), all are in use.`,
      )
    } else {
      console.log(formatCleanupResult(cleanupResult, dryRun))
    }
  }

  if (!dryRun) {
    console.log('\nRepair complete.')
  }
}

export const repairCommand: CommandModule<{}, RepairArgs> = {
  command: 'repair',
  aliases: ['gc'],
  describe: 'Download missing blobs and clean up unused blobs',
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
        describe: 'Show what would be done without actually doing it',
        type: 'boolean',
        default: false,
      })
      .option('offline', {
        describe: 'Skip network operations (cleanup only)',
        type: 'boolean',
        default: false,
      })
      .option('download-only', {
        describe: 'Only download missing blobs, do not clean up',
        type: 'boolean',
        default: false,
      })
      .example('$0 repair', 'Download missing blobs and clean up unused ones')
      .example('$0 repair --dry-run', 'Show what would be done without doing it')
      .example('$0 repair --offline', 'Only clean up unused blobs (no network)')
      .example('$0 repair --download-only', 'Only download missing blobs')
      .example('$0 gc', 'Alias for repair command')
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

      await repair(
        manifestPath,
        argv['dry-run'],
        argv['offline'],
        argv['download-only'],
      )
      process.exit(0)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      console.error(`Error: ${errorMessage}`)
      process.exit(1)
    }
  },
}

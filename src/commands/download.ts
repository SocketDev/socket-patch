import * as fs from 'fs/promises'
import * as path from 'path'
import type { CommandModule } from 'yargs'
import { PatchManifestSchema } from '../schema/manifest-schema.js'
import { getAPIClientFromEnv } from '../utils/api-client.js'
import {
  cleanupUnusedBlobs,
  formatCleanupResult,
} from '../utils/cleanup-blobs.js'

interface DownloadArgs {
  uuid: string
  org: string
  cwd: string
  'api-url'?: string
  'api-token'?: string
}

async function downloadPatch(
  uuid: string,
  orgSlug: string,
  cwd: string,
  apiUrl?: string,
  apiToken?: string,
): Promise<boolean> {
  // Override environment variables if CLI options are provided
  if (apiUrl) {
    process.env.SOCKET_API_URL = apiUrl
  }
  if (apiToken) {
    process.env.SOCKET_API_TOKEN = apiToken
  }

  // Get API client (will use env vars if not overridden)
  const apiClient = getAPIClientFromEnv()

  console.log(`Fetching patch ${uuid} from ${orgSlug}...`)

  // Fetch patch from API
  const patch = await apiClient.fetchPatch(orgSlug, uuid)

  if (!patch) {
    throw new Error(`Patch with UUID ${uuid} not found`)
  }

  console.log(`Downloaded patch for ${patch.purl}`)

  // Prepare .socket directory
  const socketDir = path.join(cwd, '.socket')
  const blobsDir = path.join(socketDir, 'blobs')
  const manifestPath = path.join(socketDir, 'manifest.json')

  // Create directories
  await fs.mkdir(socketDir, { recursive: true })
  await fs.mkdir(blobsDir, { recursive: true })

  // Read existing manifest or create new one
  let manifest: any
  try {
    const manifestContent = await fs.readFile(manifestPath, 'utf-8')
    manifest = PatchManifestSchema.parse(JSON.parse(manifestContent))
  } catch {
    // Create new manifest
    manifest = { patches: {} }
  }

  // Save blob contents
  const files: Record<string, { beforeHash?: string; afterHash?: string }> = {}
  for (const [filePath, fileInfo] of Object.entries(patch.files)) {
    if (fileInfo.afterHash) {
      files[filePath] = {
        beforeHash: fileInfo.beforeHash,
        afterHash: fileInfo.afterHash,
      }
    }

    // Save blob content if provided
    if (fileInfo.blobContent && fileInfo.afterHash) {
      const blobPath = path.join(blobsDir, fileInfo.afterHash)
      const blobBuffer = Buffer.from(fileInfo.blobContent, 'base64')
      await fs.writeFile(blobPath, blobBuffer)
      console.log(`  Saved blob: ${fileInfo.afterHash}`)
    }
  }

  // Add/update patch in manifest
  manifest.patches[patch.purl] = {
    uuid: patch.uuid,
    exportedAt: patch.publishedAt,
    files,
    vulnerabilities: patch.vulnerabilities,
    description: patch.description,
    license: patch.license,
    tier: patch.tier,
  }

  // Write updated manifest
  await fs.writeFile(
    manifestPath,
    JSON.stringify(manifest, null, 2) + '\n',
    'utf-8',
  )

  console.log(`\nPatch saved to ${manifestPath}`)
  console.log(`  PURL: ${patch.purl}`)
  console.log(`  UUID: ${patch.uuid}`)
  console.log(`  Files: ${Object.keys(files).length}`)
  console.log(`  Vulnerabilities: ${Object.keys(patch.vulnerabilities).length}`)

  // Clean up unused blobs
  const cleanupResult = await cleanupUnusedBlobs(manifest, blobsDir, false)
  if (cleanupResult.blobsRemoved > 0) {
    console.log(`\n${formatCleanupResult(cleanupResult, false)}`)
  }

  return true
}

export const downloadCommand: CommandModule<{}, DownloadArgs> = {
  command: 'download',
  describe: 'Download a security patch from Socket API',
  builder: yargs => {
    return yargs
      .option('uuid', {
        describe: 'Patch UUID to download',
        type: 'string',
        demandOption: true,
      })
      .option('org', {
        describe: 'Organization slug',
        type: 'string',
        demandOption: true,
      })
      .option('cwd', {
        describe: 'Working directory',
        type: 'string',
        default: process.cwd(),
      })
      .option('api-url', {
        describe: 'Socket API URL (overrides SOCKET_API_URL env var)',
        type: 'string',
      })
      .option('api-token', {
        describe: 'Socket API token (overrides SOCKET_API_TOKEN env var)',
        type: 'string',
      })
  },
  handler: async argv => {
    try {
      await downloadPatch(
        argv.uuid,
        argv.org,
        argv.cwd,
        argv['api-url'],
        argv['api-token'],
      )

      process.exit(0)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      console.error(`Error: ${errorMessage}`)
      process.exit(1)
    }
  },
}

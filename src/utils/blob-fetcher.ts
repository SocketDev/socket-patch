import * as fs from 'fs/promises'
import * as path from 'path'
import type { PatchManifest } from '../schema/manifest-schema.js'
import { getAfterHashBlobs } from '../manifest/operations.js'
import { APIClient, getAPIClientFromEnv } from './api-client.js'

export interface BlobFetchResult {
  hash: string
  success: boolean
  error?: string
}

export interface FetchMissingBlobsResult {
  total: number
  downloaded: number
  failed: number
  skipped: number
  results: BlobFetchResult[]
}

export interface FetchMissingBlobsOptions {
  onProgress?: (hash: string, index: number, total: number) => void
}

/**
 * Get the set of afterHash blobs that are referenced in the manifest but missing from disk.
 * Only checks for afterHash blobs since those are needed for applying patches.
 * beforeHash blobs are not needed (they can be downloaded on-demand during rollback).
 *
 * @param manifest - The patch manifest
 * @param blobsPath - Path to the blobs directory
 * @returns Set of missing afterHash blob hashes
 */
export async function getMissingBlobs(
  manifest: PatchManifest,
  blobsPath: string,
): Promise<Set<string>> {
  const afterHashBlobs = getAfterHashBlobs(manifest)
  const missingBlobs = new Set<string>()

  for (const hash of afterHashBlobs) {
    const blobPath = path.join(blobsPath, hash)
    try {
      await fs.access(blobPath)
    } catch {
      missingBlobs.add(hash)
    }
  }

  return missingBlobs
}

/**
 * Download all missing blobs referenced in the manifest.
 *
 * @param manifest - The patch manifest
 * @param blobsPath - Path to the blobs directory
 * @param client - Optional API client (will create one if not provided)
 * @param options - Optional callbacks for progress tracking
 * @returns Results of the download operation
 */
export async function fetchMissingBlobs(
  manifest: PatchManifest,
  blobsPath: string,
  client?: APIClient,
  options?: FetchMissingBlobsOptions,
): Promise<FetchMissingBlobsResult> {
  const missingBlobs = await getMissingBlobs(manifest, blobsPath)

  if (missingBlobs.size === 0) {
    return {
      total: 0,
      downloaded: 0,
      failed: 0,
      skipped: 0,
      results: [],
    }
  }

  // Get client from environment if not provided
  const apiClient = client ?? getAPIClientFromEnv().client

  // Ensure blobs directory exists
  await fs.mkdir(blobsPath, { recursive: true })

  const results: BlobFetchResult[] = []
  let downloaded = 0
  let failed = 0

  const hashes = Array.from(missingBlobs)
  for (let i = 0; i < hashes.length; i++) {
    const hash = hashes[i]

    if (options?.onProgress) {
      options.onProgress(hash, i + 1, hashes.length)
    }

    try {
      const blobData = await apiClient.fetchBlob(hash)

      if (blobData === null) {
        results.push({
          hash,
          success: false,
          error: 'Blob not found on server',
        })
        failed++
      } else {
        const blobPath = path.join(blobsPath, hash)
        await fs.writeFile(blobPath, blobData)
        results.push({
          hash,
          success: true,
        })
        downloaded++
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      results.push({
        hash,
        success: false,
        error: errorMessage,
      })
      failed++
    }
  }

  return {
    total: hashes.length,
    downloaded,
    failed,
    skipped: 0,
    results,
  }
}

/**
 * Ensure a blob exists locally, downloading it if necessary.
 *
 * @param hash - SHA256 hash of the blob
 * @param blobsPath - Path to the blobs directory
 * @param client - API client for downloading (null for offline mode)
 * @returns true if blob exists locally (or was downloaded), false otherwise
 */
export async function ensureBlobExists(
  hash: string,
  blobsPath: string,
  client: APIClient | null,
): Promise<boolean> {
  const blobPath = path.join(blobsPath, hash)

  // Check if blob already exists locally
  try {
    await fs.access(blobPath)
    return true
  } catch {
    // Blob doesn't exist locally
  }

  // If in offline mode (no client), we can't download
  if (client === null) {
    return false
  }

  // Try to download the blob
  try {
    const blobData = await client.fetchBlob(hash)
    if (blobData === null) {
      return false
    }

    // Ensure blobs directory exists
    await fs.mkdir(blobsPath, { recursive: true })

    await fs.writeFile(blobPath, blobData)
    return true
  } catch {
    return false
  }
}

/**
 * Create an ensureBlob callback function for use with apply/rollback commands.
 *
 * @param blobsPath - Path to the blobs directory
 * @param offline - If true, don't attempt network downloads
 * @returns Callback function for ensuring blobs exist
 */
export function createBlobEnsurer(
  blobsPath: string,
  offline: boolean,
): (hash: string) => Promise<boolean> {
  const client = offline ? null : getAPIClientFromEnv().client

  return async (hash: string) => {
    return ensureBlobExists(hash, blobsPath, client)
  }
}

/**
 * Fetch specific blobs by their hashes.
 * This is useful for downloading beforeHash blobs during rollback.
 *
 * @param hashes - Set of blob hashes to download
 * @param blobsPath - Path to the blobs directory
 * @param client - Optional API client (will create one if not provided)
 * @param options - Optional callbacks for progress tracking
 * @returns Results of the download operation
 */
export async function fetchBlobsByHash(
  hashes: Set<string>,
  blobsPath: string,
  client?: APIClient,
  options?: FetchMissingBlobsOptions,
): Promise<FetchMissingBlobsResult> {
  if (hashes.size === 0) {
    return {
      total: 0,
      downloaded: 0,
      failed: 0,
      skipped: 0,
      results: [],
    }
  }

  // Get client from environment if not provided
  const apiClient = client ?? getAPIClientFromEnv().client

  // Ensure blobs directory exists
  await fs.mkdir(blobsPath, { recursive: true })

  const results: BlobFetchResult[] = []
  let downloaded = 0
  let failed = 0

  const hashArray = Array.from(hashes)
  for (let i = 0; i < hashArray.length; i++) {
    const hash = hashArray[i]

    if (options?.onProgress) {
      options.onProgress(hash, i + 1, hashArray.length)
    }

    try {
      const blobData = await apiClient.fetchBlob(hash)

      if (blobData === null) {
        results.push({
          hash,
          success: false,
          error: 'Blob not found on server',
        })
        failed++
      } else {
        const blobPath = path.join(blobsPath, hash)
        await fs.writeFile(blobPath, blobData)
        results.push({
          hash,
          success: true,
        })
        downloaded++
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      results.push({
        hash,
        success: false,
        error: errorMessage,
      })
      failed++
    }
  }

  return {
    total: hashArray.length,
    downloaded,
    failed,
    skipped: 0,
    results,
  }
}

/**
 * Format the fetch results for human-readable output.
 */
export function formatFetchResult(result: FetchMissingBlobsResult): string {
  if (result.total === 0) {
    return 'All blobs are present locally.'
  }

  const lines: string[] = []

  if (result.downloaded > 0) {
    lines.push(`Downloaded ${result.downloaded} blob(s)`)
  }

  if (result.failed > 0) {
    lines.push(`Failed to download ${result.failed} blob(s)`)

    // Show failed blobs
    const failedResults = result.results.filter(r => !r.success)
    for (const r of failedResults.slice(0, 5)) {
      lines.push(`  - ${r.hash.slice(0, 12)}...: ${r.error}`)
    }
    if (failedResults.length > 5) {
      lines.push(`  ... and ${failedResults.length - 5} more`)
    }
  }

  return lines.join('\n')
}

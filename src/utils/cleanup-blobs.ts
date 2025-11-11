import * as fs from 'fs/promises'
import * as path from 'path'
import type { PatchManifest } from '../schema/manifest-schema.js'

export interface CleanupResult {
  blobsChecked: number
  blobsRemoved: number
  bytesFreed: number
  removedBlobs: string[]
}

/**
 * Cleans up unused blob files from the .socket/blobs directory.
 * Analyzes the manifest to determine which blobs are still in use,
 * then removes any blob files that are not referenced.
 *
 * @param manifest - The patch manifest containing all active patches
 * @param blobsDir - Path to the .socket/blobs directory
 * @param dryRun - If true, only reports what would be deleted without actually deleting
 * @returns Statistics about the cleanup operation
 */
export async function cleanupUnusedBlobs(
  manifest: PatchManifest,
  blobsDir: string,
  dryRun: boolean = false,
): Promise<CleanupResult> {
  // Collect all blob hashes that are currently in use
  const usedBlobs = new Set<string>()

  for (const patch of Object.values(manifest.patches)) {
    for (const fileInfo of Object.values(patch.files)) {
      // Add both before and after hashes if they exist
      if (fileInfo.beforeHash) {
        usedBlobs.add(fileInfo.beforeHash)
      }
      if (fileInfo.afterHash) {
        usedBlobs.add(fileInfo.afterHash)
      }
    }
  }

  // Check if blobs directory exists
  try {
    await fs.access(blobsDir)
  } catch {
    // Blobs directory doesn't exist, nothing to clean up
    return {
      blobsChecked: 0,
      blobsRemoved: 0,
      bytesFreed: 0,
      removedBlobs: [],
    }
  }

  // Read all files in the blobs directory
  const blobFiles = await fs.readdir(blobsDir)

  const result: CleanupResult = {
    blobsChecked: blobFiles.length,
    blobsRemoved: 0,
    bytesFreed: 0,
    removedBlobs: [],
  }

  // Check each blob file
  for (const blobFile of blobFiles) {
    // Skip hidden files and directories
    if (blobFile.startsWith('.')) {
      continue
    }

    const blobPath = path.join(blobsDir, blobFile)

    // Check if it's a file (not a directory)
    const stats = await fs.stat(blobPath)
    if (!stats.isFile()) {
      continue
    }

    // If this blob is not in use, remove it
    if (!usedBlobs.has(blobFile)) {
      result.blobsRemoved++
      result.bytesFreed += stats.size
      result.removedBlobs.push(blobFile)

      if (!dryRun) {
        await fs.unlink(blobPath)
      }
    }
  }

  return result
}

/**
 * Formats the cleanup result for human-readable output
 */
export function formatCleanupResult(result: CleanupResult, dryRun: boolean): string {
  if (result.blobsChecked === 0) {
    return 'No blobs directory found, nothing to clean up.'
  }

  if (result.blobsRemoved === 0) {
    return `Checked ${result.blobsChecked} blob(s), all are in use.`
  }

  const action = dryRun ? 'Would remove' : 'Removed'
  const bytesFormatted = formatBytes(result.bytesFreed)

  let output = `${action} ${result.blobsRemoved} unused blob(s) (${bytesFormatted} freed)`

  if (dryRun && result.removedBlobs.length > 0) {
    output += '\nUnused blobs:'
    for (const blob of result.removedBlobs) {
      output += `\n  - ${blob}`
    }
  }

  return output
}

/**
 * Formats bytes into a human-readable string
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

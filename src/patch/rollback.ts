import * as fs from 'fs/promises'
import * as path from 'path'
import { computeFileGitSHA256 } from './file-hash.js'
import type { PatchFileInfo } from './apply.js'

export interface VerifyRollbackResult {
  file: string
  status:
    | 'ready'
    | 'already-original'
    | 'hash-mismatch'
    | 'not-found'
    | 'missing-blob'
  message?: string
  currentHash?: string
  expectedHash?: string
  targetHash?: string
}

export interface RollbackResult {
  packageKey: string
  packagePath: string
  success: boolean
  filesVerified: VerifyRollbackResult[]
  filesRolledBack: string[]
  error?: string
}

/**
 * Normalize file path by removing the 'package/' prefix if present
 * Patch files come from the API with paths like 'package/lib/file.js'
 * but we need relative paths like 'lib/file.js' for the actual package directory
 */
function normalizeFilePath(fileName: string): string {
  const packagePrefix = 'package/'
  if (fileName.startsWith(packagePrefix)) {
    return fileName.slice(packagePrefix.length)
  }
  return fileName
}

/**
 * Verify a single file can be rolled back
 * A file is ready for rollback if its current hash matches the afterHash (patched state)
 */
export async function verifyFileRollback(
  packagePath: string,
  fileName: string,
  fileInfo: PatchFileInfo,
  blobsPath: string,
): Promise<VerifyRollbackResult> {
  const normalizedFileName = normalizeFilePath(fileName)
  const filepath = path.join(packagePath, normalizedFileName)

  // Check if file exists
  try {
    await fs.access(filepath)
  } catch {
    return {
      file: fileName,
      status: 'not-found',
      message: 'File not found',
    }
  }

  // Check if before blob exists (required for rollback)
  const beforeBlobPath = path.join(blobsPath, fileInfo.beforeHash)
  try {
    await fs.access(beforeBlobPath)
  } catch {
    return {
      file: fileName,
      status: 'missing-blob',
      message: `Before blob not found: ${fileInfo.beforeHash}. Re-download the patch to enable rollback.`,
      targetHash: fileInfo.beforeHash,
    }
  }

  // Compute current hash
  const currentHash = await computeFileGitSHA256(filepath)

  // Check if already in original state
  if (currentHash === fileInfo.beforeHash) {
    return {
      file: fileName,
      status: 'already-original',
      currentHash,
    }
  }

  // Check if matches expected patched hash (afterHash)
  if (currentHash !== fileInfo.afterHash) {
    return {
      file: fileName,
      status: 'hash-mismatch',
      message:
        'File has been modified after patching. Cannot safely rollback.',
      currentHash,
      expectedHash: fileInfo.afterHash,
      targetHash: fileInfo.beforeHash,
    }
  }

  return {
    file: fileName,
    status: 'ready',
    currentHash,
    targetHash: fileInfo.beforeHash,
  }
}

/**
 * Rollback a single file to its original state
 */
export async function rollbackFilePatch(
  packagePath: string,
  fileName: string,
  originalContent: Buffer,
  expectedHash: string,
): Promise<void> {
  const normalizedFileName = normalizeFilePath(fileName)
  const filepath = path.join(packagePath, normalizedFileName)

  // Write the original content
  await fs.writeFile(filepath, originalContent)

  // Verify the hash after writing
  const verifyHash = await computeFileGitSHA256(filepath)
  if (verifyHash !== expectedHash) {
    throw new Error(
      `Hash verification failed after rollback. Expected: ${expectedHash}, Got: ${verifyHash}`,
    )
  }
}

/**
 * Verify and rollback patches for a single package
 */
export async function rollbackPackagePatch(
  packageKey: string,
  packagePath: string,
  files: Record<string, PatchFileInfo>,
  blobsPath: string,
  dryRun: boolean = false,
): Promise<RollbackResult> {
  const result: RollbackResult = {
    packageKey,
    packagePath,
    success: false,
    filesVerified: [],
    filesRolledBack: [],
  }

  try {
    // First, verify all files
    for (const [fileName, fileInfo] of Object.entries(files)) {
      const verifyResult = await verifyFileRollback(
        packagePath,
        fileName,
        fileInfo,
        blobsPath,
      )
      result.filesVerified.push(verifyResult)

      // If any file has issues (not ready and not already original), we can't proceed
      if (
        verifyResult.status !== 'ready' &&
        verifyResult.status !== 'already-original'
      ) {
        result.error = `Cannot rollback: ${verifyResult.file} - ${verifyResult.message || verifyResult.status}`
        return result
      }
    }

    // Check if all files are already in original state
    const allOriginal = result.filesVerified.every(
      v => v.status === 'already-original',
    )
    if (allOriginal) {
      result.success = true
      return result
    }

    // If dry run, stop here
    if (dryRun) {
      result.success = true
      return result
    }

    // Rollback files that need it
    for (const [fileName, fileInfo] of Object.entries(files)) {
      const verifyResult = result.filesVerified.find(v => v.file === fileName)
      if (verifyResult?.status === 'already-original') {
        continue
      }

      // Read original content from blobs
      const blobPath = path.join(blobsPath, fileInfo.beforeHash)
      const originalContent = await fs.readFile(blobPath)

      // Rollback the file
      await rollbackFilePatch(
        packagePath,
        fileName,
        originalContent,
        fileInfo.beforeHash,
      )
      result.filesRolledBack.push(fileName)
    }

    result.success = true
  } catch (error) {
    result.error = error instanceof Error ? error.message : String(error)
  }

  return result
}

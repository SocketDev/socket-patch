import * as fs from 'fs/promises'
import * as path from 'path'
import { computeFileGitSHA256 } from './file-hash.js'
import type { PatchManifest } from '../schema/manifest-schema.js'

export interface PatchFileInfo {
  beforeHash: string
  afterHash: string
}

export interface PackageLocation {
  name: string
  version: string
  path: string
}

export interface VerifyResult {
  file: string
  status: 'ready' | 'already-patched' | 'hash-mismatch' | 'not-found'
  message?: string
  currentHash?: string
  expectedHash?: string
  targetHash?: string
}

export interface ApplyResult {
  packageKey: string
  packagePath: string
  success: boolean
  filesVerified: VerifyResult[]
  filesPatched: string[]
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
 * Verify a single file can be patched
 */
export async function verifyFilePatch(
  packagePath: string,
  fileName: string,
  fileInfo: PatchFileInfo,
): Promise<VerifyResult> {
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

  // Compute current hash
  const currentHash = await computeFileGitSHA256(filepath)

  // Check if already patched
  if (currentHash === fileInfo.afterHash) {
    return {
      file: fileName,
      status: 'already-patched',
      currentHash,
    }
  }

  // Check if matches expected before hash
  if (currentHash !== fileInfo.beforeHash) {
    return {
      file: fileName,
      status: 'hash-mismatch',
      message: 'File hash does not match expected value',
      currentHash,
      expectedHash: fileInfo.beforeHash,
      targetHash: fileInfo.afterHash,
    }
  }

  return {
    file: fileName,
    status: 'ready',
    currentHash,
    targetHash: fileInfo.afterHash,
  }
}

/**
 * Apply a patch to a single file
 */
export async function applyFilePatch(
  packagePath: string,
  fileName: string,
  patchedContent: Buffer,
  expectedHash: string,
): Promise<void> {
  const normalizedFileName = normalizeFilePath(fileName)
  const filepath = path.join(packagePath, normalizedFileName)

  // Write the patched content
  await fs.writeFile(filepath, patchedContent)

  // Verify the hash after writing
  const verifyHash = await computeFileGitSHA256(filepath)
  if (verifyHash !== expectedHash) {
    throw new Error(
      `Hash verification failed after patch. Expected: ${expectedHash}, Got: ${verifyHash}`,
    )
  }
}

/**
 * Verify and apply patches for a single package
 */
export async function applyPackagePatch(
  packageKey: string,
  packagePath: string,
  files: Record<string, PatchFileInfo>,
  blobsPath: string,
  dryRun: boolean = false,
): Promise<ApplyResult> {
  const result: ApplyResult = {
    packageKey,
    packagePath,
    success: false,
    filesVerified: [],
    filesPatched: [],
  }

  try {
    // First, verify all files
    for (const [fileName, fileInfo] of Object.entries(files)) {
      const verifyResult = await verifyFilePatch(
        packagePath,
        fileName,
        fileInfo,
      )
      result.filesVerified.push(verifyResult)

      // If any file is not ready or already patched, we can't proceed
      if (
        verifyResult.status !== 'ready' &&
        verifyResult.status !== 'already-patched'
      ) {
        result.error = `Cannot apply patch: ${verifyResult.file} - ${verifyResult.message || verifyResult.status}`
        return result
      }
    }

    // Check if all files are already patched
    const allPatched = result.filesVerified.every(
      v => v.status === 'already-patched',
    )
    if (allPatched) {
      result.success = true
      return result
    }

    // If dry run, stop here
    if (dryRun) {
      result.success = true
      return result
    }

    // Apply patches to files that need it
    for (const [fileName, fileInfo] of Object.entries(files)) {
      const verifyResult = result.filesVerified.find(v => v.file === fileName)
      if (verifyResult?.status === 'already-patched') {
        continue
      }

      // Read patched content from blobs
      const blobPath = path.join(blobsPath, fileInfo.afterHash)
      const patchedContent = await fs.readFile(blobPath)

      // Apply the patch
      await applyFilePatch(
        packagePath,
        fileName,
        patchedContent,
        fileInfo.afterHash,
      )
      result.filesPatched.push(fileName)
    }

    result.success = true
  } catch (error) {
    result.error = error instanceof Error ? error.message : String(error)
  }

  return result
}

/**
 * Find all node_modules directories recursively
 */
export async function findNodeModules(startPath: string): Promise<string[]> {
  const results: string[] = []

  async function search(dir: string): Promise<void> {
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true })

      for (const entry of entries) {
        if (!entry.isDirectory()) continue

        const fullPath = path.join(dir, entry.name)

        if (entry.name === 'node_modules') {
          results.push(fullPath)
          // Don't recurse into nested node_modules
          continue
        }

        // Skip hidden directories and common non-source directories
        if (
          entry.name.startsWith('.') ||
          entry.name === 'dist' ||
          entry.name === 'build'
        ) {
          continue
        }

        await search(fullPath)
      }
    } catch {
      // Ignore permission errors
    }
  }

  await search(startPath)
  return results
}

/**
 * Find packages in node_modules that match the manifest
 */
export async function findPackagesForPatches(
  nodeModulesPath: string,
  manifest: PatchManifest,
): Promise<Map<string, PackageLocation>> {
  const packages = new Map<string, PackageLocation>()

  try {
    const entries = await fs.readdir(nodeModulesPath, { withFileTypes: true })

    for (const entry of entries) {
      // Allow both directories and symlinks (pnpm uses symlinks)
      if (!entry.isDirectory() && !entry.isSymbolicLink()) continue

      const isScoped = entry.name.startsWith('@')
      const dirPath = path.join(nodeModulesPath, entry.name)

      if (isScoped) {
        // Handle scoped packages
        const scopedEntries = await fs.readdir(dirPath, { withFileTypes: true })
        for (const scopedEntry of scopedEntries) {
          // Allow both directories and symlinks (pnpm uses symlinks)
          if (!scopedEntry.isDirectory() && !scopedEntry.isSymbolicLink()) continue

          const pkgPath = path.join(dirPath, scopedEntry.name)
          const pkgName = `${entry.name}/${scopedEntry.name}`
          await checkPackage(pkgPath, pkgName, manifest, packages)
        }
      } else {
        // Handle non-scoped packages
        await checkPackage(dirPath, entry.name, manifest, packages)
      }
    }
  } catch {
    // Ignore errors reading node_modules
  }

  return packages
}

async function checkPackage(
  pkgPath: string,
  _pkgName: string,
  manifest: PatchManifest,
  packages: Map<string, PackageLocation>,
): Promise<void> {
  try {
    const pkgJsonPath = path.join(pkgPath, 'package.json')
    const pkgJsonContent = await fs.readFile(pkgJsonPath, 'utf-8')
    const pkgJson = JSON.parse(pkgJsonContent)

    if (!pkgJson.name || !pkgJson.version) return

    // Check if this package has a patch
    const purl = `pkg:npm/${pkgJson.name}@${pkgJson.version}`
    if (manifest.patches[purl]) {
      packages.set(purl, {
        name: pkgJson.name,
        version: pkgJson.version,
        path: pkgPath,
      })
    }
  } catch {
    // Ignore invalid package.json
  }
}

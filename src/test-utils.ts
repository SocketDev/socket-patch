/**
 * Test utilities for socket-patch e2e tests
 */
import * as fs from 'fs/promises'
import * as path from 'path'
import * as os from 'os'
import { computeGitSHA256FromBuffer } from './hash/git-sha256.js'
import type { PatchManifest, PatchRecord } from './schema/manifest-schema.js'

/**
 * Create a temporary test directory
 */
export async function createTestDir(prefix: string = 'socket-patch-test-'): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix))
}

/**
 * Remove a directory recursively
 */
export async function removeTestDir(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true })
}

/**
 * Compute git SHA256 hash of content
 */
export function computeTestHash(content: string): string {
  return computeGitSHA256FromBuffer(Buffer.from(content, 'utf-8'))
}

/**
 * Create a mock manifest
 */
export function createTestManifest(
  patches: Record<string, PatchRecord>,
): PatchManifest {
  return { patches }
}

/**
 * Generate a valid UUID v4 for testing
 * Uses a simple approach that produces valid UUIDs
 */
export function generateTestUUID(): string {
  const hex = '0123456789abcdef'
  let uuid = ''

  for (let i = 0; i < 36; i++) {
    if (i === 8 || i === 13 || i === 18 || i === 23) {
      uuid += '-'
    } else if (i === 14) {
      uuid += '4' // Version 4
    } else if (i === 19) {
      uuid += hex[Math.floor(Math.random() * 4) + 8] // Variant bits
    } else {
      uuid += hex[Math.floor(Math.random() * 16)]
    }
  }

  return uuid
}

/**
 * Create a patch entry for testing
 */
export function createTestPatchEntry(options: {
  uuid?: string // If not provided, generates a valid UUID
  files: Record<string, { beforeContent: string; afterContent: string }>
  vulnerabilities?: Record<
    string,
    {
      cves: string[]
      summary: string
      severity: string
      description: string
    }
  >
  description?: string
  license?: string
  tier?: 'free' | 'paid'
}): { entry: PatchRecord; blobs: Record<string, string> } {
  const files: Record<string, { beforeHash: string; afterHash: string }> = {}
  const blobs: Record<string, string> = {}

  for (const [filePath, { beforeContent, afterContent }] of Object.entries(
    options.files,
  )) {
    const beforeHash = computeTestHash(beforeContent)
    const afterHash = computeTestHash(afterContent)

    files[filePath] = { beforeHash, afterHash }
    blobs[beforeHash] = beforeContent
    blobs[afterHash] = afterContent
  }

  return {
    entry: {
      uuid: options.uuid ?? generateTestUUID(),
      exportedAt: new Date().toISOString(),
      files,
      vulnerabilities: options.vulnerabilities ?? {},
      description: options.description ?? 'Test patch',
      license: options.license ?? 'MIT',
      tier: options.tier ?? 'free',
    },
    blobs,
  }
}

/**
 * Write a manifest to disk
 */
export async function writeTestManifest(
  socketDir: string,
  manifest: PatchManifest,
): Promise<string> {
  await fs.mkdir(socketDir, { recursive: true })
  const manifestPath = path.join(socketDir, 'manifest.json')
  await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n')
  return manifestPath
}

/**
 * Create mock blob files
 */
export async function writeTestBlobs(
  blobsDir: string,
  blobs: Record<string, string>,
): Promise<void> {
  await fs.mkdir(blobsDir, { recursive: true })

  for (const [hash, content] of Object.entries(blobs)) {
    const blobPath = path.join(blobsDir, hash)
    await fs.writeFile(blobPath, content)
  }
}

/**
 * Create a mock package in node_modules
 */
export async function createTestPackage(
  nodeModulesDir: string,
  name: string,
  version: string,
  files: Record<string, string>,
): Promise<string> {
  // Handle scoped packages
  const parts = name.split('/')
  let pkgDir: string

  if (parts.length === 2 && parts[0].startsWith('@')) {
    // Scoped package: @scope/name
    const scopeDir = path.join(nodeModulesDir, parts[0])
    await fs.mkdir(scopeDir, { recursive: true })
    pkgDir = path.join(scopeDir, parts[1])
  } else {
    // Regular package
    pkgDir = path.join(nodeModulesDir, name)
  }

  await fs.mkdir(pkgDir, { recursive: true })

  // Write package.json
  await fs.writeFile(
    path.join(pkgDir, 'package.json'),
    JSON.stringify({ name, version }, null, 2),
  )

  // Write other files
  for (const [filePath, content] of Object.entries(files)) {
    const fullPath = path.join(pkgDir, filePath)
    await fs.mkdir(path.dirname(fullPath), { recursive: true })
    await fs.writeFile(fullPath, content)
  }

  return pkgDir
}

/**
 * Create a mock Python package in site-packages
 * Creates <sitePackagesDir>/<name>-<version>.dist-info/METADATA
 * and writes package files relative to sitePackagesDir
 */
export async function createTestPythonPackage(
  sitePackagesDir: string,
  name: string,
  version: string,
  files: Record<string, string>,
): Promise<string> {
  await fs.mkdir(sitePackagesDir, { recursive: true })

  // Create dist-info directory with METADATA
  const distInfoDir = path.join(
    sitePackagesDir,
    `${name}-${version}.dist-info`,
  )
  await fs.mkdir(distInfoDir, { recursive: true })
  await fs.writeFile(
    path.join(distInfoDir, 'METADATA'),
    `Metadata-Version: 2.1\nName: ${name}\nVersion: ${version}\nSummary: Test package\n`,
  )

  // Write package files relative to sitePackagesDir
  for (const [filePath, content] of Object.entries(files)) {
    const fullPath = path.join(sitePackagesDir, filePath)
    await fs.mkdir(path.dirname(fullPath), { recursive: true })
    await fs.writeFile(fullPath, content)
  }

  return sitePackagesDir
}

/**
 * Read file content from a package
 */
export async function readPackageFile(
  pkgDir: string,
  filePath: string,
): Promise<string> {
  return fs.readFile(path.join(pkgDir, filePath), 'utf-8')
}

/**
 * Setup a complete test environment with manifest, blobs, and packages
 */
export async function setupTestEnvironment(options: {
  testDir: string
  patches: Array<{
    purl: string
    uuid: string
    files: Record<string, { beforeContent: string; afterContent: string }>
  }>
  initialState?: 'before' | 'after' // whether packages start in before or after state
}): Promise<{
  manifestPath: string
  blobsDir: string
  nodeModulesDir: string
  sitePackagesDir: string
  socketDir: string
  packageDirs: Map<string, string>
}> {
  const { testDir, patches, initialState = 'before' } = options

  const socketDir = path.join(testDir, '.socket')
  const blobsDir = path.join(socketDir, 'blobs')
  const nodeModulesDir = path.join(testDir, 'node_modules')
  const sitePackagesDir = path.join(
    testDir,
    '.venv',
    'lib',
    'python3.11',
    'site-packages',
  )

  await fs.mkdir(socketDir, { recursive: true })
  await fs.mkdir(blobsDir, { recursive: true })
  await fs.mkdir(nodeModulesDir, { recursive: true })

  const allBlobs: Record<string, string> = {}
  const manifestPatches: Record<string, PatchRecord> = {}
  const packageDirs = new Map<string, string>()

  for (const patch of patches) {
    const { entry, blobs } = createTestPatchEntry({
      uuid: patch.uuid,
      files: patch.files,
    })

    manifestPatches[patch.purl] = entry
    Object.assign(allBlobs, blobs)

    // Strip qualifiers for PURL matching
    const qIdx = patch.purl.indexOf('?')
    const basePurl = qIdx === -1 ? patch.purl : patch.purl.slice(0, qIdx)

    // Extract package name and version from PURL
    // Format: pkg:npm/name@version or pkg:npm/@scope/name@version
    const npmMatch = basePurl.match(/^pkg:npm\/(.+)@([^@]+)$/)
    if (npmMatch) {
      const [, name, version] = npmMatch

      // Prepare package files in initial state
      const packageFiles: Record<string, string> = {}
      for (const [filePath, { beforeContent, afterContent }] of Object.entries(
        patch.files,
      )) {
        // Remove 'package/' prefix if present
        const normalizedPath = filePath.startsWith('package/')
          ? filePath.slice('package/'.length)
          : filePath
        packageFiles[normalizedPath] =
          initialState === 'before' ? beforeContent : afterContent
      }

      const pkgDir = await createTestPackage(
        nodeModulesDir,
        name,
        version,
        packageFiles,
      )
      packageDirs.set(patch.purl, pkgDir)
    }

    // Handle pkg:pypi/ PURLs
    const pypiMatch = basePurl.match(/^pkg:pypi\/([^@]+)@(.+)$/)
    if (pypiMatch) {
      const [, name, version] = pypiMatch

      // Prepare package files in initial state relative to site-packages
      const packageFiles: Record<string, string> = {}
      for (const [filePath, { beforeContent, afterContent }] of Object.entries(
        patch.files,
      )) {
        packageFiles[filePath] =
          initialState === 'before' ? beforeContent : afterContent
      }

      await createTestPythonPackage(
        sitePackagesDir,
        name,
        version,
        packageFiles,
      )
      packageDirs.set(patch.purl, sitePackagesDir)
    }
  }

  await writeTestBlobs(blobsDir, allBlobs)
  const manifestPath = await writeTestManifest(
    socketDir,
    createTestManifest(manifestPatches),
  )

  return {
    manifestPath,
    blobsDir,
    nodeModulesDir,
    sitePackagesDir,
    socketDir,
    packageDirs,
  }
}

import * as fs from 'fs/promises'
import * as path from 'path'
import * as readline from 'readline'
import * as os from 'os'
import type { CommandModule } from 'yargs'
import { PatchManifestSchema } from '../schema/manifest-schema.js'
import {
  getAPIClientFromEnv,
  type APIClient,
  type PatchResponse,
  type PatchSearchResult,
  type SearchResponse,
} from '../utils/api-client.js'
import {
  cleanupUnusedBlobs,
  formatCleanupResult,
} from '../utils/cleanup-blobs.js'
import { NpmCrawler, PythonCrawler, type CrawledPackage } from '../crawlers/index.js'
import { fuzzyMatchPackages, isPurl } from '../utils/fuzzy-match.js'
import { applyPackagePatch, verifyFilePatch } from '../patch/apply.js'
import { rollbackPackagePatch } from '../patch/rollback.js'
import {
  getMissingBlobs,
  fetchMissingBlobs,
  formatFetchResult,
} from '../utils/blob-fetcher.js'
import {
  isPyPIPurl,
  isNpmPurl,
  stripPurlQualifiers,
} from '../utils/purl-utils.js'

/**
 * Represents a package that has available patches with CVE information
 */
interface PackageWithPatchInfo extends CrawledPackage {
  /** Available patches for this package */
  patches: PatchSearchResult[]
  /** Whether user can access paid patches */
  canAccessPaidPatches: boolean
  /** CVE IDs that this package's patches address */
  cveIds: string[]
  /** GHSA IDs that this package's patches address */
  ghsaIds: string[]
}

// Identifier type patterns
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const CVE_PATTERN = /^CVE-\d{4}-\d+$/i
const GHSA_PATTERN = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i

// Maximum number of packages to check for patches (to limit API queries)
const MAX_PACKAGES_TO_CHECK = 15

type IdentifierType = 'uuid' | 'cve' | 'ghsa' | 'purl' | 'package'

/**
 * Parse a PURL to extract the package directory path, version, and ecosystem.
 * Supports both npm and pypi PURLs.
 * @example parsePurl('pkg:npm/lodash@4.17.21') => { packageDir: 'lodash', version: '4.17.21', ecosystem: 'npm' }
 * @example parsePurl('pkg:npm/@types/node@20.0.0') => { packageDir: '@types/node', version: '20.0.0', ecosystem: 'npm' }
 * @example parsePurl('pkg:pypi/requests@2.28.0') => { packageDir: 'requests', version: '2.28.0', ecosystem: 'pypi' }
 */
function parsePurl(purl: string): { packageDir: string; version: string; ecosystem: 'npm' | 'pypi' } | null {
  // Strip qualifiers for parsing
  const base = stripPurlQualifiers(purl)
  const npmMatch = base.match(/^pkg:npm\/(.+)@([^@]+)$/)
  if (npmMatch) return { packageDir: npmMatch[1], version: npmMatch[2], ecosystem: 'npm' }
  const pypiMatch = base.match(/^pkg:pypi\/(.+)@([^@]+)$/)
  if (pypiMatch) return { packageDir: pypiMatch[1], version: pypiMatch[2], ecosystem: 'pypi' }
  return null
}

/**
 * Check which PURLs from search results are actually installed.
 * Supports both npm (node_modules) and pypi (site-packages) packages.
 * This is O(n) where n = number of unique packages in search results,
 * NOT O(m) where m = total packages in node_modules/site-packages.
 */
async function findInstalledPurls(
  cwd: string,
  purls: string[],
  useGlobal: boolean,
  globalPrefix?: string,
): Promise<Set<string>> {
  const installedPurls = new Set<string>()

  // Partition PURLs by ecosystem
  const npmPurls = purls.filter(p => isNpmPurl(p))
  const pypiPurls = purls.filter(p => isPyPIPurl(p))

  const crawlerOptions = { cwd, global: useGlobal, globalPrefix }

  // Check npm PURLs
  if (npmPurls.length > 0) {
    const npmCrawler = new NpmCrawler()
    try {
      const nmPaths = await npmCrawler.getNodeModulesPaths(crawlerOptions)
      for (const nmPath of nmPaths) {
        const packages = await npmCrawler.findByPurls(nmPath, npmPurls)
        for (const purl of packages.keys()) {
          installedPurls.add(purl)
        }
      }
    } catch {
      // npm not available
    }
  }

  // Check pypi PURLs
  if (pypiPurls.length > 0) {
    const pythonCrawler = new PythonCrawler()
    try {
      const basePurls = [...new Set(pypiPurls.map(stripPurlQualifiers))]
      const spPaths = await pythonCrawler.getSitePackagesPaths(crawlerOptions)
      for (const spPath of spPaths) {
        const packages = await pythonCrawler.findByPurls(spPath, basePurls)
        for (const basePurl of packages.keys()) {
          // Mark all qualified variants of this base PURL as installed
          for (const originalPurl of pypiPurls) {
            if (stripPurlQualifiers(originalPurl) === basePurl) {
              installedPurls.add(originalPurl)
            }
          }
        }
      }
    } catch {
      // python not available
    }
  }

  return installedPurls
}

/**
 * Check which packages have available patches with CVE fixes.
 * Queries the API for each package and returns only those with patches.
 *
 * @param apiClient - API client to use for queries
 * @param orgSlug - Organization slug (or null for public proxy)
 * @param packages - Packages to check
 * @param onProgress - Optional callback for progress updates
 * @returns Packages that have available patches with CVE info
 */
async function findPackagesWithPatches(
  apiClient: APIClient,
  orgSlug: string | null,
  packages: CrawledPackage[],
  onProgress?: (checked: number, total: number, current: string) => void,
): Promise<PackageWithPatchInfo[]> {
  const packagesWithPatches: PackageWithPatchInfo[] = []

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i]
    const displayName = pkg.namespace
      ? `${pkg.namespace}/${pkg.name}`
      : pkg.name

    if (onProgress) {
      onProgress(i + 1, packages.length, displayName)
    }

    try {
      const searchResponse = await apiClient.searchPatchesByPackage(
        orgSlug,
        pkg.purl,
      )

      const { patches, canAccessPaidPatches } = searchResponse

      // Include all patches (free and paid) - we'll show upgrade CTA for paid patches
      if (patches.length === 0) {
        continue
      }

      // Extract CVE and GHSA IDs from all patches
      const cveIds = new Set<string>()
      const ghsaIds = new Set<string>()

      for (const patch of patches) {
        for (const [vulnId, vulnInfo] of Object.entries(patch.vulnerabilities)) {
          // Check if the vulnId itself is a GHSA
          if (GHSA_PATTERN.test(vulnId)) {
            ghsaIds.add(vulnId)
          }
          // Add all CVEs associated with this vulnerability
          for (const cve of vulnInfo.cves) {
            cveIds.add(cve)
          }
        }
      }

      // Only include packages that have CVE fixes
      if (cveIds.size === 0 && ghsaIds.size === 0) {
        continue
      }

      packagesWithPatches.push({
        ...pkg,
        patches,
        canAccessPaidPatches,
        cveIds: Array.from(cveIds).sort(),
        ghsaIds: Array.from(ghsaIds).sort(),
      })
    } catch {
      // Skip packages that fail API lookup (likely network issues)
      continue
    }
  }

  return packagesWithPatches
}

interface GetArgs {
  identifier: string
  org?: string
  cwd: string
  id?: boolean
  cve?: boolean
  ghsa?: boolean
  package?: boolean
  yes?: boolean
  'api-url'?: string
  'api-token'?: string
  'no-apply'?: boolean
  global?: boolean
  'global-prefix'?: string
  'one-off'?: boolean
}

/**
 * Detect the type of identifier based on its format
 */
function detectIdentifierType(identifier: string): IdentifierType | null {
  if (UUID_PATTERN.test(identifier)) {
    return 'uuid'
  }
  if (CVE_PATTERN.test(identifier)) {
    return 'cve'
  }
  if (GHSA_PATTERN.test(identifier)) {
    return 'ghsa'
  }
  if (isPurl(identifier)) {
    return 'purl'
  }
  return null
}

/**
 * Prompt user for confirmation
 */
async function promptConfirmation(message: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  })

  return new Promise(resolve => {
    rl.question(`${message} [y/N] `, answer => {
      rl.close()
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes')
    })
  })
}

/**
 * Display packages with available patches and CVE info, prompt user to select one
 */
async function promptSelectPackageWithPatches(
  packages: PackageWithPatchInfo[],
): Promise<PackageWithPatchInfo | null> {
  console.log('\nPackages with available security patches:\n')

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i]
    const displayName = pkg.namespace
      ? `${pkg.namespace}/${pkg.name}`
      : pkg.name

    // Build vulnerability summary
    const vulnIds = [...pkg.cveIds, ...pkg.ghsaIds]
    const vulnSummary = vulnIds.length > 3
      ? `${vulnIds.slice(0, 3).join(', ')} (+${vulnIds.length - 3} more)`
      : vulnIds.join(', ')

    // Count free vs paid patches
    const freePatches = pkg.patches.filter(p => p.tier === 'free').length
    const paidPatches = pkg.patches.filter(p => p.tier === 'paid').length

    // Count patches and show severity info
    const severities = new Set<string>()
    for (const patch of pkg.patches) {
      for (const vuln of Object.values(patch.vulnerabilities)) {
        severities.add(vuln.severity)
      }
    }
    const severityList = Array.from(severities).sort((a, b) => {
      const order = ['critical', 'high', 'medium', 'low']
      return order.indexOf(a.toLowerCase()) - order.indexOf(b.toLowerCase())
    })

    // Build patch count string
    let patchCountStr = String(freePatches)
    if (paidPatches > 0) {
      if (pkg.canAccessPaidPatches) {
        patchCountStr += `+${paidPatches}`
      } else {
        patchCountStr += `+\x1b[33m${paidPatches} paid\x1b[0m`
      }
    }

    console.log(`  ${i + 1}. ${displayName}@${pkg.version}`)
    console.log(`     Patches: ${patchCountStr} | Severity: ${severityList.join(', ')}`)
    console.log(`     Fixes: ${vulnSummary}`)
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  })

  return new Promise(resolve => {
    rl.question(
      `\nSelect a package (1-${packages.length}) or 0 to cancel: `,
      answer => {
        rl.close()
        const selection = parseInt(answer, 10)
        if (isNaN(selection) || selection < 1 || selection > packages.length) {
          resolve(null)
        } else {
          resolve(packages[selection - 1])
        }
      },
    )
  })
}

/**
 * Display search results to the user
 */
function displaySearchResults(
  patches: PatchSearchResult[],
  canAccessPaidPatches: boolean,
): void {
  console.log('\nFound patches:\n')

  for (let i = 0; i < patches.length; i++) {
    const patch = patches[i]
    const tierLabel = patch.tier === 'paid' ? ' [PAID]' : ' [FREE]'
    const accessLabel =
      patch.tier === 'paid' && !canAccessPaidPatches ? ' (no access)' : ''

    console.log(`  ${i + 1}. ${patch.purl}${tierLabel}${accessLabel}`)
    console.log(`     UUID: ${patch.uuid}`)
    if (patch.description) {
      const desc =
        patch.description.length > 80
          ? patch.description.slice(0, 77) + '...'
          : patch.description
      console.log(`     Description: ${desc}`)
    }

    // Show vulnerabilities
    const vulnIds = Object.keys(patch.vulnerabilities)
    if (vulnIds.length > 0) {
      const vulnSummary = vulnIds
        .map(id => {
          const vuln = patch.vulnerabilities[id]
          const cves = vuln.cves.length > 0 ? vuln.cves.join(', ') : id
          return `${cves} (${vuln.severity})`
        })
        .join(', ')
      console.log(`     Fixes: ${vulnSummary}`)
    }
    console.log()
  }
}

/**
 * Save a patch to the manifest and blobs directory
 * Only saves afterHash blobs - beforeHash blobs are downloaded on-demand during rollback
 */
async function savePatch(
  patch: PatchResponse,
  manifest: any,
  blobsDir: string,
): Promise<boolean> {
  // Check if patch already exists with same UUID
  if (manifest.patches[patch.purl]?.uuid === patch.uuid) {
    console.log(`  [skip] ${patch.purl} (already in manifest)`)
    return false
  }

  // Save blob contents (only afterHash blobs to save disk space)
  const files: Record<string, { beforeHash?: string; afterHash?: string }> = {}
  for (const [filePath, fileInfo] of Object.entries(patch.files)) {
    if (fileInfo.afterHash) {
      files[filePath] = {
        beforeHash: fileInfo.beforeHash,
        afterHash: fileInfo.afterHash,
      }
    }

    // Save after blob content if provided
    // Note: beforeHash blobs are NOT saved here - they are downloaded on-demand during rollback
    if (fileInfo.blobContent && fileInfo.afterHash) {
      const blobPath = path.join(blobsDir, fileInfo.afterHash)
      const blobBuffer = Buffer.from(fileInfo.blobContent, 'base64')
      await fs.writeFile(blobPath, blobBuffer)
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

  console.log(`  [add] ${patch.purl}`)
  return true
}

/**
 * Apply patches after downloading
 */
async function applyDownloadedPatches(
  cwd: string,
  manifestPath: string,
  silent: boolean,
  useGlobal: boolean,
  globalPrefix?: string,
): Promise<boolean> {
  // Read and parse manifest
  const manifestContent = await fs.readFile(manifestPath, 'utf-8')
  const manifestData = JSON.parse(manifestContent)
  const manifest = PatchManifestSchema.parse(manifestData)

  // Find .socket directory (contains blobs)
  const socketDir = path.dirname(manifestPath)
  const blobsPath = path.join(socketDir, 'blobs')

  // Ensure blobs directory exists
  await fs.mkdir(blobsPath, { recursive: true })

  // Check for and download missing blobs
  const missingBlobs = await getMissingBlobs(manifest, blobsPath)
  if (missingBlobs.size > 0) {
    if (!silent) {
      console.log(`Downloading ${missingBlobs.size} missing blob(s)...`)
    }

    const fetchResult = await fetchMissingBlobs(manifest, blobsPath, undefined, {
      onProgress: silent
        ? undefined
        : (hash, index, total) => {
            process.stdout.write(
              `\r  Downloading ${index}/${total}: ${hash.slice(0, 12)}...`.padEnd(60),
            )
          },
    })

    if (!silent) {
      // Clear progress line
      process.stdout.write('\r' + ' '.repeat(60) + '\r')
      console.log(formatFetchResult(fetchResult))
    }

    if (fetchResult.failed > 0) {
      if (!silent) {
        console.error('Some blobs could not be downloaded. Cannot apply patches.')
      }
      return false
    }
  }

  // Partition manifest PURLs by ecosystem
  const manifestPurls = Object.keys(manifest.patches)
  const npmPurls = manifestPurls.filter(p => isNpmPurl(p))
  const pypiPurls = manifestPurls.filter(p => isPyPIPurl(p))

  const crawlerOptions = { cwd, global: useGlobal, globalPrefix }
  const allPackages = new Map<string, string>()

  // Find npm packages
  if (npmPurls.length > 0) {
    const npmCrawler = new NpmCrawler()
    try {
      const nodeModulesPaths = await npmCrawler.getNodeModulesPaths(crawlerOptions)
      for (const nmPath of nodeModulesPaths) {
        const packages = await npmCrawler.findByPurls(nmPath, npmPurls)
        for (const [purl, location] of packages) {
          if (!allPackages.has(purl)) {
            allPackages.set(purl, location.path)
          }
        }
      }
    } catch (error) {
      if (!silent) {
        console.error('Failed to find npm packages:', error instanceof Error ? error.message : String(error))
      }
    }
  }

  // Find Python packages
  if (pypiPurls.length > 0) {
    const pythonCrawler = new PythonCrawler()
    try {
      const basePypiPurls = [...new Set(pypiPurls.map(stripPurlQualifiers))]
      const sitePackagesPaths = await pythonCrawler.getSitePackagesPaths(crawlerOptions)
      for (const spPath of sitePackagesPaths) {
        const packages = await pythonCrawler.findByPurls(spPath, basePypiPurls)
        for (const [purl, location] of packages) {
          if (!allPackages.has(purl)) {
            allPackages.set(purl, location.path)
          }
        }
      }
    } catch (error) {
      if (!silent) {
        console.error('Failed to find Python packages:', error instanceof Error ? error.message : String(error))
      }
    }
  }

  if (allPackages.size === 0) {
    if (!silent) {
      console.log('No packages found that match available patches')
    }
    return true
  }

  // Group pypi manifest PURLs by base PURL for qualifier fallback
  const pypiQualifiedGroups = new Map<string, string[]>()
  for (const purl of pypiPurls) {
    const base = stripPurlQualifiers(purl)
    const group = pypiQualifiedGroups.get(base)
    if (group) {
      group.push(purl)
    } else {
      pypiQualifiedGroups.set(base, [purl])
    }
  }

  // Apply patches to each package
  let hasErrors = false
  const patchedPackages: string[] = []
  const alreadyPatched: string[] = []
  const appliedBasePurls = new Set<string>()

  for (const [purl, pkgPath] of allPackages) {
    if (isPyPIPurl(purl)) {
      const basePurl = stripPurlQualifiers(purl)
      if (appliedBasePurls.has(basePurl)) continue

      const variants = pypiQualifiedGroups.get(basePurl) ?? [basePurl]
      let applied = false

      for (const variantPurl of variants) {
        const patch = manifest.patches[variantPurl]
        if (!patch) continue

        // Check if this variant's beforeHash matches the file on disk
        const firstFile = Object.entries(patch.files)[0]
        if (firstFile) {
          const [fileName, fileInfo] = firstFile
          const verify = await verifyFilePatch(pkgPath, fileName, fileInfo)
          if (verify.status === 'hash-mismatch') continue
        }

        const result = await applyPackagePatch(
          variantPurl,
          pkgPath,
          patch.files,
          blobsPath,
          false,
        )

        if (result.success) {
          applied = true
          appliedBasePurls.add(basePurl)
          if (result.filesPatched.length > 0) {
            patchedPackages.push(variantPurl)
          } else if (result.filesVerified.every(f => f.status === 'already-patched')) {
            alreadyPatched.push(variantPurl)
          }
          break
        }
      }

      if (!applied) {
        hasErrors = true
        if (!silent) {
          console.error(`Failed to patch ${basePurl}: no matching variant found`)
        }
      }
    } else {
      const patch = manifest.patches[purl]
      if (!patch) continue

      const result = await applyPackagePatch(
        purl,
        pkgPath,
        patch.files,
        blobsPath,
        false,
      )

      if (!result.success) {
        hasErrors = true
        if (!silent) {
          console.error(`Failed to patch ${purl}: ${result.error}`)
        }
      } else if (result.filesPatched.length > 0) {
        patchedPackages.push(purl)
      } else if (result.filesVerified.every(f => f.status === 'already-patched')) {
        alreadyPatched.push(purl)
      }
    }
  }

  // Print results
  if (!silent) {
    if (patchedPackages.length > 0) {
      console.log(`\nPatched packages:`)
      for (const pkg of patchedPackages) {
        console.log(`  ${pkg}`)
      }
    }
    if (alreadyPatched.length > 0) {
      console.log(`\nAlready patched:`)
      for (const pkg of alreadyPatched) {
        console.log(`  ${pkg}`)
      }
    }
  }

  return !hasErrors
}

/**
 * Handle one-off patch application (no manifest storage)
 */
async function applyOneOffPatch(
  patch: PatchResponse,
  useGlobal: boolean,
  cwd: string,
  silent: boolean,
  globalPrefix?: string,
): Promise<{ success: boolean; rollback?: () => Promise<void> }> {
  const parsed = parsePurl(patch.purl)
  if (!parsed) {
    if (!silent) {
      console.error(`Invalid PURL format: ${patch.purl}`)
    }
    return { success: false }
  }

  let pkgPath: string
  const crawlerOptions = { cwd, global: useGlobal, globalPrefix }

  if (parsed.ecosystem === 'pypi') {
    // Find the package in Python site-packages
    const pythonCrawler = new PythonCrawler()
    try {
      const basePurl = stripPurlQualifiers(patch.purl)
      const spPaths = await pythonCrawler.getSitePackagesPaths(crawlerOptions)
      let found = false
      pkgPath = '' // Will be set if found

      for (const spPath of spPaths) {
        const packages = await pythonCrawler.findByPurls(spPath, [basePurl])
        const pkg = packages.get(basePurl)
        if (pkg) {
          pkgPath = pkg.path
          found = true
          break
        }
      }

      if (!found) {
        if (!silent) {
          console.error(`Python package not found: ${parsed.packageDir}@${parsed.version}`)
        }
        return { success: false }
      }
    } catch (error) {
      if (!silent) {
        console.error('Failed to find Python packages:', error instanceof Error ? error.message : String(error))
      }
      return { success: false }
    }
  } else {
    // npm: Find the package in node_modules
    const npmCrawler = new NpmCrawler()
    let nodeModulesPath: string
    try {
      const paths = await npmCrawler.getNodeModulesPaths(crawlerOptions)
      nodeModulesPath = paths[0] ?? path.join(cwd, 'node_modules')
    } catch (error) {
      if (!silent) {
        console.error('Failed to find npm packages:', error instanceof Error ? error.message : String(error))
      }
      return { success: false }
    }

    pkgPath = path.join(nodeModulesPath, parsed.packageDir)

    // Verify npm package exists
    try {
      const pkgJsonPath = path.join(pkgPath, 'package.json')
      const pkgJsonContent = await fs.readFile(pkgJsonPath, 'utf-8')
      const pkgJson = JSON.parse(pkgJsonContent)
      if (pkgJson.version !== parsed.version) {
        if (!silent) {
          console.error(`Version mismatch: installed ${pkgJson.version}, patch is for ${parsed.version}`)
        }
        return { success: false }
      }
    } catch {
      if (!silent) {
        console.error(`Package not found: ${parsed.packageDir}`)
      }
      return { success: false }
    }
  }

  // Create temporary directory for blobs
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'socket-patch-'))
  const tempBlobsDir = path.join(tempDir, 'blobs')
  await fs.mkdir(tempBlobsDir, { recursive: true })

  // Store beforeHash blobs in temp directory for rollback
  const beforeBlobs = new Map<string, Buffer>()
  for (const [, fileInfo] of Object.entries(patch.files)) {
    if (fileInfo.beforeBlobContent && fileInfo.beforeHash) {
      const blobBuffer = Buffer.from(fileInfo.beforeBlobContent, 'base64')
      beforeBlobs.set(fileInfo.beforeHash, blobBuffer)
      await fs.writeFile(path.join(tempBlobsDir, fileInfo.beforeHash), blobBuffer)
    }
    if (fileInfo.blobContent && fileInfo.afterHash) {
      const blobBuffer = Buffer.from(fileInfo.blobContent, 'base64')
      await fs.writeFile(path.join(tempBlobsDir, fileInfo.afterHash), blobBuffer)
    }
  }

  // Build files record for applyPackagePatch
  const files: Record<string, { beforeHash: string; afterHash: string }> = {}
  for (const [filePath, fileInfo] of Object.entries(patch.files)) {
    if (fileInfo.beforeHash && fileInfo.afterHash) {
      files[filePath] = {
        beforeHash: fileInfo.beforeHash,
        afterHash: fileInfo.afterHash,
      }
    }
  }

  // Apply the patch
  const result = await applyPackagePatch(
    patch.purl,
    pkgPath,
    files,
    tempBlobsDir,
    false,
  )

  if (!result.success) {
    if (!silent) {
      console.error(`Failed to patch ${patch.purl}: ${result.error}`)
    }
    // Clean up temp directory
    await fs.rm(tempDir, { recursive: true, force: true })
    return { success: false }
  }

  if (!silent) {
    if (result.filesPatched.length > 0) {
      console.log(`\nPatched ${patch.purl}`)
    } else if (result.filesVerified.every(f => f.status === 'already-patched')) {
      console.log(`\n${patch.purl} is already patched`)
    }
  }

  // Return rollback function
  const rollback = async () => {
    if (!silent) {
      console.log(`Rolling back ${patch.purl}...`)
    }
    const rollbackResult = await rollbackPackagePatch(
      patch.purl,
      pkgPath,
      files,
      tempBlobsDir,
      false,
    )
    if (rollbackResult.success) {
      if (!silent) {
        console.log(`Rolled back ${patch.purl}`)
      }
    } else {
      if (!silent) {
        console.error(`Failed to rollback: ${rollbackResult.error}`)
      }
    }
    // Clean up temp directory
    await fs.rm(tempDir, { recursive: true, force: true })
  }

  return { success: true, rollback }
}

async function getPatches(args: GetArgs): Promise<boolean> {
  const {
    identifier,
    org: orgSlug,
    cwd,
    id: forceId,
    cve: forceCve,
    ghsa: forceGhsa,
    package: forcePackage,
    yes: skipConfirmation,
    'api-url': apiUrl,
    'api-token': apiToken,
    'no-apply': noApply,
    global: useGlobal,
    'global-prefix': globalPrefix,
    'one-off': oneOff,
  } = args

  // Override environment variables if CLI options are provided
  if (apiUrl) {
    process.env.SOCKET_API_URL = apiUrl
  }
  if (apiToken) {
    process.env.SOCKET_API_TOKEN = apiToken
  }

  // Get API client (will use public proxy if no token is set)
  const { client: apiClient, usePublicProxy } = getAPIClientFromEnv()

  // Validate that org is provided when using authenticated API
  if (!usePublicProxy && !orgSlug) {
    throw new Error(
      '--org is required when using SOCKET_API_TOKEN. Provide an organization slug.',
    )
  }

  // The org slug to use (null when using public proxy)
  const effectiveOrgSlug = usePublicProxy ? null : orgSlug ?? null

  // Set up crawlers for package lookups
  const npmCrawler = new NpmCrawler()
  const pythonCrawler = new PythonCrawler()
  const crawlerOptions = { cwd, global: useGlobal, globalPrefix }

  // Determine identifier type
  let idType: IdentifierType
  if (forceId) {
    idType = 'uuid'
  } else if (forceCve) {
    idType = 'cve'
  } else if (forceGhsa) {
    idType = 'ghsa'
  } else if (forcePackage) {
    // --package flag forces package search (fuzzy match against node_modules)
    idType = 'package'
  } else {
    const detectedType = detectIdentifierType(identifier)
    if (!detectedType) {
      // If not recognized as UUID/CVE/GHSA/PURL, assume it's a package name search
      idType = 'package'
      console.log(`Treating "${identifier}" as a package name search`)
    } else {
      idType = detectedType
      console.log(`Detected identifier type: ${idType}`)
    }
  }

  // For UUID, directly fetch and download the patch
  if (idType === 'uuid') {
    console.log(`Fetching patch by UUID: ${identifier}`)
    const patch = await apiClient.fetchPatch(effectiveOrgSlug, identifier)
    if (!patch) {
      console.log(`No patch found with UUID: ${identifier}`)
      return true
    }

    // Check if patch is paid and user doesn't have access
    if (patch.tier === 'paid' && usePublicProxy) {
      console.log(`\n\x1b[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m`)
      console.log(`\x1b[33m  This patch requires a paid subscription to download.\x1b[0m`)
      console.log(`\x1b[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m`)
      console.log(`\n  Patch: ${patch.purl}`)
      console.log(`  Tier:  \x1b[33mpaid\x1b[0m`)
      console.log(`\n  Upgrade to Socket's paid plan to access this patch and many more:`)
      console.log(`  \x1b[36mhttps://socket.dev/pricing\x1b[0m\n`)
      return true
    }

    // Handle one-off mode
    if (oneOff) {
      const { success, rollback } = await applyOneOffPatch(patch, useGlobal ?? false, cwd, false, globalPrefix)
      if (success && rollback) {
        console.log('\nPatch applied (one-off mode). The patch will persist until you reinstall the package.')
        console.log('To rollback, use: socket-patch rollback --one-off ' + identifier + (useGlobal ? ' --global' : ''))
      }
      return success
    }

    // Prepare .socket directory
    const socketDir = path.join(cwd, '.socket')
    const blobsDir = path.join(socketDir, 'blobs')
    const manifestPath = path.join(socketDir, 'manifest.json')

    await fs.mkdir(socketDir, { recursive: true })
    await fs.mkdir(blobsDir, { recursive: true })

    let manifest: any
    try {
      const manifestContent = await fs.readFile(manifestPath, 'utf-8')
      manifest = PatchManifestSchema.parse(JSON.parse(manifestContent))
    } catch {
      manifest = { patches: {} }
    }

    const added = await savePatch(patch, manifest, blobsDir)

    await fs.writeFile(
      manifestPath,
      JSON.stringify(manifest, null, 2) + '\n',
      'utf-8',
    )

    console.log(`\nPatch saved to ${manifestPath}`)
    if (added) {
      console.log(`  Added: 1`)
    } else {
      console.log(`  Skipped: 1 (already exists)`)
    }

    // Auto-apply unless --no-apply is specified
    if (!noApply) {
      console.log('\nApplying patches...')
      const applySuccess = await applyDownloadedPatches(cwd, manifestPath, false, useGlobal ?? false, globalPrefix)
      if (!applySuccess) {
        console.error('\nSome patches could not be applied.')
      }
    }

    return true
  }

  // For CVE/GHSA/PURL/package, first search then download
  let searchResponse: SearchResponse

  switch (idType) {
    case 'cve': {
      console.log(`Searching patches for CVE: ${identifier}`)
      searchResponse = await apiClient.searchPatchesByCVE(effectiveOrgSlug, identifier)
      break
    }
    case 'ghsa': {
      console.log(`Searching patches for GHSA: ${identifier}`)
      searchResponse = await apiClient.searchPatchesByGHSA(effectiveOrgSlug, identifier)
      break
    }
    case 'purl': {
      console.log(`Searching patches for PURL: ${identifier}`)
      searchResponse = await apiClient.searchPatchesByPackage(effectiveOrgSlug, identifier)
      break
    }
    case 'package': {
      // Enumerate packages from both npm and Python ecosystems, then fuzzy match
      console.log(`Enumerating packages...`)
      const npmPackages = await npmCrawler.crawlAll(crawlerOptions)
      const pythonPackages = await pythonCrawler.crawlAll(crawlerOptions)
      const packages: CrawledPackage[] = [...npmPackages, ...pythonPackages]

      if (packages.length === 0) {
        console.log(useGlobal
          ? 'No global packages found.'
          : 'No packages found. Run npm/yarn/pnpm/pip install first.')
        return true
      }

      console.log(`Found ${packages.length} packages`)

      // Fuzzy match against the identifier
      let matches = fuzzyMatchPackages(identifier, packages)

      if (matches.length === 0) {
        console.log(`No packages matching "${identifier}" found.`)
        return true
      }

      // Sort by package name length (shorter names are typically more relevant/common)
      // and truncate to limit API queries
      let truncatedCount = 0
      if (matches.length > MAX_PACKAGES_TO_CHECK) {
        // Sort by full name length (namespace/name) - shorter = more relevant
        matches = matches.sort((a, b) => {
          const aFullName = a.namespace ? `${a.namespace}/${a.name}` : a.name
          const bFullName = b.namespace ? `${b.namespace}/${b.name}` : b.name
          return aFullName.length - bFullName.length
        })
        truncatedCount = matches.length - MAX_PACKAGES_TO_CHECK
        matches = matches.slice(0, MAX_PACKAGES_TO_CHECK)
        console.log(`Found ${matches.length + truncatedCount} matching package(s), checking top ${MAX_PACKAGES_TO_CHECK} by name length...`)
      } else {
        console.log(`Found ${matches.length} matching package(s), checking for available patches...`)
      }

      // Check which packages have available patches with CVE fixes
      const packagesWithPatches = await findPackagesWithPatches(
        apiClient,
        effectiveOrgSlug,
        matches,
        (checked, total, current) => {
          // Clear line and show progress
          process.stdout.write(`\r  Checking ${checked}/${total}: ${current}`.padEnd(80))
        },
      )
      // Clear the progress line
      process.stdout.write('\r' + ' '.repeat(80) + '\r')

      if (packagesWithPatches.length === 0) {
        console.log(`No patches with CVE fixes found for packages matching "${identifier}".`)
        const checkedCount = matches.length
        if (checkedCount > 0) {
          console.log(`  (${checkedCount} package(s) checked but none have available patches)`)
        }
        if (truncatedCount > 0) {
          console.log(`  (${truncatedCount} additional match(es) not checked - try a more specific search)`)
        }
        return true
      }

      const skippedCount = matches.length - packagesWithPatches.length
      if (skippedCount > 0 || truncatedCount > 0) {
        let note = `Found ${packagesWithPatches.length} package(s) with available patches`
        if (skippedCount > 0) {
          note += ` (${skippedCount} without patches hidden)`
        }
        if (truncatedCount > 0) {
          note += ` (${truncatedCount} additional match(es) not checked)`
        }
        console.log(note)
      }

      let selectedPackage: PackageWithPatchInfo

      if (packagesWithPatches.length === 1) {
        // Single match with patches, use it directly
        selectedPackage = packagesWithPatches[0]
        const displayName = selectedPackage.namespace
          ? `${selectedPackage.namespace}/${selectedPackage.name}`
          : selectedPackage.name
        console.log(`Found: ${displayName}@${selectedPackage.version}`)
        console.log(`  Patches: ${selectedPackage.patches.length}`)
        console.log(`  Fixes: ${[...selectedPackage.cveIds, ...selectedPackage.ghsaIds].join(', ')}`)
      } else {
        // Multiple matches with patches, prompt user to select
        if (skipConfirmation) {
          // With --yes, use the first result (best match with patches)
          selectedPackage = packagesWithPatches[0]
          console.log(`Using best match: ${selectedPackage.purl}`)
        } else {
          const selected = await promptSelectPackageWithPatches(packagesWithPatches)
          if (!selected) {
            console.log('No package selected. Download cancelled.')
            return true
          }
          selectedPackage = selected
        }
      }

      // Use pre-fetched patch info directly
      searchResponse = {
        patches: selectedPackage.patches,
        canAccessPaidPatches: selectedPackage.canAccessPaidPatches,
      }
      break
    }
    default:
      throw new Error(`Unknown identifier type: ${idType}`)
  }

  const { patches: searchResults, canAccessPaidPatches } = searchResponse

  if (searchResults.length === 0) {
    console.log(`No patches found for ${idType}: ${identifier}`)
    return true
  }

  // For CVE/GHSA searches, filter to only show patches for installed packages
  // Uses O(n) filesystem operations where n = unique packages in results,
  // NOT O(m) where m = all packages in node_modules
  let filteredResults = searchResults
  let notInstalledCount = 0

  if (idType === 'cve' || idType === 'ghsa') {
    console.log(`Checking which packages are installed...`)
    const searchPurls = searchResults.map(patch => patch.purl)
    const installedPurls = await findInstalledPurls(cwd, searchPurls, useGlobal ?? false, globalPrefix)

    filteredResults = searchResults.filter(patch => installedPurls.has(patch.purl))
    notInstalledCount = searchResults.length - filteredResults.length

    if (filteredResults.length === 0) {
      console.log(`No patches found for installed packages.`)
      if (notInstalledCount > 0) {
        console.log(`  (${notInstalledCount} patch(es) exist for packages not installed in this project)`)
      }
      return true
    }
  }

  // Filter patches based on tier access
  const accessiblePatches = filteredResults.filter(
    patch => patch.tier === 'free' || canAccessPaidPatches,
  )
  const inaccessibleCount = filteredResults.length - accessiblePatches.length

  // Display search results
  displaySearchResults(filteredResults, canAccessPaidPatches)

  if (notInstalledCount > 0) {
    console.log(`Note: ${notInstalledCount} patch(es) for packages not installed in this project were hidden.`)
  }

  if (inaccessibleCount > 0 && !canAccessPaidPatches) {
    console.log(
      `\x1b[33mNote: ${inaccessibleCount} patch(es) require a paid subscription and will be skipped.\x1b[0m`,
    )
  }

  if (accessiblePatches.length === 0) {
    console.log(`\n\x1b[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m`)
    console.log(`\x1b[33m  All available patches require a paid subscription.\x1b[0m`)
    console.log(`\x1b[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m`)
    console.log(`\n  Found ${inaccessibleCount} paid patch(es) that you cannot currently access.`)
    console.log(`\n  Upgrade to Socket's paid plan to access these patches:`)
    console.log(`  \x1b[36mhttps://socket.dev/pricing\x1b[0m\n`)
    return true
  }

  // Prompt for confirmation if multiple patches and not using --yes
  if (accessiblePatches.length > 1 && !skipConfirmation) {
    const confirmed = await promptConfirmation(
      `Download ${accessiblePatches.length} patch(es)?`,
    )
    if (!confirmed) {
      console.log('Download cancelled.')
      return true
    }
  }

  // Handle one-off mode for search results
  if (oneOff) {
    // For one-off mode with multiple patches, apply the first one
    const patchToApply = accessiblePatches[0]
    console.log(`\nFetching and applying patch for ${patchToApply.purl}...`)

    const fullPatch = await apiClient.fetchPatch(effectiveOrgSlug, patchToApply.uuid)
    if (!fullPatch) {
      console.error(`Could not fetch patch details for ${patchToApply.uuid}`)
      return false
    }

    const { success, rollback } = await applyOneOffPatch(fullPatch, useGlobal ?? false, cwd, false, globalPrefix)
    if (success && rollback) {
      console.log('\nPatch applied (one-off mode). The patch will persist until you reinstall the package.')
      console.log('To rollback, use: socket-patch rollback --one-off ' + patchToApply.uuid + (useGlobal ? ' --global' : ''))
    }
    return success
  }

  // Prepare .socket directory
  const socketDir = path.join(cwd, '.socket')
  const blobsDir = path.join(socketDir, 'blobs')
  const manifestPath = path.join(socketDir, 'manifest.json')

  await fs.mkdir(socketDir, { recursive: true })
  await fs.mkdir(blobsDir, { recursive: true })

  let manifest: any
  try {
    const manifestContent = await fs.readFile(manifestPath, 'utf-8')
    manifest = PatchManifestSchema.parse(JSON.parse(manifestContent))
  } catch {
    manifest = { patches: {} }
  }

  // Download and save each accessible patch
  console.log(`\nDownloading ${accessiblePatches.length} patch(es)...`)

  let patchesAdded = 0
  let patchesSkipped = 0
  let patchesFailed = 0

  for (const searchResult of accessiblePatches) {
    // Fetch full patch details with blob content
    const patch = await apiClient.fetchPatch(effectiveOrgSlug, searchResult.uuid)
    if (!patch) {
      console.log(`  [fail] ${searchResult.purl} (could not fetch details)`)
      patchesFailed++
      continue
    }

    const added = await savePatch(patch, manifest, blobsDir)
    if (added) {
      patchesAdded++
    } else {
      patchesSkipped++
    }
  }

  // Write updated manifest
  await fs.writeFile(
    manifestPath,
    JSON.stringify(manifest, null, 2) + '\n',
    'utf-8',
  )

  console.log(`\nPatches saved to ${manifestPath}`)
  console.log(`  Added: ${patchesAdded}`)
  if (patchesSkipped > 0) {
    console.log(`  Skipped: ${patchesSkipped}`)
  }
  if (patchesFailed > 0) {
    console.log(`  Failed: ${patchesFailed}`)
  }

  // Clean up unused blobs
  const cleanupResult = await cleanupUnusedBlobs(manifest, blobsDir, false)
  if (cleanupResult.blobsRemoved > 0) {
    console.log(`\n${formatCleanupResult(cleanupResult, false)}`)
  }

  // Auto-apply unless --no-apply is specified
  if (!noApply && patchesAdded > 0) {
    console.log('\nApplying patches...')
    const applySuccess = await applyDownloadedPatches(cwd, manifestPath, false, useGlobal ?? false, globalPrefix)
    if (!applySuccess) {
      console.error('\nSome patches could not be applied.')
    }
  }

  return true
}

export const getCommand: CommandModule<{}, GetArgs> = {
  command: 'get <identifier>',
  aliases: ['download'],
  describe: 'Get security patches from Socket API and apply them',
  builder: yargs => {
    return yargs
      .positional('identifier', {
        describe:
          'Patch identifier (UUID, CVE ID, GHSA ID, PURL, or package name)',
        type: 'string',
        demandOption: true,
      })
      .option('org', {
        describe: 'Organization slug (required when using SOCKET_API_TOKEN, optional for public proxy)',
        type: 'string',
        demandOption: false,
      })
      .option('id', {
        describe: 'Force identifier to be treated as a patch UUID',
        type: 'boolean',
        default: false,
      })
      .option('cve', {
        describe: 'Force identifier to be treated as a CVE ID',
        type: 'boolean',
        default: false,
      })
      .option('ghsa', {
        describe: 'Force identifier to be treated as a GHSA ID',
        type: 'boolean',
        default: false,
      })
      .option('package', {
        alias: 'p',
        describe: 'Force identifier to be treated as a package name (fuzzy matches against node_modules)',
        type: 'boolean',
        default: false,
      })
      .option('yes', {
        alias: 'y',
        describe: 'Skip confirmation prompt for multiple patches',
        type: 'boolean',
        default: false,
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
      .option('no-apply', {
        describe: 'Download patch without applying it',
        type: 'boolean',
        default: false,
      })
      .option('global', {
        alias: 'g',
        describe: 'Apply patch to globally installed npm packages',
        type: 'boolean',
        default: false,
      })
      .option('global-prefix', {
        describe: 'Custom path to global node_modules (overrides auto-detection, useful for yarn/pnpm)',
        type: 'string',
      })
      .option('one-off', {
        describe: 'Apply patch immediately without saving to .socket folder (ephemeral)',
        type: 'boolean',
        default: false,
      })
      .example(
        '$0 get CVE-2021-44228',
        'Get and apply free patches for a CVE',
      )
      .example(
        '$0 get GHSA-jfhm-5ghh-2f97',
        'Get and apply free patches for a GHSA',
      )
      .example(
        '$0 get pkg:npm/lodash@4.17.21',
        'Get and apply patches for a specific package version by PURL',
      )
      .example(
        '$0 get lodash --package',
        'Search for patches by package name (fuzzy matches node_modules)',
      )
      .example(
        '$0 get CVE-2021-44228 --no-apply',
        'Download patches without applying them',
      )
      .example(
        '$0 get lodash --global',
        'Get and apply patches to globally installed package',
      )
      .example(
        '$0 get CVE-2021-44228 --one-off',
        'Apply patch immediately without saving to .socket folder',
      )
      .example(
        '$0 get lodash --global --one-off',
        'Apply patch to global package without saving',
      )
      .check(argv => {
        // Ensure only one type flag is set
        const typeFlags = [argv.id, argv.cve, argv.ghsa, argv.package].filter(
          Boolean,
        )
        if (typeFlags.length > 1) {
          throw new Error(
            'Only one of --id, --cve, --ghsa, or --package can be specified',
          )
        }
        // --one-off implies apply, so --no-apply doesn't make sense
        if (argv['one-off'] && argv['no-apply']) {
          throw new Error(
            '--one-off and --no-apply cannot be used together',
          )
        }
        return true
      })
  },
  handler: async argv => {
    try {
      const success = await getPatches(argv)
      process.exit(success ? 0 : 1)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      console.error(`Error: ${errorMessage}`)
      process.exit(1)
    }
  },
}

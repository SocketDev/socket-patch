import * as fs from 'fs/promises'
import * as path from 'path'
import * as readline from 'readline'
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
import {
  enumerateNodeModules,
  type EnumeratedPackage,
} from '../utils/enumerate-packages.js'
import { fuzzyMatchPackages, isPurl } from '../utils/fuzzy-match.js'

/**
 * Represents a package that has available patches with CVE information
 */
interface PackageWithPatchInfo extends EnumeratedPackage {
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
 * Parse a PURL to extract the package directory path and version
 * @example parsePurl('pkg:npm/lodash@4.17.21') => { packageDir: 'lodash', version: '4.17.21' }
 * @example parsePurl('pkg:npm/@types/node@20.0.0') => { packageDir: '@types/node', version: '20.0.0' }
 */
function parsePurl(purl: string): { packageDir: string; version: string } | null {
  const match = purl.match(/^pkg:npm\/(.+)@([^@]+)$/)
  if (!match) return null
  return { packageDir: match[1], version: match[2] }
}

/**
 * Check which PURLs from search results are actually installed in node_modules.
 * This is O(n) where n = number of unique packages in search results,
 * NOT O(m) where m = total packages in node_modules.
 */
async function findInstalledPurls(
  cwd: string,
  purls: string[],
): Promise<Set<string>> {
  const nodeModulesPath = path.join(cwd, 'node_modules')
  const installedPurls = new Set<string>()

  // Group PURLs by package directory to handle multiple versions of same package
  const packageVersions = new Map<string, Set<string>>()
  const purlLookup = new Map<string, string>() // "packageDir@version" -> original purl

  for (const purl of purls) {
    const parsed = parsePurl(purl)
    if (!parsed) continue

    if (!packageVersions.has(parsed.packageDir)) {
      packageVersions.set(parsed.packageDir, new Set())
    }
    packageVersions.get(parsed.packageDir)!.add(parsed.version)
    purlLookup.set(`${parsed.packageDir}@${parsed.version}`, purl)
  }

  // Check only the specific packages we need - O(n) filesystem operations
  for (const [packageDir, versions] of packageVersions) {
    const pkgJsonPath = path.join(nodeModulesPath, packageDir, 'package.json')
    try {
      const content = await fs.readFile(pkgJsonPath, 'utf-8')
      const pkg = JSON.parse(content)
      if (pkg.version && versions.has(pkg.version)) {
        const key = `${packageDir}@${pkg.version}`
        const originalPurl = purlLookup.get(key)
        if (originalPurl) {
          installedPurls.add(originalPurl)
        }
      }
    } catch {
      // Package not found or invalid package.json - skip
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
  packages: EnumeratedPackage[],
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

      // Filter to only accessible patches
      const accessiblePatches = patches.filter(
        patch => patch.tier === 'free' || canAccessPaidPatches,
      )

      if (accessiblePatches.length === 0) {
        continue
      }

      // Extract CVE and GHSA IDs from patches
      const cveIds = new Set<string>()
      const ghsaIds = new Set<string>()

      for (const patch of accessiblePatches) {
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
        patches: accessiblePatches,
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

interface DownloadArgs {
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

    console.log(`  ${i + 1}. ${displayName}@${pkg.version}`)
    console.log(`     Patches: ${pkg.patches.length} | Severity: ${severityList.join(', ')}`)
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

  // Save blob contents
  const files: Record<string, { beforeHash?: string; afterHash?: string }> = {}
  for (const [filePath, fileInfo] of Object.entries(patch.files)) {
    if (fileInfo.afterHash) {
      files[filePath] = {
        beforeHash: fileInfo.beforeHash,
        afterHash: fileInfo.afterHash,
      }
    }

    // Save after blob content if provided
    if (fileInfo.blobContent && fileInfo.afterHash) {
      const blobPath = path.join(blobsDir, fileInfo.afterHash)
      const blobBuffer = Buffer.from(fileInfo.blobContent, 'base64')
      await fs.writeFile(blobPath, blobBuffer)
    }

    // Save before blob content if provided (for rollback support)
    if (fileInfo.beforeBlobContent && fileInfo.beforeHash) {
      const blobPath = path.join(blobsDir, fileInfo.beforeHash)
      const blobBuffer = Buffer.from(fileInfo.beforeBlobContent, 'base64')
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

async function downloadPatches(args: DownloadArgs): Promise<boolean> {
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
      // Enumerate packages from node_modules and fuzzy match
      console.log(`Enumerating packages in ${cwd}...`)
      const packages = await enumerateNodeModules(cwd)

      if (packages.length === 0) {
        console.log('No packages found in node_modules. Run npm/yarn/pnpm install first.')
        return true
      }

      console.log(`Found ${packages.length} packages in node_modules`)

      // Fuzzy match against the identifier
      let matches = fuzzyMatchPackages(identifier, packages)

      if (matches.length === 0) {
        console.log(`No packages matching "${identifier}" found in node_modules.`)
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
    const installedPurls = await findInstalledPurls(cwd, searchPurls)

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

  if (inaccessibleCount > 0) {
    console.log(
      `Note: ${inaccessibleCount} patch(es) require paid access and will be skipped.`,
    )
  }

  if (accessiblePatches.length === 0) {
    console.log(
      'No accessible patches available. Upgrade to access paid patches.',
    )
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

  return true
}

export const downloadCommand: CommandModule<{}, DownloadArgs> = {
  command: 'download <identifier>',
  describe: 'Download security patches from Socket API',
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
      .example(
        '$0 download CVE-2021-44228',
        'Download free patches for a CVE (no auth required)',
      )
      .example(
        '$0 download GHSA-jfhm-5ghh-2f97',
        'Download free patches for a GHSA (no auth required)',
      )
      .example(
        '$0 download pkg:npm/lodash@4.17.21',
        'Download patches for a specific package version by PURL',
      )
      .example(
        '$0 download lodash --package',
        'Search for patches by package name (fuzzy matches node_modules)',
      )
      .example(
        '$0 download 12345678-1234-1234-1234-123456789abc --org myorg',
        'Download a patch by UUID (requires SOCKET_API_TOKEN)',
      )
      .example(
        '$0 download CVE-2021-44228 --org myorg --yes',
        'Download all matching patches without confirmation (with auth)',
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
        return true
      })
  },
  handler: async argv => {
    try {
      const success = await downloadPatches(argv)
      process.exit(success ? 0 : 1)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      console.error(`Error: ${errorMessage}`)
      process.exit(1)
    }
  },
}

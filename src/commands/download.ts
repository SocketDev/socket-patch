import * as fs from 'fs/promises'
import * as path from 'path'
import * as readline from 'readline'
import type { CommandModule } from 'yargs'
import { PatchManifestSchema } from '../schema/manifest-schema.js'
import {
  getAPIClientFromEnv,
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

// Identifier type patterns
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const CVE_PATTERN = /^CVE-\d{4}-\d+$/i
const GHSA_PATTERN = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i

type IdentifierType = 'uuid' | 'cve' | 'ghsa' | 'purl' | 'package'

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
 * Display enumerated packages and prompt user to select one
 */
async function promptSelectPackage(
  packages: EnumeratedPackage[],
): Promise<EnumeratedPackage | null> {
  console.log('\nMatching packages found:\n')

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i]
    const displayName = pkg.namespace
      ? `${pkg.namespace}/${pkg.name}`
      : pkg.name
    console.log(`  ${i + 1}. ${displayName}@${pkg.version}`)
    console.log(`     PURL: ${pkg.purl}`)
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

    // Save blob content if provided
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
      const matches = fuzzyMatchPackages(identifier, packages)

      if (matches.length === 0) {
        console.log(`No packages matching "${identifier}" found in node_modules.`)
        return true
      }

      let selectedPackage: EnumeratedPackage

      if (matches.length === 1) {
        // Single match, use it directly
        selectedPackage = matches[0]
        console.log(`Found exact match: ${selectedPackage.purl}`)
      } else {
        // Multiple matches, prompt user to select
        if (skipConfirmation) {
          // With --yes, use the best match (first result)
          selectedPackage = matches[0]
          console.log(`Using best match: ${selectedPackage.purl}`)
        } else {
          const selected = await promptSelectPackage(matches)
          if (!selected) {
            console.log('No package selected. Download cancelled.')
            return true
          }
          selectedPackage = selected
        }
      }

      // Search for patches using the selected package's PURL
      console.log(`Searching patches for package: ${selectedPackage.purl}`)
      searchResponse = await apiClient.searchPatchesByPackage(
        effectiveOrgSlug,
        selectedPackage.purl,
      )
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

  // Filter patches based on tier access
  const accessiblePatches = searchResults.filter(
    patch => patch.tier === 'free' || canAccessPaidPatches,
  )
  const inaccessibleCount = searchResults.length - accessiblePatches.length

  // Display search results
  displaySearchResults(searchResults, canAccessPaidPatches)

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

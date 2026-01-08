import type { CommandModule } from 'yargs'
import {
  getAPIClientFromEnv,
  type BatchPackagePatches,
} from '../utils/api-client.js'
import { NpmCrawler } from '../crawlers/index.js'
import { createSpinner } from '../utils/spinner.js'

// Default batch size for API queries
const DEFAULT_BATCH_SIZE = 100

// Severity order for sorting (most severe first)
const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
}

interface ScanArgs {
  cwd: string
  org?: string
  json?: boolean
  global?: boolean
  'global-prefix'?: string
  'batch-size'?: number
  'api-url'?: string
  'api-token'?: string
}

/**
 * Result structure for JSON output
 */
interface ScanResult {
  scannedPackages: number
  packagesWithPatches: number
  totalPatches: number
  freePatches: number
  paidPatches: number
  canAccessPaidPatches: boolean
  packages: Array<{
    purl: string
    patches: Array<{
      uuid: string
      purl: string
      tier: 'free' | 'paid'
      cveIds: string[]
      ghsaIds: string[]
      severity: string | null
      title: string
    }>
  }>
}

/**
 * Format severity with color codes for terminal output
 */
function formatSeverity(severity: string | null): string {
  if (!severity) return 'unknown'
  const s = severity.toLowerCase()
  switch (s) {
    case 'critical':
      return '\x1b[31mcritical\x1b[0m' // red
    case 'high':
      return '\x1b[91mhigh\x1b[0m' // bright red
    case 'medium':
      return '\x1b[33mmedium\x1b[0m' // yellow
    case 'low':
      return '\x1b[36mlow\x1b[0m' // cyan
    default:
      return s
  }
}

/**
 * Get numeric severity for sorting
 */
function getSeverityOrder(severity: string | null): number {
  if (!severity) return 4
  return SEVERITY_ORDER[severity.toLowerCase()] ?? 4
}

/**
 * Format a table row for console output
 */
function formatTableRow(
  purl: string,
  freeCount: number,
  paidCount: number,
  severity: string | null,
  cveIds: string[],
  ghsaIds: string[],
  canAccessPaidPatches: boolean,
): string {
  // Truncate PURL if too long
  const maxPurlLen = 40
  const displayPurl =
    purl.length > maxPurlLen ? purl.slice(0, maxPurlLen - 3) + '...' : purl

  // Format patch counts
  let countStr = String(freeCount)
  if (paidCount > 0) {
    if (canAccessPaidPatches) {
      countStr += `+${paidCount}`
    } else {
      countStr += `\x1b[33m+${paidCount}\x1b[0m` // yellow for locked paid patches
    }
  }

  // Format vulnerability IDs
  const vulnIds = [...cveIds, ...ghsaIds]
  const maxVulnLen = 30
  let vulnStr =
    vulnIds.length > 0
      ? vulnIds.slice(0, 2).join(', ')
      : '-'
  if (vulnIds.length > 2) {
    vulnStr += ` (+${vulnIds.length - 2})`
  }
  if (vulnStr.length > maxVulnLen) {
    vulnStr = vulnStr.slice(0, maxVulnLen - 3) + '...'
  }

  return `${displayPurl.padEnd(maxPurlLen)}  ${countStr.padStart(8)}  ${formatSeverity(severity).padEnd(16)}  ${vulnStr}`
}

/**
 * Scan installed packages for available patches
 */
async function scanPatches(args: ScanArgs): Promise<boolean> {
  const {
    cwd,
    org: orgSlug,
    json: outputJson,
    global: useGlobal,
    'global-prefix': globalPrefix,
    'batch-size': batchSize = DEFAULT_BATCH_SIZE,
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

  // Initialize crawler and spinner
  const crawler = new NpmCrawler()
  const spinner = createSpinner({ disabled: outputJson })

  const scanTarget = useGlobal || globalPrefix
    ? 'global npm packages'
    : 'npm packages'

  spinner.start(`Scanning ${scanTarget}...`)

  // Collect all packages using batching to be memory-efficient
  const allPurls: string[] = []
  let packageCount = 0
  let lastPath = ''

  for await (const batch of crawler.crawlBatches({
    cwd,
    global: useGlobal,
    globalPrefix,
    batchSize,
  })) {
    for (const pkg of batch) {
      allPurls.push(pkg.purl)
      packageCount++
      lastPath = pkg.path
    }

    // Update spinner with progress - show last package scanned and its relative path
    // Compute relative path from cwd
    const relativePath = lastPath.startsWith(cwd)
      ? lastPath.slice(cwd.length + 1) // +1 to remove leading slash
      : lastPath
    spinner.update(`Scanning... ${packageCount} pkgs | ${relativePath}`)
  }

  if (packageCount === 0) {
    spinner.stop()
    if (outputJson) {
      console.log(
        JSON.stringify(
          {
            scannedPackages: 0,
            packagesWithPatches: 0,
            totalPatches: 0,
            freePatches: 0,
            paidPatches: 0,
            canAccessPaidPatches: false,
            packages: [],
          } satisfies ScanResult,
          null,
          2,
        ),
      )
    } else {
      console.log(
        useGlobal || globalPrefix
          ? 'No global npm packages found.'
          : 'No packages found. Run npm/yarn/pnpm install first.',
      )
    }
    return true
  }

  spinner.succeed(`Found ${packageCount} packages`)

  // Query API in batches
  const allPackagesWithPatches: BatchPackagePatches[] = []
  let canAccessPaidPatches = false
  let batchIndex = 0
  const totalBatches = Math.ceil(allPurls.length / batchSize)
  let totalPatchesFound = 0

  spinner.start(`Querying API for patches... (batch 1/${totalBatches})`)

  for (let i = 0; i < allPurls.length; i += batchSize) {
    batchIndex++
    const batch = allPurls.slice(i, i + batchSize)

    // Show progress with batch number and patches found so far
    const patchInfo = totalPatchesFound > 0 ? `, ${totalPatchesFound} patches found` : ''
    spinner.update(`Querying API for patches... (batch ${batchIndex}/${totalBatches}${patchInfo})`)

    try {
      const response = await apiClient.searchPatchesBatch(effectiveOrgSlug, batch)

      // Merge results
      if (response.canAccessPaidPatches) {
        canAccessPaidPatches = true
      }

      // Include ALL patches (free and paid) - we'll show paid as upgrade options
      for (const pkg of response.packages) {
        if (pkg.patches.length > 0) {
          allPackagesWithPatches.push({
            purl: pkg.purl,
            patches: pkg.patches,
          })
          totalPatchesFound += pkg.patches.length
        }
      }
    } catch (error) {
      spinner.stop()
      if (!outputJson) {
        console.error(
          `Error querying batch ${batchIndex}: ${error instanceof Error ? error.message : String(error)}`,
        )
      }
      // Restart spinner and continue with other batches
      if (batchIndex < totalBatches) {
        spinner.start(`Querying API for patches... (batch ${batchIndex + 1}/${totalBatches})`)
      }
    }
  }

  if (totalPatchesFound > 0) {
    spinner.succeed(`Found ${totalPatchesFound} patches for ${allPackagesWithPatches.length} packages`)
  } else {
    spinner.succeed('API query complete')
  }

  // Calculate patch counts by tier
  let freePatches = 0
  let paidPatches = 0
  for (const pkg of allPackagesWithPatches) {
    for (const patch of pkg.patches) {
      if (patch.tier === 'free') {
        freePatches++
      } else {
        paidPatches++
      }
    }
  }
  const totalPatches = freePatches + paidPatches

  // Prepare result
  const result: ScanResult = {
    scannedPackages: packageCount,
    packagesWithPatches: allPackagesWithPatches.length,
    totalPatches,
    freePatches,
    paidPatches,
    canAccessPaidPatches,
    packages: allPackagesWithPatches,
  }

  if (outputJson) {
    console.log(JSON.stringify(result, null, 2))
    return true
  }

  // Console table output
  if (allPackagesWithPatches.length === 0) {
    console.log('\nNo patches available for installed packages.')
    return true
  }

  // Sort packages by highest severity
  const sortedPackages = allPackagesWithPatches.sort((a, b) => {
    const aMaxSeverity = Math.min(
      ...a.patches.map(p => getSeverityOrder(p.severity)),
    )
    const bMaxSeverity = Math.min(
      ...b.patches.map(p => getSeverityOrder(p.severity)),
    )
    return aMaxSeverity - bMaxSeverity
  })

  // Print table header
  console.log('\n' + '='.repeat(100))
  console.log('PACKAGE'.padEnd(40) + '  ' + 'PATCHES'.padStart(8) + '  ' + 'SEVERITY'.padEnd(16) + '  VULNERABILITIES')
  console.log('='.repeat(100))

  // Print each package
  for (const pkg of sortedPackages) {
    // Get highest severity among all patches
    const highestSeverity = pkg.patches.reduce<string | null>((acc, patch) => {
      if (!acc) return patch.severity
      if (!patch.severity) return acc
      return getSeverityOrder(patch.severity) < getSeverityOrder(acc)
        ? patch.severity
        : acc
    }, null)

    // Count free vs paid patches for this package
    const pkgFreeCount = pkg.patches.filter(p => p.tier === 'free').length
    const pkgPaidCount = pkg.patches.filter(p => p.tier === 'paid').length

    // Collect all CVE/GHSA IDs
    const allCveIds = new Set<string>()
    const allGhsaIds = new Set<string>()
    for (const patch of pkg.patches) {
      for (const cve of patch.cveIds) allCveIds.add(cve)
      for (const ghsa of patch.ghsaIds) allGhsaIds.add(ghsa)
    }

    console.log(
      formatTableRow(
        pkg.purl,
        pkgFreeCount,
        pkgPaidCount,
        highestSeverity,
        Array.from(allCveIds),
        Array.from(allGhsaIds),
        canAccessPaidPatches,
      ),
    )
  }

  console.log('='.repeat(100))

  // Summary with breakdown
  if (canAccessPaidPatches) {
    console.log(
      `\nSummary: ${allPackagesWithPatches.length} package(s) with ${totalPatches} available patch(es)`,
    )
  } else {
    console.log(
      `\nSummary: ${allPackagesWithPatches.length} package(s) with ${freePatches} free patch(es)`,
    )
    if (paidPatches > 0) {
      console.log(
        `\x1b[33m         + ${paidPatches} additional patch(es) available with paid subscription\x1b[0m`,
      )
      console.log(
        '\nUpgrade to Socket\'s paid plan to access all patches: https://socket.dev/pricing',
      )
    }
  }

  console.log('\nTo apply a patch, run:')
  console.log('  socket-patch get <package-name-or-purl>')
  console.log('  socket-patch get <CVE-ID>')

  return true
}

export const scanCommand: CommandModule<{}, ScanArgs> = {
  command: 'scan',
  describe: 'Scan installed packages for available security patches',
  builder: yargs => {
    return yargs
      .option('cwd', {
        describe: 'Working directory',
        type: 'string',
        default: process.cwd(),
      })
      .option('org', {
        describe: 'Organization slug (required when using SOCKET_API_TOKEN, optional for public proxy)',
        type: 'string',
        demandOption: false,
      })
      .option('json', {
        describe: 'Output results as JSON',
        type: 'boolean',
        default: false,
      })
      .option('global', {
        alias: 'g',
        describe: 'Scan globally installed npm packages',
        type: 'boolean',
        default: false,
      })
      .option('global-prefix', {
        describe: 'Custom path to global node_modules (overrides auto-detection)',
        type: 'string',
      })
      .option('batch-size', {
        describe: 'Number of packages to query per API request',
        type: 'number',
        default: DEFAULT_BATCH_SIZE,
      })
      .option('api-url', {
        describe: 'Socket API URL (overrides SOCKET_API_URL env var)',
        type: 'string',
      })
      .option('api-token', {
        describe: 'Socket API token (overrides SOCKET_API_TOKEN env var)',
        type: 'string',
      })
      .example('$0 scan', 'Scan local node_modules for available patches')
      .example('$0 scan --json', 'Output scan results as JSON')
      .example('$0 scan --global', 'Scan globally installed packages')
      .example(
        '$0 scan --batch-size 200',
        'Use larger batches for faster scanning',
      )
  },
  handler: async argv => {
    try {
      const success = await scanPatches(argv)
      process.exit(success ? 0 : 1)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      console.error(`Error: ${errorMessage}`)
      process.exit(1)
    }
  },
}

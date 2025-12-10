import type { EnumeratedPackage } from './enumerate-packages.js'

/**
 * Match type for sorting results
 */
enum MatchType {
  /** Exact match on full name (including namespace) */
  ExactFull = 0,
  /** Exact match on package name only */
  ExactName = 1,
  /** Query is a prefix of the full name */
  PrefixFull = 2,
  /** Query is a prefix of the package name */
  PrefixName = 3,
  /** Query is contained in the full name */
  ContainsFull = 4,
  /** Query is contained in the package name */
  ContainsName = 5,
}

interface MatchResult {
  package: EnumeratedPackage
  matchType: MatchType
}

/**
 * Get the full display name for a package (including namespace if present)
 */
function getFullName(pkg: EnumeratedPackage): string {
  if (pkg.namespace) {
    return `${pkg.namespace}/${pkg.name}`
  }
  return pkg.name
}

/**
 * Determine the match type for a package against a query
 */
function getMatchType(
  pkg: EnumeratedPackage,
  query: string,
): MatchType | null {
  const lowerQuery = query.toLowerCase()
  const fullName = getFullName(pkg).toLowerCase()
  const name = pkg.name.toLowerCase()

  // Check exact matches
  if (fullName === lowerQuery) {
    return MatchType.ExactFull
  }
  if (name === lowerQuery) {
    return MatchType.ExactName
  }

  // Check prefix matches
  if (fullName.startsWith(lowerQuery)) {
    return MatchType.PrefixFull
  }
  if (name.startsWith(lowerQuery)) {
    return MatchType.PrefixName
  }

  // Check contains matches
  if (fullName.includes(lowerQuery)) {
    return MatchType.ContainsFull
  }
  if (name.includes(lowerQuery)) {
    return MatchType.ContainsName
  }

  return null
}

/**
 * Fuzzy match packages against a query string
 *
 * Matches are sorted by relevance:
 * 1. Exact match on full name (e.g., "@types/node" matches "@types/node")
 * 2. Exact match on package name (e.g., "node" matches "@types/node")
 * 3. Prefix match on full name
 * 4. Prefix match on package name
 * 5. Contains match on full name
 * 6. Contains match on package name
 *
 * @param query - Search query string
 * @param packages - List of packages to search
 * @param limit - Maximum number of results to return (default: 20)
 * @returns Sorted list of matching packages
 */
export function fuzzyMatchPackages(
  query: string,
  packages: EnumeratedPackage[],
  limit: number = 20,
): EnumeratedPackage[] {
  if (!query || query.trim().length === 0) {
    return []
  }

  const matches: MatchResult[] = []

  for (const pkg of packages) {
    const matchType = getMatchType(pkg, query)
    if (matchType !== null) {
      matches.push({ package: pkg, matchType })
    }
  }

  // Sort by match type (lower is better), then alphabetically by name
  matches.sort((a, b) => {
    if (a.matchType !== b.matchType) {
      return a.matchType - b.matchType
    }
    return getFullName(a.package).localeCompare(getFullName(b.package))
  })

  // Return only the packages, limited to the specified count
  return matches.slice(0, limit).map(m => m.package)
}

/**
 * Check if a string looks like a PURL
 */
export function isPurl(str: string): boolean {
  return str.startsWith('pkg:')
}

/**
 * Check if a string looks like a scoped package name
 */
export function isScopedPackage(str: string): boolean {
  return str.startsWith('@') && str.includes('/')
}

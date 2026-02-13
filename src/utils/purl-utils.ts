/**
 * Strip query string qualifiers from a PURL.
 * e.g., "pkg:pypi/requests@2.28.0?artifact_id=abc" -> "pkg:pypi/requests@2.28.0"
 */
export function stripPurlQualifiers(purl: string): string {
  const qIdx = purl.indexOf('?')
  return qIdx === -1 ? purl : purl.slice(0, qIdx)
}

/**
 * Check if a PURL is a PyPI package.
 */
export function isPyPIPurl(purl: string): boolean {
  return purl.startsWith('pkg:pypi/')
}

/**
 * Check if a PURL is an npm package.
 */
export function isNpmPurl(purl: string): boolean {
  return purl.startsWith('pkg:npm/')
}

/**
 * Parse a PyPI PURL to extract name and version.
 * e.g., "pkg:pypi/requests@2.28.0?artifact_id=abc" -> { name: "requests", version: "2.28.0" }
 */
export function parsePyPIPurl(
  purl: string,
): { name: string; version: string } | null {
  const base = stripPurlQualifiers(purl)
  const match = base.match(/^pkg:pypi\/([^@]+)@(.+)$/)
  if (!match) return null
  return { name: match[1], version: match[2] }
}

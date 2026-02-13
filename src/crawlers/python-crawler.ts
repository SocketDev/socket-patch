import * as fs from 'fs/promises'
import * as path from 'path'
import { execSync } from 'child_process'
import type { CrawledPackage, CrawlerOptions } from './types.js'

const DEFAULT_BATCH_SIZE = 100

/**
 * Canonicalize a Python package name per PEP 503.
 * Lowercases, trims, and replaces runs of [-_.] with a single '-'.
 */
export function canonicalizePyPIName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replaceAll(/[-_.]+/gi, '-')
}

/**
 * Read Name and Version from a dist-info METADATA file.
 */
async function readPythonMetadata(
  distInfoPath: string,
): Promise<{ name: string; version: string } | null> {
  try {
    const metadataPath = path.join(distInfoPath, 'METADATA')
    const content = await fs.readFile(metadataPath, 'utf-8')

    let name: string | undefined
    let version: string | undefined

    for (const line of content.split('\n')) {
      if (name && version) break
      if (line.startsWith('Name:')) {
        name = line.slice('Name:'.length).trim()
      } else if (line.startsWith('Version:')) {
        version = line.slice('Version:'.length).trim()
      }
      // Stop at first empty line (end of headers)
      if (line.trim() === '' && (name || version)) break
    }

    if (name && version) {
      return { name, version }
    }
    return null
  } catch {
    return null
  }
}

/**
 * Find directories matching a pattern with a single `python3.*` wildcard segment.
 * E.g., given "/path/to/lib/python3.*\/site-packages", find all matching paths.
 * This replaces the glob dependency.
 */
export async function findPythonDirs(basePath: string, ...segments: string[]): Promise<string[]> {
  const results: string[] = []

  try {
    const stat = await fs.stat(basePath)
    if (!stat.isDirectory()) return results
  } catch {
    return results
  }

  if (segments.length === 0) {
    results.push(basePath)
    return results
  }

  const [first, ...rest] = segments

  if (first === 'python3.*') {
    // Wildcard segment: list directory and match python3.X entries
    try {
      const entries = await fs.readdir(basePath, { withFileTypes: true })
      for (const entry of entries) {
        if (entry.isDirectory() && entry.name.startsWith('python3.')) {
          const subResults = await findPythonDirs(
            path.join(basePath, entry.name),
            ...rest,
          )
          results.push(...subResults)
        }
      }
    } catch {
      // directory not readable
    }
  } else if (first === '*') {
    // Generic wildcard: match any directory entry
    try {
      const entries = await fs.readdir(basePath, { withFileTypes: true })
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const subResults = await findPythonDirs(
            path.join(basePath, entry.name),
            ...rest,
          )
          results.push(...subResults)
        }
      }
    } catch {
      // directory not readable
    }
  } else {
    // Literal segment: just check if it exists
    const subResults = await findPythonDirs(
      path.join(basePath, first),
      ...rest,
    )
    results.push(...subResults)
  }

  return results
}

/**
 * Find site-packages directories under a given lib directory using python version wildcard.
 * Handles both Unix (lib/python3.X/site-packages) and Windows (Lib/site-packages) layouts.
 */
async function findSitePackagesUnder(
  baseDir: string,
  subDirType: 'dist-packages' | 'site-packages' = 'site-packages',
): Promise<string[]> {
  if (process.platform === 'win32') {
    return findPythonDirs(baseDir, 'Lib', subDirType)
  }
  return findPythonDirs(baseDir, 'lib', 'python3.*', subDirType)
}

/**
 * Find local virtual environment site-packages directories.
 */
export async function findLocalVenvSitePackages(cwd: string): Promise<string[]> {
  const results: string[] = []

  // 1. Check VIRTUAL_ENV env var
  const virtualEnv = process.env['VIRTUAL_ENV']
  if (virtualEnv) {
    const matches = await findSitePackagesUnder(virtualEnv)
    results.push(...matches)
    if (results.length > 0) return results
  }

  // 2. Check .venv and venv in cwd
  for (const venvDir of ['.venv', 'venv']) {
    const venvPath = path.join(cwd, venvDir)
    const matches = await findSitePackagesUnder(venvPath)
    results.push(...matches)
  }

  return results
}

/**
 * Get global/system Python site-packages directories.
 */
async function getGlobalPythonSitePackages(): Promise<string[]> {
  const results: string[] = []
  const seen = new Set<string>()

  function addPath(p: string): void {
    const resolved = path.resolve(p)
    if (!seen.has(resolved)) {
      seen.add(resolved)
      results.push(resolved)
    }
  }

  // 1. Ask Python for site-packages
  try {
    const output = execSync(
      'python3 -c "import site; print(\'\\n\'.join(site.getsitepackages())); print(site.getusersitepackages())"',
      {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    )
    for (const line of output.trim().split('\n')) {
      const p = line.trim()
      if (p) addPath(p)
    }
  } catch {
    // python3 not available
  }

  // 2. Well-known system paths
  const homeDir = process.env['HOME'] ?? '~'

  // Helper to scan a base/lib/python3.*/[dist|site]-packages pattern
  async function scanWellKnown(base: string, pkgType: 'dist-packages' | 'site-packages'): Promise<void> {
    const matches = await findPythonDirs(base, 'lib', 'python3.*', pkgType)
    for (const m of matches) addPath(m)
  }

  // Debian/Ubuntu
  await scanWellKnown('/usr', 'dist-packages')
  await scanWellKnown('/usr', 'site-packages')
  // Debian pip / most distros / macOS
  await scanWellKnown('/usr/local', 'dist-packages')
  await scanWellKnown('/usr/local', 'site-packages')
  // pip --user
  await scanWellKnown(`${homeDir}/.local`, 'site-packages')

  // macOS-specific
  if (process.platform === 'darwin') {
    await scanWellKnown('/opt/homebrew', 'site-packages')
    // Python.org framework: /Library/Frameworks/Python.framework/Versions/3.*/lib/python3.*/site-packages
    const fwMatches = await findPythonDirs(
      '/Library/Frameworks/Python.framework/Versions',
      'python3.*',
      'lib',
      'python3.*',
      'site-packages',
    )
    for (const m of fwMatches) addPath(m)
    // Also try just 3.* version dirs
    const fwMatches2 = await findPythonDirs(
      '/Library/Frameworks/Python.framework',
      'Versions',
      '*',
      'lib',
      'python3.*',
      'site-packages',
    )
    for (const m of fwMatches2) addPath(m)
  }

  // Conda
  await scanWellKnown(`${homeDir}/anaconda3`, 'site-packages')
  await scanWellKnown(`${homeDir}/miniconda3`, 'site-packages')

  // uv tools
  if (process.platform === 'darwin') {
    const uvMatches = await findPythonDirs(
      `${homeDir}/Library/Application Support/uv/tools`,
      '*',
      'lib',
      'python3.*',
      'site-packages',
    )
    for (const m of uvMatches) addPath(m)
  } else {
    const uvMatches = await findPythonDirs(
      `${homeDir}/.local/share/uv/tools`,
      '*',
      'lib',
      'python3.*',
      'site-packages',
    )
    for (const m of uvMatches) addPath(m)
  }

  return results
}

/**
 * Python ecosystem crawler for discovering packages in site-packages
 */
export class PythonCrawler {
  /**
   * Get site-packages paths based on options
   */
  async getSitePackagesPaths(options: CrawlerOptions): Promise<string[]> {
    if (options.global || options.globalPrefix) {
      if (options.globalPrefix) {
        return [options.globalPrefix]
      }
      return getGlobalPythonSitePackages()
    }
    return findLocalVenvSitePackages(options.cwd)
  }

  /**
   * Yield packages in batches (memory efficient for large codebases)
   */
  async *crawlBatches(
    options: CrawlerOptions,
  ): AsyncGenerator<CrawledPackage[], void, unknown> {
    const batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE
    const seen = new Set<string>()
    let batch: CrawledPackage[] = []

    const sitePackagesPaths = await this.getSitePackagesPaths(options)

    for (const spPath of sitePackagesPaths) {
      for await (const pkg of this.scanSitePackages(spPath, seen)) {
        batch.push(pkg)
        if (batch.length >= batchSize) {
          yield batch
          batch = []
        }
      }
    }

    if (batch.length > 0) {
      yield batch
    }
  }

  /**
   * Return all packages at once (convenience method)
   */
  async crawlAll(options: CrawlerOptions): Promise<CrawledPackage[]> {
    const packages: CrawledPackage[] = []
    for await (const batch of this.crawlBatches(options)) {
      packages.push(...batch)
    }
    return packages
  }

  /**
   * Find specific packages by PURL.
   * Accepts base PURLs (no qualifiers) - caller strips qualifiers before calling.
   */
  async findByPurls(
    sitePackagesPath: string,
    purls: string[],
  ): Promise<Map<string, CrawledPackage>> {
    const result = new Map<string, CrawledPackage>()

    // Build a lookup map from canonicalized-name@version -> purl
    const purlLookup = new Map<string, string>()
    for (const purl of purls) {
      const parsed = this.parsePurl(purl)
      if (parsed) {
        const key = `${canonicalizePyPIName(parsed.name)}@${parsed.version}`
        purlLookup.set(key, purl)
      }
    }

    if (purlLookup.size === 0) return result

    // Scan all dist-info dirs once, check against requested purls
    let entries: string[]
    try {
      const allEntries = await fs.readdir(sitePackagesPath)
      entries = allEntries.filter(e => e.endsWith('.dist-info'))
    } catch {
      return result
    }

    for (const entry of entries) {
      const distInfoPath = path.join(sitePackagesPath, entry)
      const metadata = await readPythonMetadata(distInfoPath)
      if (!metadata) continue

      const canonName = canonicalizePyPIName(metadata.name)
      const key = `${canonName}@${metadata.version}`
      const matchedPurl = purlLookup.get(key)

      if (matchedPurl) {
        result.set(matchedPurl, {
          name: canonName,
          version: metadata.version,
          purl: matchedPurl,
          path: sitePackagesPath,
        })
      }
    }

    return result
  }

  /**
   * Scan a site-packages directory and yield packages
   */
  private async *scanSitePackages(
    sitePackagesPath: string,
    seen: Set<string>,
  ): AsyncGenerator<CrawledPackage, void, unknown> {
    let entries: string[]
    try {
      const allEntries = await fs.readdir(sitePackagesPath)
      entries = allEntries.filter(e => e.endsWith('.dist-info'))
    } catch {
      return
    }

    for (const entry of entries) {
      const distInfoPath = path.join(sitePackagesPath, entry)
      const metadata = await readPythonMetadata(distInfoPath)
      if (!metadata) continue

      const canonName = canonicalizePyPIName(metadata.name)
      const purl = `pkg:pypi/${canonName}@${metadata.version}`

      if (seen.has(purl)) continue
      seen.add(purl)

      yield {
        name: canonName,
        version: metadata.version,
        purl,
        path: sitePackagesPath,
      }
    }
  }

  /**
   * Parse a PyPI PURL string to extract name and version.
   * Strips qualifiers before parsing.
   */
  private parsePurl(
    purl: string,
  ): { name: string; version: string } | null {
    // Strip qualifiers
    const qIdx = purl.indexOf('?')
    const base = qIdx === -1 ? purl : purl.slice(0, qIdx)
    const match = base.match(/^pkg:pypi\/([^@]+)@(.+)$/)
    if (!match) return null
    return { name: match[1], version: match[2] }
  }
}

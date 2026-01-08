import * as fs from 'fs/promises'
import * as path from 'path'
import { execSync } from 'child_process'
import type { Dirent } from 'fs'
import type { CrawledPackage, CrawlerOptions } from './types.js'

const DEFAULT_BATCH_SIZE = 100

/**
 * Read and parse a package.json file
 */
async function readPackageJson(
  pkgPath: string,
): Promise<{ name: string; version: string } | null> {
  try {
    const content = await fs.readFile(pkgPath, 'utf-8')
    const pkg = JSON.parse(content)
    if (typeof pkg.name === 'string' && typeof pkg.version === 'string') {
      return { name: pkg.name, version: pkg.version }
    }
    return null
  } catch {
    return null
  }
}

/**
 * Parse a package name into namespace and name components
 */
function parsePackageName(fullName: string): {
  namespace?: string
  name: string
} {
  if (fullName.startsWith('@')) {
    const slashIndex = fullName.indexOf('/')
    if (slashIndex !== -1) {
      return {
        namespace: fullName.substring(0, slashIndex),
        name: fullName.substring(slashIndex + 1),
      }
    }
  }
  return { name: fullName }
}

/**
 * Build a PURL string from package components
 */
function buildPurl(
  namespace: string | undefined,
  name: string,
  version: string,
): string {
  if (namespace) {
    return `pkg:npm/${namespace}/${name}@${version}`
  }
  return `pkg:npm/${name}@${version}`
}

/**
 * Get the npm global node_modules path using 'npm root -g'
 */
function getNpmGlobalPrefix(): string {
  try {
    const result = execSync('npm root -g', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    return result.trim()
  } catch {
    throw new Error(
      'Failed to determine npm global prefix. Ensure npm is installed and in PATH.',
    )
  }
}

/**
 * Get the yarn global node_modules path
 */
function getYarnGlobalPrefix(): string | null {
  try {
    const result = execSync('yarn global dir', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    return path.join(result.trim(), 'node_modules')
  } catch {
    return null
  }
}

/**
 * Get the pnpm global node_modules path
 */
function getPnpmGlobalPrefix(): string | null {
  try {
    const result = execSync('pnpm root -g', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    return result.trim()
  } catch {
    return null
  }
}

/**
 * NPM ecosystem crawler for discovering packages in node_modules
 */
export class NpmCrawler {
  /**
   * Get node_modules paths based on options
   */
  async getNodeModulesPaths(options: CrawlerOptions): Promise<string[]> {
    if (options.global || options.globalPrefix) {
      // Global mode: return well-known global paths
      if (options.globalPrefix) {
        return [options.globalPrefix]
      }
      return this.getGlobalNodeModulesPaths()
    }

    // Local mode: find node_modules in cwd and workspace directories
    return this.findLocalNodeModulesDirs(options.cwd)
  }

  /**
   * Get well-known global node_modules paths
   * Only checks standard locations where global packages are installed
   */
  private getGlobalNodeModulesPaths(): string[] {
    const paths: string[] = []

    // Try npm global path
    try {
      paths.push(getNpmGlobalPrefix())
    } catch {
      // npm not available
    }

    // Try pnpm global path
    const pnpmPath = getPnpmGlobalPrefix()
    if (pnpmPath) {
      paths.push(pnpmPath)
    }

    // Try yarn global path
    const yarnPath = getYarnGlobalPrefix()
    if (yarnPath) {
      paths.push(yarnPath)
    }

    return paths
  }

  /**
   * Find node_modules directories within the project root.
   * Recursively searches for workspace node_modules but stays within the project.
   */
  private async findLocalNodeModulesDirs(startPath: string): Promise<string[]> {
    const results: string[] = []

    // Check for node_modules directly in startPath
    const directNodeModules = path.join(startPath, 'node_modules')
    try {
      const stat = await fs.stat(directNodeModules)
      if (stat.isDirectory()) {
        results.push(directNodeModules)
      }
    } catch {
      // No direct node_modules
    }

    // Recursively search for workspace node_modules
    await this.findWorkspaceNodeModules(startPath, startPath, results)

    return results
  }

  /**
   * Recursively find node_modules in subdirectories (for monorepos/workspaces).
   * Stays within the project by not crossing into other projects or system directories.
   * Skips symlinks to avoid duplicates and potential infinite loops.
   */
  private async findWorkspaceNodeModules(
    dir: string,
    rootPath: string,
    results: string[],
  ): Promise<void> {
    let entries
    try {
      entries = await fs.readdir(dir, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      // Skip non-directories and symlinks (avoid duplicates and infinite loops)
      if (!entry.isDirectory()) continue

      const fullPath = path.join(dir, entry.name)

      // Skip node_modules - we handle these separately when found
      if (entry.name === 'node_modules') continue

      // Skip hidden directories
      if (entry.name.startsWith('.')) continue

      // Skip common build/output directories that won't have workspace node_modules
      if (
        entry.name === 'dist' ||
        entry.name === 'build' ||
        entry.name === 'coverage' ||
        entry.name === 'tmp' ||
        entry.name === 'temp' ||
        entry.name === '__pycache__' ||
        entry.name === 'vendor'
      ) {
        continue
      }

      // Check if this subdirectory has its own node_modules
      const subNodeModules = path.join(fullPath, 'node_modules')
      try {
        const stat = await fs.stat(subNodeModules)
        if (stat.isDirectory()) {
          results.push(subNodeModules)
        }
      } catch {
        // No node_modules here
      }

      // Recurse into subdirectory
      await this.findWorkspaceNodeModules(fullPath, rootPath, results)
    }
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

    const nodeModulesPaths = await this.getNodeModulesPaths(options)

    for (const nodeModulesPath of nodeModulesPaths) {
      for await (const pkg of this.scanNodeModules(nodeModulesPath, seen)) {
        batch.push(pkg)
        if (batch.length >= batchSize) {
          yield batch
          batch = []
        }
      }
    }

    // Yield remaining packages
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
   * Find specific packages by PURL
   * Efficient O(n) lookup where n = number of PURLs to find
   */
  async findByPurls(
    nodeModulesPath: string,
    purls: string[],
  ): Promise<Map<string, CrawledPackage>> {
    const result = new Map<string, CrawledPackage>()

    // Parse PURLs to extract package info for targeted lookup
    const purlSet = new Set(purls)
    const packageTargets = new Map<
      string,
      { namespace?: string; name: string; version: string; purl: string }
    >()

    for (const purl of purls) {
      const parsed = this.parsePurl(purl)
      if (parsed) {
        // Key by directory path pattern: @scope/name or name
        const dirKey = parsed.namespace
          ? `${parsed.namespace}/${parsed.name}`
          : parsed.name
        packageTargets.set(dirKey, { ...parsed, purl })
      }
    }

    // Check each target package directory directly
    for (const [dirKey, target] of packageTargets) {
      const pkgPath = path.join(nodeModulesPath, dirKey)
      const pkgJsonPath = path.join(pkgPath, 'package.json')

      const pkgInfo = await readPackageJson(pkgJsonPath)
      if (pkgInfo && pkgInfo.version === target.version) {
        const purl = buildPurl(target.namespace, target.name, pkgInfo.version)
        if (purlSet.has(purl)) {
          result.set(purl, {
            name: target.name,
            version: pkgInfo.version,
            namespace: target.namespace,
            purl,
            path: pkgPath,
          })
        }
      }
    }

    return result
  }

  /**
   * Scan a node_modules directory and yield packages
   */
  private async *scanNodeModules(
    nodeModulesPath: string,
    seen: Set<string>,
  ): AsyncGenerator<CrawledPackage, void, unknown> {
    let entries: Dirent[]
    try {
      entries = await fs.readdir(nodeModulesPath, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      // Skip hidden files and special directories
      if (entry.name.startsWith('.') || entry.name === 'node_modules') {
        continue
      }

      // Allow both directories and symlinks (pnpm uses symlinks)
      if (!entry.isDirectory() && !entry.isSymbolicLink()) {
        continue
      }

      const entryPath = path.join(nodeModulesPath, entry.name)

      // Handle scoped packages (@scope/package)
      if (entry.name.startsWith('@')) {
        yield* this.scanScopedPackages(entryPath, entry.name, seen)
      } else {
        // Regular package
        const pkg = await this.checkPackage(entryPath, seen)
        if (pkg) {
          yield pkg
        }

        // Check for nested node_modules only for real directories (not symlinks)
        // Symlinked packages (pnpm) have their deps managed separately
        if (entry.isDirectory()) {
          yield* this.scanNestedNodeModules(entryPath, seen)
        }
      }
    }
  }

  /**
   * Scan scoped packages directory (@scope/)
   */
  private async *scanScopedPackages(
    scopePath: string,
    _scope: string,
    seen: Set<string>,
  ): AsyncGenerator<CrawledPackage, void, unknown> {
    let scopeEntries: Dirent[]
    try {
      scopeEntries = await fs.readdir(scopePath, { withFileTypes: true })
    } catch {
      return
    }

    for (const scopeEntry of scopeEntries) {
      if (scopeEntry.name.startsWith('.')) continue

      // Allow both directories and symlinks (pnpm uses symlinks)
      if (!scopeEntry.isDirectory() && !scopeEntry.isSymbolicLink()) {
        continue
      }

      const pkgPath = path.join(scopePath, scopeEntry.name)
      const pkg = await this.checkPackage(pkgPath, seen)
      if (pkg) {
        yield pkg
      }

      // Check for nested node_modules only for real directories (not symlinks)
      if (scopeEntry.isDirectory()) {
        yield* this.scanNestedNodeModules(pkgPath, seen)
      }
    }
  }

  /**
   * Scan nested node_modules inside a package (if it exists)
   */
  private async *scanNestedNodeModules(
    pkgPath: string,
    seen: Set<string>,
  ): AsyncGenerator<CrawledPackage, void, unknown> {
    const nestedNodeModules = path.join(pkgPath, 'node_modules')
    try {
      // Try to read the directory - this checks existence and gets entries in one call
      const entries = await fs.readdir(nestedNodeModules, { withFileTypes: true })
      // If we got here, the directory exists and we have its entries
      // Yield packages from this nested node_modules
      for (const entry of entries) {
        if (entry.name.startsWith('.') || entry.name === 'node_modules') {
          continue
        }
        if (!entry.isDirectory() && !entry.isSymbolicLink()) {
          continue
        }

        const entryPath = path.join(nestedNodeModules, entry.name)

        if (entry.name.startsWith('@')) {
          yield* this.scanScopedPackages(entryPath, entry.name, seen)
        } else {
          const pkg = await this.checkPackage(entryPath, seen)
          if (pkg) {
            yield pkg
          }
          // Recursively check for deeper nested node_modules
          yield* this.scanNestedNodeModules(entryPath, seen)
        }
      }
    } catch {
      // No nested node_modules or can't read it - this is the common case
    }
  }

  /**
   * Check a package directory and return CrawledPackage if valid
   */
  private async checkPackage(
    pkgPath: string,
    seen: Set<string>,
  ): Promise<CrawledPackage | null> {
    const packageJsonPath = path.join(pkgPath, 'package.json')
    const pkgInfo = await readPackageJson(packageJsonPath)

    if (!pkgInfo) {
      return null
    }

    const { namespace, name } = parsePackageName(pkgInfo.name)
    const purl = buildPurl(namespace, name, pkgInfo.version)

    // Deduplicate by PURL
    if (seen.has(purl)) {
      return null
    }
    seen.add(purl)

    return {
      name,
      version: pkgInfo.version,
      namespace,
      purl,
      path: pkgPath,
    }
  }

  /**
   * Parse a PURL string to extract components
   */
  private parsePurl(
    purl: string,
  ): { namespace?: string; name: string; version: string } | null {
    // Format: pkg:npm/name@version or pkg:npm/@scope/name@version
    const match = purl.match(/^pkg:npm\/(?:(@[^/]+)\/)?([^@]+)@(.+)$/)
    if (!match) {
      return null
    }
    return {
      namespace: match[1] || undefined,
      name: match[2],
      version: match[3],
    }
  }
}

// Re-export global prefix functions for backward compatibility
export { getNpmGlobalPrefix, getYarnGlobalPrefix, getPnpmGlobalPrefix }

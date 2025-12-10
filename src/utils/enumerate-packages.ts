import * as fs from 'fs/promises'
import * as path from 'path'

/**
 * Represents a package found in node_modules
 */
export interface EnumeratedPackage {
  /** Package name (without scope) */
  name: string
  /** Package version */
  version: string
  /** Package scope/namespace (e.g., @types) - undefined for unscoped packages */
  namespace?: string
  /** Full PURL string (e.g., pkg:npm/@types/node@20.0.0) */
  purl: string
  /** Absolute path to the package directory */
  path: string
}

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
 * @param fullName - Full package name (e.g., "@types/node" or "lodash")
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
  ecosystem: string,
  namespace: string | undefined,
  name: string,
  version: string,
): string {
  if (namespace) {
    return `pkg:${ecosystem}/${namespace}/${name}@${version}`
  }
  return `pkg:${ecosystem}/${name}@${version}`
}

/**
 * Enumerate all packages in a node_modules directory
 *
 * @param cwd - Working directory to start from
 * @param ecosystem - Package ecosystem (default: npm)
 * @returns Array of enumerated packages
 */
export async function enumerateNodeModules(
  cwd: string,
  ecosystem: string = 'npm',
): Promise<EnumeratedPackage[]> {
  const packages: EnumeratedPackage[] = []
  const seen = new Set<string>()

  const nodeModulesPath = path.join(cwd, 'node_modules')

  try {
    await fs.access(nodeModulesPath)
  } catch {
    // node_modules doesn't exist
    return packages
  }

  await scanDirectory(nodeModulesPath, packages, seen, ecosystem)

  return packages
}

/**
 * Recursively scan a directory for packages
 */
async function scanDirectory(
  dirPath: string,
  packages: EnumeratedPackage[],
  seen: Set<string>,
  ecosystem: string,
): Promise<void> {
  let entries: string[]
  try {
    entries = await fs.readdir(dirPath)
  } catch {
    return
  }

  for (const entry of entries) {
    // Skip hidden files and special directories
    if (entry.startsWith('.') || entry === 'node_modules') {
      continue
    }

    const entryPath = path.join(dirPath, entry)

    // Handle scoped packages (@scope/package)
    if (entry.startsWith('@')) {
      // This is a scope directory, scan its contents
      let scopeEntries: string[]
      try {
        scopeEntries = await fs.readdir(entryPath)
      } catch {
        continue
      }

      for (const scopeEntry of scopeEntries) {
        if (scopeEntry.startsWith('.')) continue

        const pkgPath = path.join(entryPath, scopeEntry)
        const packageJsonPath = path.join(pkgPath, 'package.json')

        const pkgInfo = await readPackageJson(packageJsonPath)
        if (pkgInfo) {
          const { namespace, name } = parsePackageName(pkgInfo.name)
          const purl = buildPurl(ecosystem, namespace, name, pkgInfo.version)

          // Deduplicate by PURL
          if (!seen.has(purl)) {
            seen.add(purl)
            packages.push({
              name,
              version: pkgInfo.version,
              namespace,
              purl,
              path: pkgPath,
            })
          }

          // Check for nested node_modules
          const nestedNodeModules = path.join(pkgPath, 'node_modules')
          try {
            await fs.access(nestedNodeModules)
            await scanDirectory(nestedNodeModules, packages, seen, ecosystem)
          } catch {
            // No nested node_modules
          }
        }
      }
    } else {
      // Regular package
      const packageJsonPath = path.join(entryPath, 'package.json')

      const pkgInfo = await readPackageJson(packageJsonPath)
      if (pkgInfo) {
        const { namespace, name } = parsePackageName(pkgInfo.name)
        const purl = buildPurl(ecosystem, namespace, name, pkgInfo.version)

        // Deduplicate by PURL
        if (!seen.has(purl)) {
          seen.add(purl)
          packages.push({
            name,
            version: pkgInfo.version,
            namespace,
            purl,
            path: entryPath,
          })
        }

        // Check for nested node_modules
        const nestedNodeModules = path.join(entryPath, 'node_modules')
        try {
          await fs.access(nestedNodeModules)
          await scanDirectory(nestedNodeModules, packages, seen, ecosystem)
        } catch {
          // No nested node_modules
        }
      }
    }
  }
}

import * as fs from 'fs/promises'
import * as path from 'path'

export interface WorkspaceConfig {
  type: 'npm' | 'yarn' | 'pnpm' | 'none'
  patterns: string[]
}

export interface PackageJsonLocation {
  path: string
  isRoot: boolean
  isWorkspace: boolean
  workspacePattern?: string
}

/**
 * Find all package.json files recursively, respecting workspace configurations
 */
export async function findPackageJsonFiles(
  startPath: string,
): Promise<PackageJsonLocation[]> {
  const results: PackageJsonLocation[] = []
  const rootPackageJsonPath = path.join(startPath, 'package.json')

  // Check if root package.json exists
  let rootExists = false
  let workspaceConfig: WorkspaceConfig = { type: 'none', patterns: [] }

  try {
    await fs.access(rootPackageJsonPath)
    rootExists = true

    // Detect workspace configuration
    workspaceConfig = await detectWorkspaces(rootPackageJsonPath)

    // Add root package.json
    results.push({
      path: rootPackageJsonPath,
      isRoot: true,
      isWorkspace: false,
    })
  } catch {
    // No root package.json
  }

  // If workspaces are configured, find all workspace package.json files
  if (workspaceConfig.type !== 'none') {
    const workspacePackages = await findWorkspacePackages(
      startPath,
      workspaceConfig,
    )
    results.push(...workspacePackages)
  } else if (rootExists) {
    // No workspaces, just search for nested package.json files
    const nestedPackages = await findNestedPackageJsonFiles(startPath)
    results.push(...nestedPackages)
  }

  return results
}

/**
 * Detect workspace configuration from package.json
 */
export async function detectWorkspaces(
  packageJsonPath: string,
): Promise<WorkspaceConfig> {
  try {
    const content = await fs.readFile(packageJsonPath, 'utf-8')
    const packageJson = JSON.parse(content)

    // Check for npm/yarn workspaces
    if (packageJson.workspaces) {
      const patterns = Array.isArray(packageJson.workspaces)
        ? packageJson.workspaces
        : packageJson.workspaces.packages || []

      return {
        type: 'npm', // npm and yarn use same format
        patterns,
      }
    }

    // Check for pnpm workspaces (pnpm-workspace.yaml)
    const dir = path.dirname(packageJsonPath)
    const pnpmWorkspacePath = path.join(dir, 'pnpm-workspace.yaml')

    try {
      await fs.access(pnpmWorkspacePath)
      // Parse pnpm-workspace.yaml (simple YAML parsing for packages field)
      const yamlContent = await fs.readFile(pnpmWorkspacePath, 'utf-8')
      const patterns = parsePnpmWorkspacePatterns(yamlContent)

      return {
        type: 'pnpm',
        patterns,
      }
    } catch {
      // No pnpm workspace file
    }

    return { type: 'none', patterns: [] }
  } catch {
    return { type: 'none', patterns: [] }
  }
}

/**
 * Simple parser for pnpm-workspace.yaml packages field
 */
function parsePnpmWorkspacePatterns(yamlContent: string): string[] {
  const patterns: string[] = []
  const lines = yamlContent.split('\n')
  let inPackages = false

  for (const line of lines) {
    const trimmed = line.trim()

    if (trimmed === 'packages:') {
      inPackages = true
      continue
    }

    if (inPackages) {
      // Stop at next top-level key
      if (trimmed && !trimmed.startsWith('-') && !trimmed.startsWith('#')) {
        break
      }

      // Parse list item
      const match = trimmed.match(/^-\s*['"]?([^'"]+)['"]?/)
      if (match) {
        patterns.push(match[1])
      }
    }
  }

  return patterns
}

/**
 * Find workspace packages based on workspace patterns
 */
async function findWorkspacePackages(
  rootPath: string,
  workspaceConfig: WorkspaceConfig,
): Promise<PackageJsonLocation[]> {
  const results: PackageJsonLocation[] = []

  for (const pattern of workspaceConfig.patterns) {
    // Handle glob patterns like "packages/*" or "apps/**"
    const packages = await findPackagesMatchingPattern(rootPath, pattern)
    results.push(
      ...packages.map(p => ({
        path: p,
        isRoot: false,
        isWorkspace: true,
        workspacePattern: pattern,
      })),
    )
  }

  return results
}

/**
 * Find packages matching a workspace pattern
 * Supports basic glob patterns: *, **
 */
async function findPackagesMatchingPattern(
  rootPath: string,
  pattern: string,
): Promise<string[]> {
  const results: string[] = []

  // Convert glob pattern to regex-like logic
  const parts = pattern.split('/')
  const searchPath = path.join(rootPath, parts[0])

  // If pattern is like "packages/*", search one level deep
  if (parts.length === 2 && parts[1] === '*') {
    await searchOneLevel(searchPath, results)
  }
  // If pattern is like "packages/**", search recursively
  else if (parts.length === 2 && parts[1] === '**') {
    await searchRecursive(searchPath, results)
  }
  // If pattern is just a directory name, check if it has package.json
  else {
    const packageJsonPath = path.join(rootPath, pattern, 'package.json')
    try {
      await fs.access(packageJsonPath)
      results.push(packageJsonPath)
    } catch {
      // Not a valid package
    }
  }

  return results
}

/**
 * Search one level deep for package.json files
 */
async function searchOneLevel(
  dir: string,
  results: string[],
): Promise<void> {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true })

    for (const entry of entries) {
      if (!entry.isDirectory()) continue

      const packageJsonPath = path.join(dir, entry.name, 'package.json')
      try {
        await fs.access(packageJsonPath)
        results.push(packageJsonPath)
      } catch {
        // No package.json in this directory
      }
    }
  } catch {
    // Ignore permission errors or missing directories
  }
}

/**
 * Search recursively for package.json files
 */
async function searchRecursive(
  dir: string,
  results: string[],
): Promise<void> {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true })

    for (const entry of entries) {
      if (!entry.isDirectory()) continue

      const fullPath = path.join(dir, entry.name)

      // Skip hidden directories, node_modules, dist, build
      if (
        entry.name.startsWith('.') ||
        entry.name === 'node_modules' ||
        entry.name === 'dist' ||
        entry.name === 'build'
      ) {
        continue
      }

      // Check for package.json at this level
      const packageJsonPath = path.join(fullPath, 'package.json')
      try {
        await fs.access(packageJsonPath)
        results.push(packageJsonPath)
      } catch {
        // No package.json at this level
      }

      // Recurse into subdirectories
      await searchRecursive(fullPath, results)
    }
  } catch {
    // Ignore permission errors
  }
}

/**
 * Find nested package.json files without workspace configuration
 */
async function findNestedPackageJsonFiles(
  startPath: string,
): Promise<PackageJsonLocation[]> {
  const results: PackageJsonLocation[] = []

  async function search(dir: string, depth: number): Promise<void> {
    // Limit depth to avoid searching too deep
    if (depth > 5) return

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true })

      for (const entry of entries) {
        if (!entry.isDirectory()) continue

        const fullPath = path.join(dir, entry.name)

        // Skip hidden directories, node_modules, dist, build
        if (
          entry.name.startsWith('.') ||
          entry.name === 'node_modules' ||
          entry.name === 'dist' ||
          entry.name === 'build'
        ) {
          continue
        }

        // Check for package.json at this level
        const packageJsonPath = path.join(fullPath, 'package.json')
        try {
          await fs.access(packageJsonPath)
          // Don't include the root package.json (already added)
          if (packageJsonPath !== path.join(startPath, 'package.json')) {
            results.push({
              path: packageJsonPath,
              isRoot: false,
              isWorkspace: false,
            })
          }
        } catch {
          // No package.json at this level
        }

        // Recurse into subdirectories
        await search(fullPath, depth + 1)
      }
    } catch {
      // Ignore permission errors
    }
  }

  await search(startPath, 0)
  return results
}

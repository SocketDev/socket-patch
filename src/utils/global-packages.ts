import { execSync } from 'child_process'
import * as path from 'path'

/**
 * Get the npm global node_modules path using 'npm root -g'
 * @returns The path to the global node_modules directory
 */
export function getNpmGlobalPrefix(): string {
  try {
    const result = execSync('npm root -g', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    return result.trim()
  } catch (error) {
    throw new Error(
      'Failed to determine npm global prefix. Ensure npm is installed and in PATH.',
    )
  }
}

/**
 * Get the yarn global node_modules path
 * @returns The path to yarn's global node_modules directory, or null if not available
 */
export function getYarnGlobalPrefix(): string | null {
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
 * @returns The path to pnpm's global node_modules directory, or null if not available
 */
export function getPnpmGlobalPrefix(): string | null {
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
 * Get the bun global node_modules path
 * @returns The path to bun's global node_modules directory, or null if not available
 */
export function getBunGlobalPrefix(): string | null {
  try {
    const binPath = execSync('bun pm bin -g', {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim()
    const bunRoot = path.dirname(binPath)
    return path.join(bunRoot, 'install', 'global', 'node_modules')
  } catch {
    return null
  }
}

/**
 * Get the global node_modules path, with support for custom override
 * @param customPrefix - Optional custom path to use instead of auto-detection
 * @returns The path to the global node_modules directory
 */
export function getGlobalPrefix(customPrefix?: string): string {
  if (customPrefix) {
    return customPrefix
  }
  return getNpmGlobalPrefix()
}

/**
 * Get all global node_modules paths for package lookup
 * Returns paths from all detected package managers (npm, pnpm, yarn, bun)
 * @param customPrefix - Optional custom path to use instead of auto-detection
 * @returns Array of global node_modules paths
 */
export function getGlobalNodeModulesPaths(customPrefix?: string): string[] {
  if (customPrefix) {
    return [customPrefix]
  }

  const paths: string[] = []

  try {
    paths.push(getNpmGlobalPrefix())
  } catch {
    // npm not available
  }

  const pnpmPath = getPnpmGlobalPrefix()
  if (pnpmPath) {
    paths.push(pnpmPath)
  }

  const yarnPath = getYarnGlobalPrefix()
  if (yarnPath) {
    paths.push(yarnPath)
  }

  const bunPath = getBunGlobalPrefix()
  if (bunPath) {
    paths.push(bunPath)
  }

  return paths
}

/**
 * Check if a path is within a global node_modules directory
 */
export function isGlobalPath(pkgPath: string): boolean {
  try {
    const globalPaths = getGlobalNodeModulesPaths()
    const normalizedPkgPath = path.normalize(pkgPath)
    return globalPaths.some(globalPath =>
      normalizedPkgPath.startsWith(path.normalize(globalPath)),
    )
  } catch {
    return false
  }
}

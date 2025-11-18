import * as fs from 'fs/promises'
import {
  isPostinstallConfigured,
  updatePackageJsonContent,
} from './detect.js'

export interface UpdateResult {
  path: string
  status: 'updated' | 'already-configured' | 'error'
  oldScript: string
  newScript: string
  error?: string
}

/**
 * Update a single package.json file with socket-patch postinstall script
 */
export async function updatePackageJson(
  packageJsonPath: string,
  dryRun: boolean = false,
): Promise<UpdateResult> {
  try {
    // Read current package.json
    const content = await fs.readFile(packageJsonPath, 'utf-8')

    // Check current status
    const status = isPostinstallConfigured(content)

    if (!status.needsUpdate) {
      return {
        path: packageJsonPath,
        status: 'already-configured',
        oldScript: status.currentScript,
        newScript: status.currentScript,
      }
    }

    // Generate updated content
    const { modified, content: newContent, oldScript, newScript } =
      updatePackageJsonContent(content)

    if (!modified) {
      return {
        path: packageJsonPath,
        status: 'already-configured',
        oldScript,
        newScript,
      }
    }

    // Write updated content (unless dry run)
    if (!dryRun) {
      await fs.writeFile(packageJsonPath, newContent, 'utf-8')
    }

    return {
      path: packageJsonPath,
      status: 'updated',
      oldScript,
      newScript,
    }
  } catch (error) {
    return {
      path: packageJsonPath,
      status: 'error',
      oldScript: '',
      newScript: '',
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

/**
 * Update multiple package.json files
 */
export async function updateMultiplePackageJsons(
  paths: string[],
  dryRun: boolean = false,
): Promise<UpdateResult[]> {
  const results: UpdateResult[] = []

  for (const path of paths) {
    const result = await updatePackageJson(path, dryRun)
    results.push(result)
  }

  return results
}

/**
 * Shared logic for detecting and generating postinstall scripts
 * Used by both CLI and GitHub bot
 */

const SOCKET_PATCH_COMMAND = 'npx @socketsecurity/socket-patch apply'

export interface PostinstallStatus {
  configured: boolean
  currentScript: string
  needsUpdate: boolean
}

/**
 * Check if a postinstall script is properly configured for socket-patch
 */
export function isPostinstallConfigured(
  packageJsonContent: string | Record<string, any>,
): PostinstallStatus {
  let packageJson: Record<string, any>

  if (typeof packageJsonContent === 'string') {
    try {
      packageJson = JSON.parse(packageJsonContent)
    } catch {
      return {
        configured: false,
        currentScript: '',
        needsUpdate: true,
      }
    }
  } else {
    packageJson = packageJsonContent
  }

  const currentScript = packageJson.scripts?.postinstall || ''

  // Check if socket-patch apply is already present
  const configured = currentScript.includes('socket-patch apply')

  return {
    configured,
    currentScript,
    needsUpdate: !configured,
  }
}

/**
 * Generate an updated postinstall script that includes socket-patch
 */
export function generateUpdatedPostinstall(
  currentPostinstall: string,
): string {
  const trimmed = currentPostinstall.trim()

  // If empty, just add the socket-patch command
  if (!trimmed) {
    return SOCKET_PATCH_COMMAND
  }

  // If socket-patch is already present, return unchanged
  if (trimmed.includes('socket-patch apply')) {
    return trimmed
  }

  // Prepend socket-patch command so it runs first, then existing script
  // Using && ensures existing script only runs if patching succeeds
  return `${SOCKET_PATCH_COMMAND} && ${trimmed}`
}

/**
 * Update a package.json object with the new postinstall script
 * Returns the modified package.json and whether it was changed
 */
export function updatePackageJsonObject(
  packageJson: Record<string, any>,
): { modified: boolean; packageJson: Record<string, any> } {
  const status = isPostinstallConfigured(packageJson)

  if (!status.needsUpdate) {
    return { modified: false, packageJson }
  }

  // Ensure scripts object exists
  if (!packageJson.scripts) {
    packageJson.scripts = {}
  }

  // Update postinstall script
  const newPostinstall = generateUpdatedPostinstall(status.currentScript)
  packageJson.scripts.postinstall = newPostinstall

  return { modified: true, packageJson }
}

/**
 * Parse package.json content and update it with socket-patch postinstall
 * Returns the updated JSON string and metadata about the change
 */
export function updatePackageJsonContent(
  content: string,
): {
  modified: boolean
  content: string
  oldScript: string
  newScript: string
} {
  let packageJson: Record<string, any>

  try {
    packageJson = JSON.parse(content)
  } catch {
    throw new Error('Invalid package.json: failed to parse JSON')
  }

  const status = isPostinstallConfigured(packageJson)

  if (!status.needsUpdate) {
    return {
      modified: false,
      content,
      oldScript: status.currentScript,
      newScript: status.currentScript,
    }
  }

  // Update the package.json object
  const { packageJson: updatedPackageJson } =
    updatePackageJsonObject(packageJson)

  // Stringify with formatting
  const newContent = JSON.stringify(updatedPackageJson, null, 2) + '\n'
  const newScript = updatedPackageJson.scripts.postinstall

  return {
    modified: true,
    content: newContent,
    oldScript: status.currentScript,
    newScript,
  }
}

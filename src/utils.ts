import type { PatchResult } from './types.js'

export function formatPatchResult(result: PatchResult): string {
  if (result.success) {
    let message = `✓ Successfully patched ${result.packageName}@${result.version}`
    if (result.filesModified && result.filesModified.length > 0) {
      message += `\n  Modified files: ${result.filesModified.join(', ')}`
    }
    return message
  } else {
    return `✗ Failed to patch ${result.packageName}@${result.version}: ${result.error || 'Unknown error'}`
  }
}

export function log(message: string, verbose: boolean = false): void {
  if (verbose) {
    console.log(`[socket-patch] ${message}`)
  }
}

export function error(message: string): void {
  console.error(`[socket-patch] ERROR: ${message}`)
}

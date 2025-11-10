export interface PatchInfo {
  packageName: string
  version: string
  patchPath: string
  description?: string
}

export interface ApplyOptions {
  dryRun: boolean
  verbose: boolean
  force: boolean
}

export interface PatchResult {
  success: boolean
  packageName: string
  version: string
  error?: string
  filesModified?: string[]
}

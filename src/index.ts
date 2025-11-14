export type { PatchInfo, ApplyOptions, PatchResult } from './types.js'
export { formatPatchResult, log, error } from './utils.js'

// Re-export schema and hash modules
export * from './schema/manifest-schema.js'
export * from './hash/git-sha256.js'

// Re-export patch application utilities
export * from './patch/file-hash.js'
export * from './patch/apply.js'

// Re-export manifest utilities
export * from './manifest/operations.js'
export * from './manifest/recovery.js'

// Re-export constants
export * from './constants.js'

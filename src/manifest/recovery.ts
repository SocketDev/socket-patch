import type { PatchManifest, PatchRecord } from '../schema/manifest-schema.js'
import { PatchManifestSchema, PatchRecordSchema } from '../schema/manifest-schema.js'

/**
 * Result of manifest recovery operation
 */
export interface RecoveryResult {
  manifest: PatchManifest
  repairNeeded: boolean
  invalidPatches: string[]
  recoveredPatches: string[]
  discardedPatches: string[]
}

/**
 * Options for manifest recovery
 */
export interface RecoveryOptions {
  /**
   * Optional function to refetch patch data from external source (e.g., database)
   * Should return patch data or null if not found
   * @param uuid - The patch UUID
   * @param purl - The package URL (for context/validation)
   */
  refetchPatch?: (uuid: string, purl?: string) => Promise<PatchData | null>

  /**
   * Optional callback for logging recovery events
   */
  onRecoveryEvent?: (event: RecoveryEvent) => void
}

/**
 * Patch data returned from external source
 */
export interface PatchData {
  uuid: string
  purl: string
  publishedAt: string
  files: Record<
    string,
    {
      beforeHash?: string
      afterHash?: string
    }
  >
  vulnerabilities: Record<
    string,
    {
      cves: string[]
      summary: string
      severity: string
      description: string
    }
  >
  description: string
  license: string
  tier: string
}

/**
 * Events emitted during recovery
 */
export type RecoveryEvent =
  | { type: 'corrupted_manifest' }
  | { type: 'invalid_patch'; purl: string; uuid: string | null }
  | { type: 'recovered_patch'; purl: string; uuid: string }
  | { type: 'discarded_patch_not_found'; purl: string; uuid: string }
  | { type: 'discarded_patch_purl_mismatch'; purl: string; uuid: string; dbPurl: string }
  | { type: 'discarded_patch_no_uuid'; purl: string }
  | { type: 'recovery_error'; purl: string; uuid: string; error: string }

/**
 * Recover and validate manifest with automatic repair of invalid patches
 *
 * This function attempts to parse and validate a manifest. If the manifest
 * contains invalid patches, it will attempt to recover them using the provided
 * refetch function. Patches that cannot be recovered are discarded.
 *
 * @param parsed - The parsed manifest object (may be invalid)
 * @param options - Recovery options including refetch function and event callback
 * @returns Recovery result with repaired manifest and statistics
 */
export async function recoverManifest(
  parsed: unknown,
  options: RecoveryOptions = {},
): Promise<RecoveryResult> {
  const { refetchPatch, onRecoveryEvent } = options

  // Try strict parse first (fast path for valid manifests)
  const strictResult = PatchManifestSchema.safeParse(parsed)
  if (strictResult.success) {
    return {
      manifest: strictResult.data,
      repairNeeded: false,
      invalidPatches: [],
      recoveredPatches: [],
      discardedPatches: [],
    }
  }

  // Extract patches object with safety checks
  const patchesObj =
    parsed &&
    typeof parsed === 'object' &&
    'patches' in parsed &&
    parsed.patches &&
    typeof parsed.patches === 'object'
      ? (parsed.patches as Record<string, unknown>)
      : null

  if (!patchesObj) {
    // Completely corrupted manifest
    onRecoveryEvent?.({ type: 'corrupted_manifest' })
    return {
      manifest: { patches: {} },
      repairNeeded: true,
      invalidPatches: [],
      recoveredPatches: [],
      discardedPatches: [],
    }
  }

  // Try to recover individual patches
  const recoveredPatchesMap: Record<string, PatchRecord> = {}
  const invalidPatches: string[] = []
  const recoveredPatches: string[] = []
  const discardedPatches: string[] = []

  for (const [purl, patchData] of Object.entries(patchesObj)) {
    // Try to parse this individual patch
    const patchResult = PatchRecordSchema.safeParse(patchData)

    if (patchResult.success) {
      // Valid patch, keep it as-is
      recoveredPatchesMap[purl] = patchResult.data
    } else {
      // Invalid patch, try to recover from external source
      const uuid =
        patchData &&
        typeof patchData === 'object' &&
        'uuid' in patchData &&
        typeof patchData.uuid === 'string'
          ? patchData.uuid
          : null

      invalidPatches.push(purl)
      onRecoveryEvent?.({ type: 'invalid_patch', purl, uuid })

      if (uuid && refetchPatch) {
        try {
          // Try to refetch from external source
          const patchFromSource = await refetchPatch(uuid, purl)

          if (patchFromSource && patchFromSource.purl === purl) {
            // Successfully recovered, reconstruct patch record
            const manifestFiles: Record<
              string,
              { beforeHash: string; afterHash: string }
            > = {}
            for (const [filePath, fileInfo] of Object.entries(
              patchFromSource.files,
            )) {
              if (fileInfo.beforeHash && fileInfo.afterHash) {
                manifestFiles[filePath] = {
                  beforeHash: fileInfo.beforeHash,
                  afterHash: fileInfo.afterHash,
                }
              }
            }

            recoveredPatchesMap[purl] = {
              uuid: patchFromSource.uuid,
              exportedAt: patchFromSource.publishedAt,
              files: manifestFiles,
              vulnerabilities: patchFromSource.vulnerabilities,
              description: patchFromSource.description,
              license: patchFromSource.license,
              tier: patchFromSource.tier,
            }

            recoveredPatches.push(purl)
            onRecoveryEvent?.({ type: 'recovered_patch', purl, uuid })
          } else if (patchFromSource && patchFromSource.purl !== purl) {
            // PURL mismatch - wrong package!
            discardedPatches.push(purl)
            onRecoveryEvent?.({
              type: 'discarded_patch_purl_mismatch',
              purl,
              uuid,
              dbPurl: patchFromSource.purl,
            })
          } else {
            // Not found in external source (might be unpublished)
            discardedPatches.push(purl)
            onRecoveryEvent?.({
              type: 'discarded_patch_not_found',
              purl,
              uuid,
            })
          }
        } catch (error: unknown) {
          // Error during recovery
          discardedPatches.push(purl)
          const errorMessage = error instanceof Error ? error.message : String(error)
          onRecoveryEvent?.({
            type: 'recovery_error',
            purl,
            uuid,
            error: errorMessage,
          })
        }
      } else {
        // No UUID or no refetch function, can't recover
        discardedPatches.push(purl)
        if (!uuid) {
          onRecoveryEvent?.({ type: 'discarded_patch_no_uuid', purl })
        } else {
          onRecoveryEvent?.({
            type: 'discarded_patch_not_found',
            purl,
            uuid,
          })
        }
      }
    }
  }

  const repairNeeded = invalidPatches.length > 0

  return {
    manifest: { patches: recoveredPatchesMap },
    repairNeeded,
    invalidPatches,
    recoveredPatches,
    discardedPatches,
  }
}

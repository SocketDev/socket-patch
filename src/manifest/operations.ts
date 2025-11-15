import * as fs from 'fs/promises'
import type { PatchManifest, PatchRecord } from '../schema/manifest-schema.js'
import { PatchManifestSchema } from '../schema/manifest-schema.js'

/**
 * Get all blob hashes referenced by a manifest
 * Used for garbage collection and validation
 */
export function getReferencedBlobs(manifest: PatchManifest): Set<string> {
  const blobs = new Set<string>()

  for (const patchRecord of Object.values(manifest.patches)) {
    const record = patchRecord as PatchRecord
    for (const fileInfo of Object.values(record.files)) {
      blobs.add(fileInfo.beforeHash)
      blobs.add(fileInfo.afterHash)
    }
  }

  return blobs
}

/**
 * Calculate differences between two manifests
 */
export interface ManifestDiff {
  added: Set<string> // PURLs
  removed: Set<string>
  modified: Set<string>
}

export function diffManifests(
  oldManifest: PatchManifest,
  newManifest: PatchManifest,
): ManifestDiff {
  const oldPurls = new Set(Object.keys(oldManifest.patches))
  const newPurls = new Set(Object.keys(newManifest.patches))

  const added = new Set<string>()
  const removed = new Set<string>()
  const modified = new Set<string>()

  // Find added and modified
  for (const purl of newPurls) {
    if (!oldPurls.has(purl)) {
      added.add(purl)
    } else {
      const oldPatch = oldManifest.patches[purl] as PatchRecord
      const newPatch = newManifest.patches[purl] as PatchRecord
      if (oldPatch.uuid !== newPatch.uuid) {
        modified.add(purl)
      }
    }
  }

  // Find removed
  for (const purl of oldPurls) {
    if (!newPurls.has(purl)) {
      removed.add(purl)
    }
  }

  return { added, removed, modified }
}

/**
 * Validate a parsed manifest object
 */
export function validateManifest(parsed: unknown): {
  success: boolean
  manifest?: PatchManifest
  error?: string
} {
  const result = PatchManifestSchema.safeParse(parsed)
  if (result.success) {
    return { success: true, manifest: result.data }
  }
  return {
    success: false,
    error: result.error.message,
  }
}

/**
 * Read and parse a manifest from the filesystem
 */
export async function readManifest(path: string): Promise<PatchManifest | null> {
  try {
    const content = await fs.readFile(path, 'utf-8')
    const parsed = JSON.parse(content)
    const result = validateManifest(parsed)
    return result.success ? result.manifest! : null
  } catch {
    return null
  }
}

/**
 * Write a manifest to the filesystem
 */
export async function writeManifest(
  path: string,
  manifest: PatchManifest,
): Promise<void> {
  const content = JSON.stringify(manifest, null, 2)
  await fs.writeFile(path, content, 'utf-8')
}

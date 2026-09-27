import { z } from 'zod'

export const DEFAULT_PATCH_MANIFEST_PATH = '.socket/manifest.json'

export const PatchRecordSchema = z.object({
  uuid: z.string().uuid(),
  exportedAt: z.string(),
  files: z.record(
    z.string(), // File path
    z.object({
      beforeHash: z.string(),
      afterHash: z.string(),
    }),
  ),
  vulnerabilities: z.record(
    z.string(), // Vulnerability ID like "GHSA-jrhj-2j3q-xf3v"
    z.object({
      cves: z.array(z.string()),
      summary: z.string(),
      severity: z.string(),
      description: z.string(),
    }),
  ),
  description: z.string(),
  license: z.string(),
  tier: z.string(),
})

export type PatchRecord = z.infer<typeof PatchRecordSchema>

export const PatchManifestSchema = z.object({
  patches: z.record(
    z.string(), // Package identifier like "npm:simplehttpserver@0.0.6"
    PatchRecordSchema,
  ),
})

export type PatchManifest = z.infer<typeof PatchManifestSchema>

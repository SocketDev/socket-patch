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

// Legacy state written by the `setup` command that v5 removed (and by the
// pre-v5 `vex`). The CLI still parses it and keeps it on rewrite, so a
// manifest validated here keeps it too. Mirrors `SetupConfig` in
// crates/socket-patch-core/src/manifest/schema.rs.
export const SetupConfigSchema = z.object({
  // Workspace-member paths the removed `setup` skipped.
  exclude: z.array(z.string()).optional(),
  // Ecosystems the pre-v5 `vex` attested with no install hook wired.
  manual: z.array(z.string()).optional(),
})

export type SetupConfig = z.infer<typeof SetupConfigSchema>

export const PatchManifestSchema = z.object({
  patches: z.record(
    z.string(), // Package PURL like "pkg:npm/simplehttpserver@0.0.6"
    PatchRecordSchema,
  ),
  setup: SetupConfigSchema.optional(),
})

export type PatchManifest = z.infer<typeof PatchManifestSchema>

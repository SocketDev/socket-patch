export type Ecosystem = 'npm' | 'pypi' | 'cargo' | 'golang' | 'gem' | 'composer' | 'maven' | 'nuget'

export interface TreeEntryInput { path: string; mode: string; type: 'blob' | 'tree' | 'commit'; size?: number }
export interface PathSelection {
  roots: string[]              // detected project roots, repo-relative ('' = repo root), sorted
  fetchText: string[]          // stream these as UTF-8 text files
  fetchBinary: string[]        // stream these as raw bytes (e.g. bun.lockb)
  presentOnly: string[]        // engine only needs to know they exist (e.g. .pnp.cjs, rush repo-state.json)
  symlinks: string[]           // candidate paths that are symlinks (mode 120000) — refuse-to-write
  ignoredCount: number
  ignoredSample: { path: string; reason: string }[]   // ≤100
}
export function selectHostedScanPaths(entries: TreeEntryInput[], options?: { projectRoots?: string[]; ecosystems?: Ecosystem[] }): PathSelection
export function hostedScanCandidateFiles(): string[]    // debug listing only
export function engineVersion(): string                  // "<crate version>+<git sha or 'unknown'>"

export type ProviderErrorKind = 'unauthorized' | 'forbidden' | 'rate_limited' | 'network' | 'parse' | 'not_found' | 'other'
export type ProviderResult<T> = { ok: true; value: T } | { ok: false; error: { kind: ProviderErrorKind; message: string } }

// Request/response bodies are EXACTLY the api-v0 HTTP JSON bodies (camelCase), so the Rust serde types are reused unchanged.
export interface BatchPatchInfo { uuid: string; purl: string; tier: string; cveIds: string[]; ghsaIds: string[]; severity: string | null; title: string; publishedAt?: string }
export interface BatchSearchResponse { packages: { purl: string; patches: BatchPatchInfo[] }[]; canAccessPaidPatches: boolean }
export interface PatchSearchResult { uuid: string; purl: string; publishedAt: string; description: string; license: string; tier: string; vulnerabilities: Record<string, { cves: string[]; summary: string; severity: string; description: string }> }
export interface SearchResponse { patches: PatchSearchResult[]; canAccessPaidPatches: boolean }
export interface PackageVendorResult { status: string; url: string | null; purl: string | null; artifacts: unknown[] | null; registryOverride: unknown | null }   // exact api-v0 package.ts serialization (null-filled)
export interface PatchResponse { uuid: string; purl: string; publishedAt: string; files: Record<string, { beforeHash?: string; afterHash?: string; socketBlob?: string }>; vulnerabilities: Record<string, unknown>; description: string; license: string; tier: string }

export interface PatchProvider {
  searchPatchesBatch(request: { components: { purl: string }[] }): Promise<ProviderResult<BatchSearchResponse>>
  searchPatchesByPackage(request: { purl: string }): Promise<ProviderResult<SearchResponse>>
  fetchRegistryReferences(request: { uuids: string[] }): Promise<ProviderResult<{ results: Record<string, PackageVendorResult> }>>
  fetchPatch(request: { uuid: string }): Promise<ProviderResult<PatchResponse | null>>
  downloadArtifact(request: { url: string; maxBytes: number }): Promise<ProviderResult<Buffer>>
}
// Providers MUST resolve (never reject); the JS loader wraps provider methods so a thrown/rejected call becomes {ok:false, kind:'other'}.
// A 'not_found' failure mirrors the HTTP API's 404 per method: searchPatchesByPackage => no patches, fetchRegistryReferences => no references, fetchPatch => null, searchPatchesBatch and downloadArtifact => error.

export interface HostedScanLimits { maxFileBytes?: number /*20 MiB*/; maxTotalBytes?: number /*64 MiB*/; maxFiles?: number /*2000*/; maxPurls?: number /*20000*/; maxProjects?: number /*200*/; maxArtifactBytes?: number /*32 MiB*/ }
export interface HostedScanSessionOptions {
  orgSlug: string
  ecosystems?: Ecosystem[]
  batchSize?: number               // 1..500, default 100
  dryRun?: boolean
  pipenvMajor?: number             // never spawns pipenv; absent => same default as CLI when pipenv unavailable
  trustLockfileConfig?: boolean    // default true
  npmAllowRemoteConfig?: boolean   // default true
  projectRoots?: string[]          // must match selectHostedScanPaths input
  providerConcurrency?: number     // default 8
  requestTimeoutMs?: number        // per provider call, default 60000
  limits?: HostedScanLimits
  maxNewPatches?: number | 'none'  // run-wide cap on NEW patches, most severe first; 0 = upgrades only; absent/'none' = unlimited
  maxNewPatchesCap?: number        // server ceiling: tightens maxNewPatches (including 'none'), never loosens it
  inFlightPatches?: string[]       // base purls already in the open rollout PR: ranked first
}
export class HostedScanSession {
  constructor(options: HostedScanSessionOptions, provider: PatchProvider)
  pushChunk(path: string, chunk: Buffer): void        // throws on limit breach, unknown state, or after finish
  endFile(path: string): void
  markPresent(path: string, kind: 'present' | 'symlink' | 'binary_skipped' | 'oversize' | 'lfs_pointer'): void
  finish(): Promise<HostedScanResult>                 // runs off the JS thread; rejects only on engine bug/limit/cancel
  cancel(): void                                      // cooperative; finish() rejects with code 'cancelled'
}
export interface EngineWarning { code: string; detail: string; projectRoot?: string }
export interface ProjectResult {
  root: string
  redirect: Record<string, unknown>                   // same shape as CLI `--json` `redirect` block
  summary: { scannedPackages: number; packagesWithPatches: number; totalPatches: number; freePatches: number; paidPatches: number; canAccessPaidPatches: boolean }
  redirected: { purl: string; uuid: string }[]
  skipped: { purl: string; uuid: string; reason: string; detail?: string }[]   // deferred rows also appear here as `rollout_deferred`
  deferred: DeferredPatch[]                           // NEW patches over the maxNewPatches budget, rank order
  error?: { code: string; message: string }           // project-level failure (e.g. corrupt_ledger, patch_lookup_failed)
}
export interface DeferredPatch { purl: string; uuid: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown'; rank: number }
export interface RolloutBlock {                       // same shape as CLI `scan --json` `rollout`
  maxNewPatches: { value: number | null; source: 'flag' | 'env' | 'file' | 'default' | 'cap' }
  counts: { new: number; deferred: number; upgrade: number; already: number }
  deferred: { purl: string; uuids: string[]; severity: string; advisoryCount: number; projects: string[]; rank: number }[]
}
export interface HostedScanResult {
  projects: ProjectResult[]
  changedFiles: { path: string; content: string }[]            // repo-relative, sorted, only byte-changed, includes ledgers (wet runs only)
  changedBinaryFiles: { path: string; content: Buffer }[]
  deletedFiles: string[]
  warnings: EngineWarning[]
  rollout: RolloutBlock                               // session-level: one budget across every project
  stats: { projects: number; filesInput: number; bytesInput: number; packagesScanned: number; packagesWithPatches: number; patchesSelected: number; patchesRedirected: number; filesChanged: number; providerCalls: Record<string, number>; phaseMs: Record<string, number> }
  engineVersion: string
}

export class SocketPatchAddonUnavailableError extends Error {
  readonly code: 'addon_unavailable'
  readonly attempted: string[]
}

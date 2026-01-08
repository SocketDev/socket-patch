/**
 * Represents a package discovered during crawling
 */
export interface CrawledPackage {
  /** Package name (without scope) */
  name: string
  /** Package version */
  version: string
  /** Package scope/namespace (e.g., @types) - undefined for unscoped packages */
  namespace?: string
  /** Full PURL string (e.g., pkg:npm/@types/node@20.0.0) */
  purl: string
  /** Absolute path to the package directory */
  path: string
}

/**
 * Options for package crawling
 */
export interface CrawlerOptions {
  /** Working directory to start from */
  cwd: string
  /** Use global packages instead of local node_modules */
  global?: boolean
  /** Custom path to global node_modules (overrides auto-detection) */
  globalPrefix?: string
  /** Batch size for yielding packages (default: 100) */
  batchSize?: number
}

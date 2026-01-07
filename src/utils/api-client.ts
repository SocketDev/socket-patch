import * as https from 'node:https'
import * as http from 'node:http'

// Default public patch API URL for free patches (no auth required).
const DEFAULT_PATCH_API_PROXY_URL = 'https://patches-api.socket.dev'

/**
 * Check if debug mode is enabled.
 */
function isDebugEnabled(): boolean {
  return process.env.SOCKET_PATCH_DEBUG === '1' || process.env.SOCKET_PATCH_DEBUG === 'true'
}

/**
 * Log debug messages when debug mode is enabled.
 */
function debugLog(message: string, ...args: unknown[]): void {
  if (isDebugEnabled()) {
    console.error(`[socket-patch debug] ${message}`, ...args)
  }
}

/**
 * Get the HTTP proxy URL from environment variables.
 * Returns undefined if no proxy is configured.
 *
 * Note: Full HTTP proxy support requires manual configuration.
 * Node.js native http/https modules don't support proxies natively.
 * For proxy support, set NODE_EXTRA_CA_CERTS and configure your
 * system/corporate proxy settings.
 */
function getHttpProxyUrl(): string | undefined {
  return process.env.SOCKET_PATCH_HTTP_PROXY ||
    process.env.HTTPS_PROXY ||
    process.env.https_proxy ||
    process.env.HTTP_PROXY ||
    process.env.http_proxy
}

// Full patch response with blob content (from view endpoint)
export interface PatchResponse {
  uuid: string
  purl: string
  publishedAt: string
  files: Record<
    string,
    {
      beforeHash?: string
      afterHash?: string
      socketBlob?: string
      blobContent?: string // after blob content (base64)
      beforeBlobContent?: string // before blob content (base64) - for rollback
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
  tier: 'free' | 'paid'
}

// Lightweight search result (from search endpoints)
export interface PatchSearchResult {
  uuid: string
  purl: string
  publishedAt: string
  description: string
  license: string
  tier: 'free' | 'paid'
  vulnerabilities: Record<
    string,
    {
      cves: string[]
      summary: string
      severity: string
      description: string
    }
  >
}

export interface SearchResponse {
  patches: PatchSearchResult[]
  canAccessPaidPatches: boolean
}

// Minimal patch info from batch search
export interface BatchPatchInfo {
  uuid: string
  purl: string
  tier: 'free' | 'paid'
  cveIds: string[]
  ghsaIds: string[]
  severity: string | null
  title: string
}

export interface BatchPackagePatches {
  purl: string
  patches: BatchPatchInfo[]
}

export interface BatchSearchResponse {
  packages: BatchPackagePatches[]
  canAccessPaidPatches: boolean
}

export interface APIClientOptions {
  apiUrl: string
  apiToken?: string
  /**
   * When true, the client will use the public patch API proxy
   * which only provides access to free patches without authentication.
   */
  usePublicProxy?: boolean
  /**
   * Organization slug for authenticated blob downloads.
   * Required when using authenticated API (not public proxy).
   */
  orgSlug?: string
}

export class APIClient {
  private readonly apiUrl: string
  private readonly apiToken?: string
  private readonly usePublicProxy: boolean
  private readonly orgSlug?: string

  constructor(options: APIClientOptions) {
    this.apiUrl = options.apiUrl.replace(/\/$/, '') // Remove trailing slash
    this.apiToken = options.apiToken
    this.usePublicProxy = options.usePublicProxy ?? false
    this.orgSlug = options.orgSlug
  }

  /**
   * Make a GET request to the API.
   */
  private async get<T>(path: string): Promise<T | null> {
    const url = `${this.apiUrl}${path}`
    debugLog(`GET ${url}`)

    // Log proxy warning if configured but not natively supported.
    const proxyUrl = getHttpProxyUrl()
    if (proxyUrl) {
      debugLog(`HTTP proxy detected: ${proxyUrl} (Note: native http/https modules don't support proxies directly)`)
    }

    return new Promise((resolve, reject) => {
      const urlObj = new URL(url)
      const isHttps = urlObj.protocol === 'https:'
      const httpModule = isHttps ? https : http

      const headers: Record<string, string> = {
        Accept: 'application/json',
        'User-Agent': 'SocketPatchCLI/1.0',
      }

      // Only add auth header if we have a token (not using public proxy).
      if (this.apiToken) {
        headers['Authorization'] = `Bearer ${this.apiToken}`
      }

      const options: https.RequestOptions = {
        method: 'GET',
        headers,
      }

      const req = httpModule.request(urlObj, options, res => {
        let data = ''

        res.on('data', chunk => {
          data += chunk
        })

        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              const parsed = JSON.parse(data)
              resolve(parsed)
            } catch (err) {
              reject(new Error(`Failed to parse response: ${err}`))
            }
          } else if (res.statusCode === 404) {
            resolve(null)
          } else if (res.statusCode === 401) {
            reject(new Error('Unauthorized: Invalid API token'))
          } else if (res.statusCode === 403) {
            const msg = this.usePublicProxy
              ? 'Forbidden: This patch is only available to paid subscribers. Sign up at https://socket.dev to access paid patches.'
              : 'Forbidden: Access denied. This may be a paid patch or you may not have access to this organization.'
            reject(new Error(msg))
          } else if (res.statusCode === 429) {
            reject(new Error('Rate limit exceeded. Please try again later.'))
          } else {
            reject(
              new Error(
                `API request failed with status ${res.statusCode}: ${data}`,
              ),
            )
          }
        })
      })

      req.on('error', err => {
        reject(new Error(`Network error: ${err.message}`))
      })

      req.end()
    })
  }

  /**
   * Make a POST request to the API.
   */
  private async post<T>(path: string, body: unknown): Promise<T | null> {
    const url = `${this.apiUrl}${path}`
    debugLog(`POST ${url}`)

    return new Promise((resolve, reject) => {
      const urlObj = new URL(url)
      const isHttps = urlObj.protocol === 'https:'
      const httpModule = isHttps ? https : http

      const jsonBody = JSON.stringify(body)

      const headers: Record<string, string> = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(jsonBody).toString(),
        'User-Agent': 'SocketPatchCLI/1.0',
      }

      // Only add auth header if we have a token (not using public proxy).
      if (this.apiToken) {
        headers['Authorization'] = `Bearer ${this.apiToken}`
      }

      const options: https.RequestOptions = {
        method: 'POST',
        headers,
      }

      const req = httpModule.request(urlObj, options, res => {
        let data = ''

        res.on('data', chunk => {
          data += chunk
        })

        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              const parsed = JSON.parse(data)
              resolve(parsed)
            } catch (err) {
              reject(new Error(`Failed to parse response: ${err}`))
            }
          } else if (res.statusCode === 404) {
            resolve(null)
          } else if (res.statusCode === 401) {
            reject(new Error('Unauthorized: Invalid API token'))
          } else if (res.statusCode === 403) {
            const msg = this.usePublicProxy
              ? 'Forbidden: This resource is only available to paid subscribers.'
              : 'Forbidden: Access denied.'
            reject(new Error(msg))
          } else if (res.statusCode === 429) {
            reject(new Error('Rate limit exceeded. Please try again later.'))
          } else {
            reject(
              new Error(
                `API request failed with status ${res.statusCode}: ${data}`,
              ),
            )
          }
        })
      })

      req.on('error', err => {
        reject(new Error(`Network error: ${err.message}`))
      })

      req.write(jsonBody)
      req.end()
    })
  }

  /**
   * Fetch a patch by UUID (full details with blob content)
   */
  async fetchPatch(
    orgSlug: string | null,
    uuid: string,
  ): Promise<PatchResponse | null> {
    // Public proxy uses /patch/* prefix for patch endpoints
    const path = this.usePublicProxy
      ? `/patch/view/${uuid}`
      : `/v0/orgs/${orgSlug}/patches/view/${uuid}`
    return this.get(path)
  }

  /**
   * Search patches by CVE ID
   * Returns lightweight search results (no blob content)
   */
  async searchPatchesByCVE(
    orgSlug: string | null,
    cveId: string,
  ): Promise<SearchResponse> {
    // Public proxy uses /patch/* prefix for patch endpoints
    const path = this.usePublicProxy
      ? `/patch/by-cve/${encodeURIComponent(cveId)}`
      : `/v0/orgs/${orgSlug}/patches/by-cve/${encodeURIComponent(cveId)}`
    const result = await this.get<SearchResponse>(path)
    return result ?? { patches: [], canAccessPaidPatches: false }
  }

  /**
   * Search patches by GHSA ID
   * Returns lightweight search results (no blob content)
   */
  async searchPatchesByGHSA(
    orgSlug: string | null,
    ghsaId: string,
  ): Promise<SearchResponse> {
    // Public proxy uses /patch/* prefix for patch endpoints
    const path = this.usePublicProxy
      ? `/patch/by-ghsa/${encodeURIComponent(ghsaId)}`
      : `/v0/orgs/${orgSlug}/patches/by-ghsa/${encodeURIComponent(ghsaId)}`
    const result = await this.get<SearchResponse>(path)
    return result ?? { patches: [], canAccessPaidPatches: false }
  }

  /**
   * Search patches by package PURL
   * Returns lightweight search results (no blob content)
   *
   * The PURL must be a valid Package URL starting with "pkg:"
   * Examples:
   * - pkg:npm/lodash@4.17.21
   * - pkg:npm/@types/node
   * - pkg:pypi/django@3.2.0
   */
  async searchPatchesByPackage(
    orgSlug: string | null,
    purl: string,
  ): Promise<SearchResponse> {
    // Public proxy uses /patch/* prefix for patch endpoints
    const path = this.usePublicProxy
      ? `/patch/by-package/${encodeURIComponent(purl)}`
      : `/v0/orgs/${orgSlug}/patches/by-package/${encodeURIComponent(purl)}`
    const result = await this.get<SearchResponse>(path)
    return result ?? { patches: [], canAccessPaidPatches: false }
  }

  /**
   * Search patches for multiple packages by PURL (batch)
   * Returns minimal patch information for each package that has available patches.
   *
   * Each PURL must:
   * - Start with "pkg:"
   * - Include a valid ecosystem type (npm, pypi, maven, etc.)
   * - Include package name
   * - Include version (required for batch lookups)
   *
   * Maximum 500 PURLs per request.
   */
  async searchPatchesBatch(
    orgSlug: string | null,
    purls: string[],
  ): Promise<BatchSearchResponse> {
    // Public proxy uses /patch/* prefix for patch endpoints
    const path = this.usePublicProxy
      ? `/patch/batch`
      : `/v0/orgs/${orgSlug}/patches/batch`
    const result = await this.post<BatchSearchResponse>(path, { purls })
    return result ?? { packages: [], canAccessPaidPatches: false }
  }

  /**
   * Fetch a blob by its SHA256 hash.
   * Returns the raw binary content as a Buffer, or null if not found.
   *
   * Uses authenticated API endpoint when token and orgSlug are available,
   * otherwise falls back to the public proxy.
   *
   * @param hash - SHA256 hash (64 hex characters)
   * @returns Buffer containing blob data, or null if not found
   */
  async fetchBlob(hash: string): Promise<Buffer | null> {
    // Validate hash format (SHA256 = 64 hex chars)
    if (!/^[a-f0-9]{64}$/i.test(hash)) {
      throw new Error(`Invalid hash format: ${hash}. Expected SHA256 hash (64 hex characters).`)
    }

    // Use authenticated API endpoint when available, otherwise use public proxy
    let url: string
    let useAuth = false
    if (this.apiToken && this.orgSlug && !this.usePublicProxy) {
      // Use authenticated endpoint
      url = `${this.apiUrl}/v0/orgs/${this.orgSlug}/patches/blob/${hash}`
      useAuth = true
    } else {
      // Fall back to public proxy
      const proxyUrl = process.env.SOCKET_PATCH_PROXY_URL || DEFAULT_PATCH_API_PROXY_URL
      url = `${proxyUrl}/patch/blob/${hash}`
    }

    return new Promise((resolve, reject) => {
      const urlObj = new URL(url)
      const isHttps = urlObj.protocol === 'https:'
      const httpModule = isHttps ? https : http

      const headers: Record<string, string> = {
        Accept: 'application/octet-stream',
        'User-Agent': 'SocketPatchCLI/1.0',
      }

      // Add auth header when using authenticated endpoint
      if (useAuth && this.apiToken) {
        headers['Authorization'] = `Bearer ${this.apiToken}`
      }

      const options: https.RequestOptions = {
        method: 'GET',
        headers,
      }

      const req = httpModule.request(urlObj, options, res => {
        const chunks: Buffer[] = []

        res.on('data', (chunk: Buffer) => {
          chunks.push(chunk)
        })

        res.on('end', () => {
          if (res.statusCode === 200) {
            resolve(Buffer.concat(chunks))
          } else if (res.statusCode === 404) {
            resolve(null)
          } else {
            const errorBody = Buffer.concat(chunks).toString('utf-8')
            reject(
              new Error(
                `Failed to fetch blob ${hash}: status ${res.statusCode} - ${errorBody}`,
              ),
            )
          }
        })
      })

      req.on('error', err => {
        reject(new Error(`Network error fetching blob ${hash}: ${err.message}`))
      })

      req.end()
    })
  }

}

/**
 * Get an API client configured from environment variables.
 *
 * If SOCKET_API_TOKEN is not set, the client will use the public patch API proxy
 * which provides free access to free-tier patches without authentication.
 *
 * Environment variables:
 * - SOCKET_API_URL: Override the API URL (defaults to https://api.socket.dev)
 * - SOCKET_API_TOKEN: API token for authenticated access to all patches
 * - SOCKET_PATCH_PROXY_URL: Override the public patch API URL (defaults to https://patches-api.socket.dev)
 * - SOCKET_ORG_SLUG: Organization slug for authenticated blob downloads
 *
 * @param orgSlug - Optional organization slug (overrides SOCKET_ORG_SLUG env var)
 */
export function getAPIClientFromEnv(orgSlug?: string): { client: APIClient; usePublicProxy: boolean } {
  const apiToken = process.env.SOCKET_API_TOKEN
  const resolvedOrgSlug = orgSlug || process.env.SOCKET_ORG_SLUG

  if (!apiToken) {
    // No token provided - use public proxy for free patches
    const proxyUrl = process.env.SOCKET_PATCH_PROXY_URL || DEFAULT_PATCH_API_PROXY_URL
    console.log('No SOCKET_API_TOKEN set. Using public patch API proxy (free patches only).')
    return {
      client: new APIClient({ apiUrl: proxyUrl, usePublicProxy: true }),
      usePublicProxy: true,
    }
  }

  const apiUrl = process.env.SOCKET_API_URL || 'https://api.socket.dev'
  return {
    client: new APIClient({ apiUrl, apiToken, orgSlug: resolvedOrgSlug }),
    usePublicProxy: false,
  }
}

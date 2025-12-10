import * as https from 'node:https'
import * as http from 'node:http'

// Default public patch API proxy URL for free patches (no auth required)
// Patch API routes are now served via firewall-api-proxy under /patch prefix
const DEFAULT_PATCH_API_PROXY_URL = 'https://firewall-api.socket.dev/patch'

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
      blobContent?: string
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

export interface APIClientOptions {
  apiUrl: string
  apiToken?: string
  /**
   * When true, the client will use the public patch API proxy
   * which only provides access to free patches without authentication.
   */
  usePublicProxy?: boolean
}

export class APIClient {
  private readonly apiUrl: string
  private readonly apiToken?: string
  private readonly usePublicProxy: boolean

  constructor(options: APIClientOptions) {
    this.apiUrl = options.apiUrl.replace(/\/$/, '') // Remove trailing slash
    this.apiToken = options.apiToken
    this.usePublicProxy = options.usePublicProxy ?? false
  }

  /**
   * Make a GET request to the API
   */
  private async get<T>(path: string): Promise<T | null> {
    const url = `${this.apiUrl}${path}`

    return new Promise((resolve, reject) => {
      const urlObj = new URL(url)
      const isHttps = urlObj.protocol === 'https:'
      const httpModule = isHttps ? https : http

      const headers: Record<string, string> = {
        Accept: 'application/json',
      }

      // Only add auth header if we have a token (not using public proxy)
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
   * Fetch a patch by UUID (full details with blob content)
   */
  async fetchPatch(
    orgSlug: string | null,
    uuid: string,
  ): Promise<PatchResponse | null> {
    // Public proxy uses simpler URL structure (no org slug needed)
    const path = this.usePublicProxy
      ? `/view/${uuid}`
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
    // Public proxy uses simpler URL structure (no org slug needed)
    const path = this.usePublicProxy
      ? `/by-cve/${encodeURIComponent(cveId)}`
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
    // Public proxy uses simpler URL structure (no org slug needed)
    const path = this.usePublicProxy
      ? `/by-ghsa/${encodeURIComponent(ghsaId)}`
      : `/v0/orgs/${orgSlug}/patches/by-ghsa/${encodeURIComponent(ghsaId)}`
    const result = await this.get<SearchResponse>(path)
    return result ?? { patches: [], canAccessPaidPatches: false }
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
 * - SOCKET_PATCH_PROXY_URL: Override the public proxy URL (defaults to https://patch-api.socket.dev)
 */
export function getAPIClientFromEnv(): { client: APIClient; usePublicProxy: boolean } {
  const apiToken = process.env.SOCKET_API_TOKEN

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
    client: new APIClient({ apiUrl, apiToken }),
    usePublicProxy: false,
  }
}

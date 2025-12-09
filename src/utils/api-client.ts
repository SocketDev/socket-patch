import * as https from 'node:https'
import * as http from 'node:http'

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
  apiToken: string
}

export class APIClient {
  private readonly apiUrl: string
  private readonly apiToken: string

  constructor(options: APIClientOptions) {
    this.apiUrl = options.apiUrl.replace(/\/$/, '') // Remove trailing slash
    this.apiToken = options.apiToken
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

      const options: https.RequestOptions = {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${this.apiToken}`,
          Accept: 'application/json',
        },
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
            reject(
              new Error(
                'Forbidden: Access denied. This may be a paid patch or you may not have access to this organization.',
              ),
            )
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
    orgSlug: string,
    uuid: string,
  ): Promise<PatchResponse | null> {
    return this.get(`/v0/orgs/${orgSlug}/patches/view/${uuid}`)
  }

  /**
   * Search patches by CVE ID
   * Returns lightweight search results (no blob content)
   */
  async searchPatchesByCVE(
    orgSlug: string,
    cveId: string,
  ): Promise<SearchResponse> {
    const result = await this.get<SearchResponse>(
      `/v0/orgs/${orgSlug}/patches/by-cve/${encodeURIComponent(cveId)}`,
    )
    return result ?? { patches: [], canAccessPaidPatches: false }
  }

  /**
   * Search patches by GHSA ID
   * Returns lightweight search results (no blob content)
   */
  async searchPatchesByGHSA(
    orgSlug: string,
    ghsaId: string,
  ): Promise<SearchResponse> {
    const result = await this.get<SearchResponse>(
      `/v0/orgs/${orgSlug}/patches/by-ghsa/${encodeURIComponent(ghsaId)}`,
    )
    return result ?? { patches: [], canAccessPaidPatches: false }
  }

  /**
   * Search patches by package name (partial PURL match)
   * Returns lightweight search results (no blob content)
   */
  async searchPatchesByPackage(
    orgSlug: string,
    packageQuery: string,
  ): Promise<SearchResponse> {
    const result = await this.get<SearchResponse>(
      `/v0/orgs/${orgSlug}/patches/by-package/${encodeURIComponent(packageQuery)}`,
    )
    return result ?? { patches: [], canAccessPaidPatches: false }
  }
}

export function getAPIClientFromEnv(): APIClient {
  const apiUrl = process.env.SOCKET_API_URL || 'https://api.socket.dev'
  const apiToken = process.env.SOCKET_API_TOKEN

  if (!apiToken) {
    throw new Error(
      'SOCKET_API_TOKEN environment variable is required. Please set it to your Socket API token.',
    )
  }

  return new APIClient({ apiUrl, apiToken })
}

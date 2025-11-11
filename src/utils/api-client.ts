import * as https from 'node:https'
import * as http from 'node:http'

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

  async fetchPatch(
    orgSlug: string,
    uuid: string,
  ): Promise<PatchResponse | null> {
    const url = `${this.apiUrl}/v0/orgs/${orgSlug}/patches/view/${uuid}`

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
              new Error(`API request failed with status ${res.statusCode}: ${data}`),
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
}

export function getAPIClientFromEnv(): APIClient {
  const apiUrl =
    process.env.SOCKET_API_URL || 'https://api.socket.dev'
  const apiToken = process.env.SOCKET_API_TOKEN

  if (!apiToken) {
    throw new Error(
      'SOCKET_API_TOKEN environment variable is required. Please set it to your Socket API token.',
    )
  }

  return new APIClient({ apiUrl, apiToken })
}

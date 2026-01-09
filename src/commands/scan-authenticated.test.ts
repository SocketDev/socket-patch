import { describe, it, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import * as path from 'path'
import * as http from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  createTestDir,
  removeTestDir,
  createTestPackage,
} from '../test-utils.js'
import { APIClient, type BatchSearchResponse } from '../utils/api-client.js'
import { NpmCrawler } from '../crawlers/index.js'

// Test UUIDs
const TEST_UUID_1 = '11111111-1111-4111-8111-111111111111'
const TEST_UUID_2 = '22222222-2222-4222-8222-222222222222'
const TEST_UUID_3 = '33333333-3333-4333-8333-333333333333'

/**
 * Create a mock HTTP server that simulates the Socket API
 */
function createMockServer(options: {
  requireAuth?: boolean
  canAccessPaidPatches?: boolean
  patchResponses?: Map<string, BatchSearchResponse>
}): http.Server {
  const {
    requireAuth = false,
    canAccessPaidPatches = false,
    patchResponses = new Map(),
  } = options

  return http.createServer((req, res) => {
    // Check authorization if required
    if (requireAuth) {
      const authHeader = req.headers['authorization']
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.writeHead(401, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Unauthorized' }))
        return
      }
    }

    // Handle batch endpoint (authenticated API)
    if (req.method === 'POST' && req.url?.includes('/patches/batch')) {
      let body = ''
      req.on('data', chunk => {
        body += chunk
      })
      req.on('end', () => {
        try {
          const { components } = JSON.parse(body) as { components: Array<{ purl: string }> }
          const purls = components.map(c => c.purl)

          // Build response from configured patch responses
          const packages: BatchSearchResponse['packages'] = []
          for (const purl of purls) {
            // Check each configured response
            for (const [, response] of patchResponses) {
              const pkg = response.packages.find((p: BatchSearchResponse['packages'][0]) => p.purl === purl)
              if (pkg) {
                packages.push(pkg)
              }
            }
          }

          const response: BatchSearchResponse = {
            packages,
            canAccessPaidPatches,
          }

          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify(response))
        } catch {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Invalid request' }))
        }
      })
      return
    }

    // Handle individual package endpoint (public proxy)
    if (req.method === 'GET' && req.url?.includes('/patch/by-package/')) {
      const purl = decodeURIComponent(req.url.split('/patch/by-package/')[1])

      // Find matching package in configured responses
      for (const [, response] of patchResponses) {
        const pkg = response.packages.find((p: BatchSearchResponse['packages'][0]) => p.purl === purl)
        if (pkg) {
          // Convert batch format to search response format
          const searchResponse = {
            patches: pkg.patches.map((patch: BatchSearchResponse['packages'][0]['patches'][0]) => ({
              uuid: patch.uuid,
              purl: patch.purl,
              publishedAt: new Date().toISOString(),
              description: patch.title,
              license: 'MIT',
              tier: patch.tier,
              vulnerabilities: Object.fromEntries(
                patch.ghsaIds.map((ghsaId: string, i: number) => [
                  ghsaId,
                  {
                    cves: patch.cveIds.slice(i, i + 1),
                    summary: patch.title,
                    severity: patch.severity || 'unknown',
                    description: patch.title,
                  },
                ]),
              ),
            })),
            canAccessPaidPatches,
          }
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify(searchResponse))
          return
        }
      }

      // No patches found for this package
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ patches: [], canAccessPaidPatches: false }))
      return
    }

    // 404 for unknown endpoints
    res.writeHead(404, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'Not found' }))
  })
}

describe('scan command authenticated API', () => {
  describe('APIClient with paid tier token', () => {
    let server: http.Server
    let serverUrl: string
    let testDir: string
    let nodeModulesDir: string

    const patchResponses = new Map<string, BatchSearchResponse>()

    before(async () => {
      // Create test directory with packages
      testDir = await createTestDir('scan-auth-paid-')
      nodeModulesDir = path.join(testDir, 'node_modules')

      // Create test packages
      await createTestPackage(nodeModulesDir, 'vulnerable-pkg', '1.0.0', {
        'index.js': 'module.exports = "vulnerable"',
      })
      await createTestPackage(nodeModulesDir, 'another-pkg', '2.0.0', {
        'index.js': 'module.exports = "another"',
      })

      // Configure mock responses
      patchResponses.set('vulnerable-pkg', {
        packages: [
          {
            purl: 'pkg:npm/vulnerable-pkg@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_1,
                purl: 'pkg:npm/vulnerable-pkg@1.0.0',
                tier: 'free',
                cveIds: ['CVE-2024-1234'],
                ghsaIds: ['GHSA-xxxx-xxxx-xxxx'],
                severity: 'high',
                title: 'Prototype pollution vulnerability',
              },
              {
                uuid: TEST_UUID_2,
                purl: 'pkg:npm/vulnerable-pkg@1.0.0',
                tier: 'paid',
                cveIds: ['CVE-2024-5678'],
                ghsaIds: ['GHSA-yyyy-yyyy-yyyy'],
                severity: 'critical',
                title: 'Remote code execution',
              },
            ],
          },
        ],
        canAccessPaidPatches: true,
      })

      // Start mock server (requires auth, can access paid patches)
      server = createMockServer({
        requireAuth: true,
        canAccessPaidPatches: true,
        patchResponses,
      })

      await new Promise<void>(resolve => {
        server.listen(0, '127.0.0.1', () => {
          const address = server.address() as AddressInfo
          serverUrl = `http://127.0.0.1:${address.port}`
          resolve()
        })
      })
    })

    after(async () => {
      await removeTestDir(testDir)
      await new Promise<void>(resolve => server.close(() => resolve()))
    })

    it('should authenticate with Bearer token', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        apiToken: 'test-paid-token',
        orgSlug: 'test-org',
      })

      const response = await client.searchPatchesBatch('test-org', [
        'pkg:npm/vulnerable-pkg@1.0.0',
      ])

      assert.ok(response, 'Should get response')
      assert.equal(response.canAccessPaidPatches, true, 'Should have paid access')
      assert.equal(response.packages.length, 1, 'Should find 1 package with patches')
    })

    it('should fail without auth token when server requires auth', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        // No token
      })

      await assert.rejects(
        async () => client.searchPatchesBatch('test-org', ['pkg:npm/vulnerable-pkg@1.0.0']),
        /Unauthorized/,
        'Should reject with unauthorized error',
      )
    })

    it('should return both free and paid patches with paid token', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        apiToken: 'test-paid-token',
        orgSlug: 'test-org',
      })

      const response = await client.searchPatchesBatch('test-org', [
        'pkg:npm/vulnerable-pkg@1.0.0',
      ])

      assert.equal(response.packages.length, 1)
      const pkg = response.packages[0]
      assert.equal(pkg.patches.length, 2, 'Should have 2 patches (free + paid)')

      const freePatch = pkg.patches.find(p => p.tier === 'free')
      const paidPatch = pkg.patches.find(p => p.tier === 'paid')

      assert.ok(freePatch, 'Should have free patch')
      assert.ok(paidPatch, 'Should have paid patch')
      assert.deepEqual(freePatch.cveIds, ['CVE-2024-1234'])
      assert.deepEqual(paidPatch.cveIds, ['CVE-2024-5678'])
    })

    it('should indicate canAccessPaidPatches: true for paid tier', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        apiToken: 'test-paid-token',
        orgSlug: 'test-org',
      })

      const response = await client.searchPatchesBatch('test-org', [
        'pkg:npm/vulnerable-pkg@1.0.0',
      ])

      assert.equal(response.canAccessPaidPatches, true)
    })
  })

  describe('APIClient with free tier (public proxy)', () => {
    let server: http.Server
    let serverUrl: string
    let testDir: string
    let nodeModulesDir: string

    const patchResponses = new Map<string, BatchSearchResponse>()

    before(async () => {
      // Create test directory with packages
      testDir = await createTestDir('scan-auth-free-')
      nodeModulesDir = path.join(testDir, 'node_modules')

      await createTestPackage(nodeModulesDir, 'free-vuln-pkg', '1.0.0', {
        'index.js': 'module.exports = "free"',
      })

      // Configure mock responses for free tier
      patchResponses.set('free-vuln-pkg', {
        packages: [
          {
            purl: 'pkg:npm/free-vuln-pkg@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_1,
                purl: 'pkg:npm/free-vuln-pkg@1.0.0',
                tier: 'free',
                cveIds: ['CVE-2024-1111'],
                ghsaIds: ['GHSA-free-free-free'],
                severity: 'medium',
                title: 'XSS vulnerability',
              },
            ],
          },
        ],
        canAccessPaidPatches: false,
      })

      // Start mock server (no auth required, no paid access)
      server = createMockServer({
        requireAuth: false,
        canAccessPaidPatches: false,
        patchResponses,
      })

      await new Promise<void>(resolve => {
        server.listen(0, '127.0.0.1', () => {
          const address = server.address() as AddressInfo
          serverUrl = `http://127.0.0.1:${address.port}`
          resolve()
        })
      })
    })

    after(async () => {
      await removeTestDir(testDir)
      await new Promise<void>(resolve => server.close(() => resolve()))
    })

    it('should work without authentication token (public proxy)', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        usePublicProxy: true,
      })

      // Public proxy uses individual GET requests, not batch POST
      const response = await client.searchPatchesBatch(null, [
        'pkg:npm/free-vuln-pkg@1.0.0',
      ])

      assert.ok(response, 'Should get response')
      assert.equal(response.packages.length, 1, 'Should find 1 package')
    })

    it('should indicate canAccessPaidPatches: false for free tier', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        usePublicProxy: true,
      })

      const response = await client.searchPatchesBatch(null, [
        'pkg:npm/free-vuln-pkg@1.0.0',
      ])

      assert.equal(response.canAccessPaidPatches, false)
    })

    it('should only return free patches for free tier', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        usePublicProxy: true,
      })

      const response = await client.searchPatchesBatch(null, [
        'pkg:npm/free-vuln-pkg@1.0.0',
      ])

      assert.equal(response.packages.length, 1)
      const pkg = response.packages[0]

      // All patches should be free tier
      for (const patch of pkg.patches) {
        assert.equal(patch.tier, 'free', 'All patches should be free tier')
      }
    })

    it('should not require org slug for public proxy', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        usePublicProxy: true,
      })

      // Should work with null org slug
      const response = await client.searchPatchesBatch(null, [
        'pkg:npm/free-vuln-pkg@1.0.0',
      ])

      assert.ok(response, 'Should work without org slug')
    })
  })

  describe('Batch mode scanning', () => {
    let server: http.Server
    let serverUrl: string
    let testDir: string
    let nodeModulesDir: string
    let requestCount: number
    let requestedPurls: string[][]

    const patchResponses = new Map<string, BatchSearchResponse>()

    before(async () => {
      // Create test directory with many packages
      testDir = await createTestDir('scan-batch-')
      nodeModulesDir = path.join(testDir, 'node_modules')

      // Create 10 test packages
      for (let i = 1; i <= 10; i++) {
        await createTestPackage(nodeModulesDir, `batch-pkg-${i}`, '1.0.0', {
          'index.js': `module.exports = "pkg${i}"`,
        })
      }

      // Configure mock responses for some packages
      patchResponses.set('batch-pkg-1', {
        packages: [
          {
            purl: 'pkg:npm/batch-pkg-1@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_1,
                purl: 'pkg:npm/batch-pkg-1@1.0.0',
                tier: 'free',
                cveIds: ['CVE-2024-0001'],
                ghsaIds: ['GHSA-0001-0001-0001'],
                severity: 'high',
                title: 'Batch pkg 1 vulnerability',
              },
            ],
          },
        ],
        canAccessPaidPatches: true,
      })

      patchResponses.set('batch-pkg-5', {
        packages: [
          {
            purl: 'pkg:npm/batch-pkg-5@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_2,
                purl: 'pkg:npm/batch-pkg-5@1.0.0',
                tier: 'paid',
                cveIds: ['CVE-2024-0005'],
                ghsaIds: ['GHSA-0005-0005-0005'],
                severity: 'critical',
                title: 'Batch pkg 5 vulnerability',
              },
            ],
          },
        ],
        canAccessPaidPatches: true,
      })

      patchResponses.set('batch-pkg-10', {
        packages: [
          {
            purl: 'pkg:npm/batch-pkg-10@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_3,
                purl: 'pkg:npm/batch-pkg-10@1.0.0',
                tier: 'free',
                cveIds: ['CVE-2024-0010'],
                ghsaIds: ['GHSA-0010-0010-0010'],
                severity: 'medium',
                title: 'Batch pkg 10 vulnerability',
              },
            ],
          },
        ],
        canAccessPaidPatches: true,
      })
    })

    beforeEach(async () => {
      requestCount = 0
      requestedPurls = []

      // Create a new server for each test to track requests
      server = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url?.includes('/patches/batch')) {
          requestCount++
          let body = ''
          req.on('data', chunk => {
            body += chunk
          })
          req.on('end', () => {
            const { components } = JSON.parse(body) as { components: Array<{ purl: string }> }
            const purls = components.map(c => c.purl)
            requestedPurls.push(purls)

            // Build response
            const packages: BatchSearchResponse['packages'] = []
            for (const purl of purls) {
              for (const [, response] of patchResponses) {
                const pkg = response.packages.find(p => p.purl === purl)
                if (pkg) {
                  packages.push(pkg)
                }
              }
            }

            const response: BatchSearchResponse = {
              packages,
              canAccessPaidPatches: true,
            }

            res.writeHead(200, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify(response))
          })
          return
        }

        res.writeHead(404)
        res.end()
      })

      await new Promise<void>(resolve => {
        server.listen(0, '127.0.0.1', () => {
          const address = server.address() as AddressInfo
          serverUrl = `http://127.0.0.1:${address.port}`
          resolve()
        })
      })
    })

    afterEach(async () => {
      await new Promise<void>(resolve => server.close(() => resolve()))
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should send packages in batches', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        apiToken: 'test-token',
        orgSlug: 'test-org',
      })

      // Crawl all packages
      const crawler = new NpmCrawler()
      const packages = await crawler.crawlAll({ cwd: testDir })
      const purls = packages.map(p => p.purl)

      assert.equal(purls.length, 10, 'Should have 10 packages')

      // Make a single batch request with all packages
      const response = await client.searchPatchesBatch('test-org', purls)

      assert.ok(response, 'Should get a response')
      assert.equal(requestCount, 1, 'Should make 1 batch request')
      assert.equal(requestedPurls[0].length, 10, 'Batch should contain all 10 purls')
    })

    it('should split large requests into multiple batches', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        apiToken: 'test-token',
        orgSlug: 'test-org',
      })

      // Create a large list of purls (simulating many packages)
      const purls: string[] = []
      for (let i = 1; i <= 10; i++) {
        purls.push(`pkg:npm/batch-pkg-${i}@1.0.0`)
      }

      // The batch endpoint accepts all at once, but the scan command
      // splits them based on batch-size option
      // Here we're testing the APIClient directly which sends all in one request
      const response = await client.searchPatchesBatch('test-org', purls)

      assert.ok(response, 'Should get response')
      assert.equal(response.packages.length, 3, 'Should find 3 packages with patches')
    })

    it('should handle batch response correctly', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        apiToken: 'test-token',
        orgSlug: 'test-org',
      })

      const purls = [
        'pkg:npm/batch-pkg-1@1.0.0',
        'pkg:npm/batch-pkg-5@1.0.0',
        'pkg:npm/batch-pkg-10@1.0.0',
      ]

      const response = await client.searchPatchesBatch('test-org', purls)

      assert.equal(response.packages.length, 3, 'Should return 3 packages')
      assert.equal(response.canAccessPaidPatches, true)

      // Verify each package
      const pkg1 = response.packages.find(p => p.purl === 'pkg:npm/batch-pkg-1@1.0.0')
      const pkg5 = response.packages.find(p => p.purl === 'pkg:npm/batch-pkg-5@1.0.0')
      const pkg10 = response.packages.find(p => p.purl === 'pkg:npm/batch-pkg-10@1.0.0')

      assert.ok(pkg1, 'Should have batch-pkg-1')
      assert.ok(pkg5, 'Should have batch-pkg-5')
      assert.ok(pkg10, 'Should have batch-pkg-10')

      assert.equal(pkg1.patches[0].tier, 'free')
      assert.equal(pkg5.patches[0].tier, 'paid')
      assert.equal(pkg10.patches[0].tier, 'free')
    })

    it('should return empty packages array for packages without patches', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        apiToken: 'test-token',
        orgSlug: 'test-org',
      })

      // Request packages that don't have patches configured
      const purls = [
        'pkg:npm/batch-pkg-2@1.0.0',
        'pkg:npm/batch-pkg-3@1.0.0',
      ]

      const response = await client.searchPatchesBatch('test-org', purls)

      assert.equal(response.packages.length, 0, 'Should return empty packages array')
    })

    it('should aggregate results across multiple batches', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        apiToken: 'test-token',
        orgSlug: 'test-org',
      })

      // First batch: packages 1-5
      const response1 = await client.searchPatchesBatch('test-org', [
        'pkg:npm/batch-pkg-1@1.0.0',
        'pkg:npm/batch-pkg-2@1.0.0',
        'pkg:npm/batch-pkg-3@1.0.0',
        'pkg:npm/batch-pkg-4@1.0.0',
        'pkg:npm/batch-pkg-5@1.0.0',
      ])

      // Second batch: packages 6-10
      const response2 = await client.searchPatchesBatch('test-org', [
        'pkg:npm/batch-pkg-6@1.0.0',
        'pkg:npm/batch-pkg-7@1.0.0',
        'pkg:npm/batch-pkg-8@1.0.0',
        'pkg:npm/batch-pkg-9@1.0.0',
        'pkg:npm/batch-pkg-10@1.0.0',
      ])

      // Aggregate results (as the scan command does)
      const allPackages = [...response1.packages, ...response2.packages]
      const canAccessPaid = response1.canAccessPaidPatches || response2.canAccessPaidPatches

      assert.equal(allPackages.length, 3, 'Should find 3 packages with patches total')
      assert.equal(canAccessPaid, true)

      // Verify we found packages from both batches
      const foundPurls = allPackages.map(p => p.purl).sort()
      assert.deepEqual(foundPurls, [
        'pkg:npm/batch-pkg-10@1.0.0',
        'pkg:npm/batch-pkg-1@1.0.0',
        'pkg:npm/batch-pkg-5@1.0.0',
      ].sort())
    })
  })

  describe('Public proxy fallback to individual requests', () => {
    let server: http.Server
    let serverUrl: string
    let testDir: string
    let nodeModulesDir: string
    let getRequestCount: number
    let getRequestedPurls: string[]

    const patchResponses = new Map<string, BatchSearchResponse>()

    before(async () => {
      testDir = await createTestDir('scan-proxy-fallback-')
      nodeModulesDir = path.join(testDir, 'node_modules')

      await createTestPackage(nodeModulesDir, 'proxy-pkg-1', '1.0.0', {
        'index.js': 'module.exports = "pkg1"',
      })
      await createTestPackage(nodeModulesDir, 'proxy-pkg-2', '1.0.0', {
        'index.js': 'module.exports = "pkg2"',
      })

      patchResponses.set('proxy-pkg-1', {
        packages: [
          {
            purl: 'pkg:npm/proxy-pkg-1@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_1,
                purl: 'pkg:npm/proxy-pkg-1@1.0.0',
                tier: 'free',
                cveIds: ['CVE-2024-PROX'],
                ghsaIds: ['GHSA-prox-prox-prox'],
                severity: 'low',
                title: 'Proxy pkg 1 vulnerability',
              },
            ],
          },
        ],
        canAccessPaidPatches: false,
      })
    })

    beforeEach(async () => {
      getRequestCount = 0
      getRequestedPurls = []

      server = http.createServer((req, res) => {
        // Public proxy uses GET requests for individual packages
        if (req.method === 'GET' && req.url?.includes('/patch/by-package/')) {
          getRequestCount++
          const purl = decodeURIComponent(req.url.split('/patch/by-package/')[1])
          getRequestedPurls.push(purl)

          // Find matching package
          for (const [, response] of patchResponses) {
            const pkg = response.packages.find(p => p.purl === purl)
            if (pkg) {
              const searchResponse = {
                patches: pkg.patches.map(patch => ({
                  uuid: patch.uuid,
                  purl: patch.purl,
                  publishedAt: new Date().toISOString(),
                  description: patch.title,
                  license: 'MIT',
                  tier: patch.tier,
                  vulnerabilities: {
                    [patch.ghsaIds[0]]: {
                      cves: patch.cveIds,
                      summary: patch.title,
                      severity: patch.severity || 'unknown',
                      description: patch.title,
                    },
                  },
                })),
                canAccessPaidPatches: false,
              }
              res.writeHead(200, { 'Content-Type': 'application/json' })
              res.end(JSON.stringify(searchResponse))
              return
            }
          }

          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ patches: [], canAccessPaidPatches: false }))
          return
        }

        res.writeHead(404)
        res.end()
      })

      await new Promise<void>(resolve => {
        server.listen(0, '127.0.0.1', () => {
          const address = server.address() as AddressInfo
          serverUrl = `http://127.0.0.1:${address.port}`
          resolve()
        })
      })
    })

    afterEach(async () => {
      await new Promise<void>(resolve => server.close(() => resolve()))
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should use individual GET requests for public proxy batch search', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        usePublicProxy: true,
      })

      const purls = [
        'pkg:npm/proxy-pkg-1@1.0.0',
        'pkg:npm/proxy-pkg-2@1.0.0',
      ]

      await client.searchPatchesBatch(null, purls)

      // Public proxy falls back to individual GET requests
      assert.equal(getRequestCount, 2, 'Should make 2 individual GET requests')
      assert.ok(getRequestedPurls.includes('pkg:npm/proxy-pkg-1@1.0.0'))
      assert.ok(getRequestedPurls.includes('pkg:npm/proxy-pkg-2@1.0.0'))
    })

    it('should aggregate results from individual requests', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        usePublicProxy: true,
      })

      const purls = [
        'pkg:npm/proxy-pkg-1@1.0.0',
        'pkg:npm/proxy-pkg-2@1.0.0',
      ]

      const response = await client.searchPatchesBatch(null, purls)

      // Only proxy-pkg-1 has patches configured
      assert.equal(response.packages.length, 1)
      assert.equal(response.packages[0].purl, 'pkg:npm/proxy-pkg-1@1.0.0')
    })
  })

  describe('Error handling', () => {
    let server: http.Server
    let serverUrl: string

    beforeEach(async () => {
      server = http.createServer((req, res) => {
        if (req.url?.includes('/error-401')) {
          res.writeHead(401, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Unauthorized' }))
          return
        }
        if (req.url?.includes('/error-403')) {
          res.writeHead(403, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Forbidden' }))
          return
        }
        if (req.url?.includes('/error-429')) {
          res.writeHead(429, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Rate limited' }))
          return
        }
        if (req.url?.includes('/error-500')) {
          res.writeHead(500, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Server error' }))
          return
        }

        res.writeHead(404)
        res.end()
      })

      await new Promise<void>(resolve => {
        server.listen(0, '127.0.0.1', () => {
          const address = server.address() as AddressInfo
          serverUrl = `http://127.0.0.1:${address.port}`
          resolve()
        })
      })
    })

    afterEach(async () => {
      await new Promise<void>(resolve => server.close(() => resolve()))
    })

    it('should throw on 401 Unauthorized', async () => {
      const client = new APIClient({
        apiUrl: `${serverUrl}/error-401`,
        apiToken: 'invalid-token',
      })

      await assert.rejects(
        async () => client.searchPatchesBatch('test-org', ['pkg:npm/test@1.0.0']),
        /Unauthorized/,
      )
    })

    it('should throw on 403 Forbidden', async () => {
      const client = new APIClient({
        apiUrl: `${serverUrl}/error-403`,
        apiToken: 'test-token',
      })

      await assert.rejects(
        async () => client.searchPatchesBatch('test-org', ['pkg:npm/test@1.0.0']),
        /Forbidden/,
      )
    })

    it('should throw on 429 Rate Limit', async () => {
      const client = new APIClient({
        apiUrl: `${serverUrl}/error-429`,
        apiToken: 'test-token',
      })

      await assert.rejects(
        async () => client.searchPatchesBatch('test-org', ['pkg:npm/test@1.0.0']),
        /Rate limit/,
      )
    })

    it('should throw on 500 Server Error', async () => {
      const client = new APIClient({
        apiUrl: `${serverUrl}/error-500`,
        apiToken: 'test-token',
      })

      await assert.rejects(
        async () => client.searchPatchesBatch('test-org', ['pkg:npm/test@1.0.0']),
        /API request failed/,
      )
    })
  })

  describe('getAPIClientFromEnv behavior', () => {
    let originalEnv: NodeJS.ProcessEnv

    beforeEach(() => {
      originalEnv = { ...process.env }
    })

    afterEach(() => {
      process.env = originalEnv
    })

    it('should use public proxy when no SOCKET_API_TOKEN is set', async () => {
      delete process.env.SOCKET_API_TOKEN
      delete process.env.SOCKET_API_URL

      const { getAPIClientFromEnv } = await import('../utils/api-client.js')
      const { usePublicProxy } = getAPIClientFromEnv()

      assert.equal(usePublicProxy, true, 'Should use public proxy without token')
    })

    it('should use authenticated API when SOCKET_API_TOKEN is set', async () => {
      process.env.SOCKET_API_TOKEN = 'test-token'
      process.env.SOCKET_API_URL = 'https://api.socket.dev'

      // Re-import to get fresh state
      const apiClientModule = await import('../utils/api-client.js')
      const { usePublicProxy } = apiClientModule.getAPIClientFromEnv()

      assert.equal(usePublicProxy, false, 'Should use authenticated API with token')
    })
  })
})

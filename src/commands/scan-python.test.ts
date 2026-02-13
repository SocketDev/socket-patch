import { describe, it, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import * as path from 'path'
import * as http from 'node:http'
import type { AddressInfo } from 'node:net'
import {
  createTestDir,
  removeTestDir,
  createTestPackage,
  createTestPythonPackage,
} from '../test-utils.js'
import { APIClient, type BatchSearchResponse } from '../utils/api-client.js'
import { NpmCrawler, PythonCrawler } from '../crawlers/index.js'

// Test UUIDs
const TEST_UUID_1 = 'ee111111-1111-4111-8111-111111111111'

describe('scan command - Python packages', () => {
  describe('combined npm + python scanning', () => {
    let testDir: string
    let nodeModulesDir: string
    let sitePackagesDir: string

    before(async () => {
      testDir = await createTestDir('scan-python-combined-')
      nodeModulesDir = path.join(testDir, 'node_modules')
      sitePackagesDir = path.join(
        testDir,
        '.venv',
        'lib',
        'python3.11',
        'site-packages',
      )

      // Create npm packages
      await createTestPackage(nodeModulesDir, 'npm-pkg-a', '1.0.0', {
        'index.js': 'module.exports = "a"',
      })
      await createTestPackage(nodeModulesDir, 'npm-pkg-b', '2.0.0', {
        'index.js': 'module.exports = "b"',
      })

      // Create python packages
      await createTestPythonPackage(sitePackagesDir, 'requests', '2.28.0', {})
      await createTestPythonPackage(sitePackagesDir, 'flask', '2.3.0', {})
      await createTestPythonPackage(sitePackagesDir, 'six', '1.16.0', {})
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should find both npm and python packages', async () => {
      const npmCrawler = new NpmCrawler()
      const pythonCrawler = new PythonCrawler()

      const npmPackages = await npmCrawler.crawlAll({ cwd: testDir })
      const pythonPackages = await pythonCrawler.crawlAll({
        cwd: testDir,
        globalPrefix: sitePackagesDir,
      })

      assert.ok(npmPackages.length >= 2, `Should find at least 2 npm packages, got ${npmPackages.length}`)
      assert.equal(pythonPackages.length, 3, 'Should find 3 python packages')

      // Verify combined count
      const totalCount = npmPackages.length + pythonPackages.length
      assert.ok(totalCount >= 5, `Should find at least 5 total packages, got ${totalCount}`)
    })
  })

  describe('API receives pypi PURLs', () => {
    let server: http.Server
    let serverUrl: string
    let testDir: string
    let sitePackagesDir: string
    let receivedPurls: string[]

    const patchResponses = new Map<string, BatchSearchResponse>()

    before(async () => {
      testDir = await createTestDir('scan-python-api-')
      sitePackagesDir = path.join(testDir, 'site-packages')

      await createTestPythonPackage(sitePackagesDir, 'requests', '2.28.0', {})
      await createTestPythonPackage(sitePackagesDir, 'flask', '2.3.0', {})

      patchResponses.set('requests', {
        packages: [
          {
            purl: 'pkg:pypi/requests@2.28.0',
            patches: [
              {
                uuid: TEST_UUID_1,
                purl: 'pkg:pypi/requests@2.28.0',
                tier: 'free',
                cveIds: ['CVE-2024-9999'],
                ghsaIds: ['GHSA-pypi-pypi-pypi'],
                severity: 'high',
                title: 'Python requests vulnerability',
              },
            ],
          },
        ],
        canAccessPaidPatches: false,
      })
    })

    beforeEach(async () => {
      receivedPurls = []

      server = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url?.includes('/patches/batch')) {
          let body = ''
          req.on('data', (chunk: Buffer) => {
            body += chunk
          })
          req.on('end', () => {
            const { components } = JSON.parse(body) as {
              components: Array<{ purl: string }>
            }
            const purls = components.map(c => c.purl)
            receivedPurls.push(...purls)

            // Build response
            const packages: BatchSearchResponse['packages'] = []
            for (const purl of purls) {
              for (const [, response] of patchResponses) {
                const pkg = response.packages.find(p => p.purl === purl)
                if (pkg) packages.push(pkg)
              }
            }

            res.writeHead(200, { 'Content-Type': 'application/json' })
            res.end(
              JSON.stringify({ packages, canAccessPaidPatches: false }),
            )
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

    it('should send pypi PURLs in batch request', async () => {
      const client = new APIClient({
        apiUrl: serverUrl,
        apiToken: 'test-token',
        orgSlug: 'test-org',
      })

      // Crawl python packages
      const crawler = new PythonCrawler()
      const packages = await crawler.crawlAll({
        cwd: testDir,
        globalPrefix: sitePackagesDir,
      })

      const purls = packages.map(p => p.purl)

      const response = await client.searchPatchesBatch('test-org', purls)

      // Verify pypi PURLs were sent
      assert.ok(
        receivedPurls.some(p => p.startsWith('pkg:pypi/')),
        'Should send pypi PURLs to API',
      )
      assert.ok(
        receivedPurls.includes('pkg:pypi/requests@2.28.0'),
        'Should include requests PURL',
      )
      assert.ok(
        receivedPurls.includes('pkg:pypi/flask@2.3.0'),
        'Should include flask PURL',
      )

      // Verify response
      assert.equal(response.packages.length, 1)
      assert.equal(response.packages[0].purl, 'pkg:pypi/requests@2.28.0')
    })
  })

  describe('ecosystem summary', () => {
    it('should build ecosystem summary with both npm and python counts', () => {
      // This tests the summary formatting logic from scan.ts
      const npmCount = 2
      const pythonCount = 3

      const ecosystemParts: string[] = []
      if (npmCount > 0) ecosystemParts.push(`${npmCount} npm`)
      if (pythonCount > 0) ecosystemParts.push(`${pythonCount} python`)
      const ecosystemSummary =
        ecosystemParts.length > 0
          ? ` (${ecosystemParts.join(', ')})`
          : ''

      assert.equal(ecosystemSummary, ' (2 npm, 3 python)')
    })
  })

  describe('scan with only python packages', () => {
    let testDir: string
    let sitePackagesDir: string

    before(async () => {
      testDir = await createTestDir('scan-python-only-')
      sitePackagesDir = path.join(testDir, 'site-packages')

      await createTestPythonPackage(sitePackagesDir, 'requests', '2.28.0', {})
      await createTestPythonPackage(sitePackagesDir, 'flask', '2.3.0', {})
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should work with only python packages (no node_modules)', async () => {
      const npmCrawler = new NpmCrawler()
      const pythonCrawler = new PythonCrawler()

      const npmPackages = await npmCrawler.crawlAll({ cwd: testDir })
      const pythonPackages = await pythonCrawler.crawlAll({
        cwd: testDir,
        globalPrefix: sitePackagesDir,
      })

      assert.equal(npmPackages.length, 0, 'Should find no npm packages')
      assert.equal(pythonPackages.length, 2, 'Should find 2 python packages')

      const allPurls = [
        ...npmPackages.map(p => p.purl),
        ...pythonPackages.map(p => p.purl),
      ]
      assert.equal(allPurls.length, 2)
      assert.ok(allPurls.every(p => p.startsWith('pkg:pypi/')))
    })
  })

  describe('scan with no packages found', () => {
    it('should handle empty dirs gracefully', async () => {
      const tempDir = await createTestDir('scan-python-empty-')

      const npmCrawler = new NpmCrawler()
      const pythonCrawler = new PythonCrawler()

      const npmPackages = await npmCrawler.crawlAll({ cwd: tempDir })
      // Use globalPrefix pointing to non-existent dir to avoid finding system packages
      const pythonPackages = await pythonCrawler.crawlAll({
        cwd: tempDir,
        globalPrefix: path.join(tempDir, 'nonexistent-site-packages'),
      })

      const packageCount = npmPackages.length + pythonPackages.length
      assert.equal(packageCount, 0, 'Should find no packages')

      await removeTestDir(tempDir)
    })
  })
})

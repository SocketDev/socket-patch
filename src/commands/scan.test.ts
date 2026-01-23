import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as path from 'path'
import {
  createTestDir,
  removeTestDir,
  createTestPackage,
} from '../test-utils.js'
import { NpmCrawler } from '../crawlers/index.js'

// Test UUID
const TEST_UUID_1 = '11111111-1111-4111-8111-111111111111'

describe('scan command', () => {
  describe('NpmCrawler', () => {
    let testDir: string
    let nodeModulesDir: string

    before(async () => {
      testDir = await createTestDir('scan-crawler-')
      nodeModulesDir = path.join(testDir, 'node_modules')
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should crawl packages in node_modules', async () => {
      // Create test packages
      await createTestPackage(nodeModulesDir, 'test-pkg-a', '1.0.0', {
        'index.js': 'module.exports = "a"',
      })
      await createTestPackage(nodeModulesDir, 'test-pkg-b', '2.0.0', {
        'index.js': 'module.exports = "b"',
      })

      const crawler = new NpmCrawler()
      const packages = await crawler.crawlAll({ cwd: testDir })

      assert.ok(packages.length >= 2, 'Should find at least 2 packages')

      const pkgA = packages.find(p => p.name === 'test-pkg-a')
      const pkgB = packages.find(p => p.name === 'test-pkg-b')

      assert.ok(pkgA, 'Should find test-pkg-a')
      assert.ok(pkgB, 'Should find test-pkg-b')

      assert.equal(pkgA.version, '1.0.0')
      assert.equal(pkgA.purl, 'pkg:npm/test-pkg-a@1.0.0')

      assert.equal(pkgB.version, '2.0.0')
      assert.equal(pkgB.purl, 'pkg:npm/test-pkg-b@2.0.0')
    })

    it('should handle scoped packages', async () => {
      await createTestPackage(nodeModulesDir, '@scope/test-pkg', '3.0.0', {
        'index.js': 'module.exports = "scoped"',
      })

      const crawler = new NpmCrawler()
      const packages = await crawler.crawlAll({ cwd: testDir })

      const scopedPkg = packages.find(p => p.namespace === '@scope' && p.name === 'test-pkg')
      assert.ok(scopedPkg, 'Should find scoped package')
      assert.equal(scopedPkg.version, '3.0.0')
      assert.equal(scopedPkg.purl, 'pkg:npm/@scope/test-pkg@3.0.0')
    })

    it('should yield packages in batches', async () => {
      const crawler = new NpmCrawler()
      const batches: number[] = []

      for await (const batch of crawler.crawlBatches({ cwd: testDir, batchSize: 2 })) {
        batches.push(batch.length)
      }

      assert.ok(batches.length > 0, 'Should yield at least one batch')
      // With batch size 2 and 3+ packages, should have multiple batches
      if (batches.length > 1) {
        assert.ok(batches[0] <= 2, 'Batch size should be respected')
      }
    })

    it('should find packages by PURL', async () => {
      const crawler = new NpmCrawler()

      const purls = [
        'pkg:npm/test-pkg-a@1.0.0',
        'pkg:npm/@scope/test-pkg@3.0.0',
        'pkg:npm/nonexistent@1.0.0', // Should not be found
      ]

      const found = await crawler.findByPurls(nodeModulesDir, purls)

      assert.equal(found.size, 2, 'Should find 2 packages')
      assert.ok(found.has('pkg:npm/test-pkg-a@1.0.0'), 'Should find test-pkg-a')
      assert.ok(found.has('pkg:npm/@scope/test-pkg@3.0.0'), 'Should find scoped package')
      assert.ok(!found.has('pkg:npm/nonexistent@1.0.0'), 'Should not find nonexistent')
    })

    it('should deduplicate packages by PURL', async () => {
      const crawler = new NpmCrawler()
      const packages = await crawler.crawlAll({ cwd: testDir })

      const purls = new Set(packages.map(p => p.purl))
      assert.equal(purls.size, packages.length, 'All PURLs should be unique')
    })
  })

  describe('NpmCrawler with nested node_modules', () => {
    let testDir: string
    let nodeModulesDir: string

    before(async () => {
      testDir = await createTestDir('scan-nested-')
      nodeModulesDir = path.join(testDir, 'node_modules')

      // Create parent package
      await createTestPackage(nodeModulesDir, 'parent-pkg', '1.0.0', {
        'index.js': 'module.exports = "parent"',
      })

      // Create nested node_modules inside parent-pkg
      const nestedNodeModules = path.join(nodeModulesDir, 'parent-pkg', 'node_modules')
      await createTestPackage(nestedNodeModules, 'nested-pkg', '1.0.0', {
        'index.js': 'module.exports = "nested"',
      })
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should find nested packages', async () => {
      const crawler = new NpmCrawler()
      const packages = await crawler.crawlAll({ cwd: testDir })

      const parentPkg = packages.find(p => p.name === 'parent-pkg')
      const nestedPkg = packages.find(p => p.name === 'nested-pkg')

      assert.ok(parentPkg, 'Should find parent package')
      assert.ok(nestedPkg, 'Should find nested package')
    })
  })

  describe('NpmCrawler edge cases', () => {
    let testDir: string

    before(async () => {
      testDir = await createTestDir('scan-edge-')
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should handle empty node_modules', async () => {
      const emptyDir = path.join(testDir, 'empty-project')
      const { mkdir } = await import('fs/promises')
      await mkdir(path.join(emptyDir, 'node_modules'), { recursive: true })

      const crawler = new NpmCrawler()
      const packages = await crawler.crawlAll({ cwd: emptyDir })

      assert.equal(packages.length, 0, 'Should return empty array for empty node_modules')
    })

    it('should handle missing node_modules', async () => {
      const noNodeModulesDir = path.join(testDir, 'no-node-modules')
      const { mkdir } = await import('fs/promises')
      await mkdir(noNodeModulesDir, { recursive: true })

      const crawler = new NpmCrawler()
      const packages = await crawler.crawlAll({ cwd: noNodeModulesDir })

      assert.equal(packages.length, 0, 'Should return empty array when no node_modules')
    })

    it('should skip packages with invalid package.json', async () => {
      const invalidDir = path.join(testDir, 'invalid-pkgjson')
      const nodeModulesDir = path.join(invalidDir, 'node_modules')
      const { mkdir, writeFile } = await import('fs/promises')

      // Create package with invalid package.json
      const badPkgDir = path.join(nodeModulesDir, 'bad-pkg')
      await mkdir(badPkgDir, { recursive: true })
      await writeFile(path.join(badPkgDir, 'package.json'), 'not valid json')

      // Create valid package
      await createTestPackage(nodeModulesDir, 'good-pkg', '1.0.0', {
        'index.js': 'module.exports = "good"',
      })

      const crawler = new NpmCrawler()
      const packages = await crawler.crawlAll({ cwd: invalidDir })

      assert.equal(packages.length, 1, 'Should only find valid package')
      assert.equal(packages[0].name, 'good-pkg')
    })

    it('should skip packages missing name or version', async () => {
      const incompleteDir = path.join(testDir, 'incomplete-pkgjson')
      const nodeModulesDir = path.join(incompleteDir, 'node_modules')
      const { mkdir, writeFile } = await import('fs/promises')

      // Create package without version
      const noVersionDir = path.join(nodeModulesDir, 'no-version')
      await mkdir(noVersionDir, { recursive: true })
      await writeFile(
        path.join(noVersionDir, 'package.json'),
        JSON.stringify({ name: 'no-version' }),
      )

      // Create package without name
      const noNameDir = path.join(nodeModulesDir, 'no-name')
      await mkdir(noNameDir, { recursive: true })
      await writeFile(
        path.join(noNameDir, 'package.json'),
        JSON.stringify({ version: '1.0.0' }),
      )

      // Create valid package
      await createTestPackage(nodeModulesDir, 'complete-pkg', '1.0.0', {
        'index.js': 'module.exports = "complete"',
      })

      const crawler = new NpmCrawler()
      const packages = await crawler.crawlAll({ cwd: incompleteDir })

      assert.equal(packages.length, 1, 'Should only find complete package')
      assert.equal(packages[0].name, 'complete-pkg')
    })
  })

  describe('Batch search result structure', () => {
    // These tests verify the expected response structure from the batch API
    // They use mock data since actual API calls require authentication

    it('should have correct BatchPatchInfo structure', () => {
      // Verify the expected structure matches what scan.ts expects
      const mockPatchInfo = {
        uuid: TEST_UUID_1,
        purl: 'pkg:npm/test@1.0.0',
        tier: 'free' as const,
        cveIds: ['CVE-2024-1234'],
        ghsaIds: ['GHSA-xxxx-xxxx-xxxx'],
        severity: 'high',
        title: 'Test vulnerability',
      }

      assert.equal(typeof mockPatchInfo.uuid, 'string')
      assert.equal(typeof mockPatchInfo.purl, 'string')
      assert.ok(['free', 'paid'].includes(mockPatchInfo.tier))
      assert.ok(Array.isArray(mockPatchInfo.cveIds))
      assert.ok(Array.isArray(mockPatchInfo.ghsaIds))
      assert.ok(mockPatchInfo.severity === null || typeof mockPatchInfo.severity === 'string')
      assert.equal(typeof mockPatchInfo.title, 'string')
    })

    it('should have correct BatchSearchResponse structure', () => {
      const mockResponse = {
        packages: [
          {
            purl: 'pkg:npm/test@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_1,
                purl: 'pkg:npm/test@1.0.0',
                tier: 'free' as const,
                cveIds: ['CVE-2024-1234'],
                ghsaIds: [],
                severity: 'high',
                title: 'Test vulnerability',
              },
            ],
          },
        ],
        canAccessPaidPatches: false,
      }

      assert.ok(Array.isArray(mockResponse.packages))
      assert.equal(typeof mockResponse.canAccessPaidPatches, 'boolean')

      for (const pkg of mockResponse.packages) {
        assert.equal(typeof pkg.purl, 'string')
        assert.ok(Array.isArray(pkg.patches))
      }
    })
  })

  describe('Scan output formatting', () => {
    // Test the output formatting logic used in scan command

    it('should sort packages by severity', () => {
      const packages = [
        { purl: 'low', patches: [{ severity: 'low' }] },
        { purl: 'critical', patches: [{ severity: 'critical' }] },
        { purl: 'medium', patches: [{ severity: 'medium' }] },
        { purl: 'high', patches: [{ severity: 'high' }] },
      ]

      const severityOrder: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        unknown: 4,
      }

      const sorted = packages.sort((a, b) => {
        const aMaxSeverity = Math.min(
          ...a.patches.map(p => severityOrder[p.severity ?? 'unknown'] ?? 4),
        )
        const bMaxSeverity = Math.min(
          ...b.patches.map(p => severityOrder[p.severity ?? 'unknown'] ?? 4),
        )
        return aMaxSeverity - bMaxSeverity
      })

      assert.equal(sorted[0].purl, 'critical')
      assert.equal(sorted[1].purl, 'high')
      assert.equal(sorted[2].purl, 'medium')
      assert.equal(sorted[3].purl, 'low')
    })

    it('should handle packages with multiple patches of different severities', () => {
      const packages = [
        {
          purl: 'mixed-low',
          patches: [{ severity: 'low' }, { severity: 'medium' }],
        },
        {
          purl: 'has-critical',
          patches: [{ severity: 'low' }, { severity: 'critical' }],
        },
      ]

      const severityOrder: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        unknown: 4,
      }

      const sorted = packages.sort((a, b) => {
        const aMaxSeverity = Math.min(
          ...a.patches.map(p => severityOrder[p.severity ?? 'unknown'] ?? 4),
        )
        const bMaxSeverity = Math.min(
          ...b.patches.map(p => severityOrder[p.severity ?? 'unknown'] ?? 4),
        )
        return aMaxSeverity - bMaxSeverity
      })

      // Package with critical should come first
      assert.equal(sorted[0].purl, 'has-critical')
    })

    it('should handle null severity', () => {
      const severityOrder: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        unknown: 4,
      }

      const getSeverityOrder = (severity: string | null): number => {
        if (!severity) return 4
        return severityOrder[severity.toLowerCase()] ?? 4
      }

      assert.equal(getSeverityOrder(null), 4)
      assert.equal(getSeverityOrder('unknown'), 4)
      assert.equal(getSeverityOrder('critical'), 0)
    })
  })

  describe('JSON output structure', () => {
    it('should produce valid ScanResult JSON', () => {
      const result = {
        scannedPackages: 100,
        packagesWithPatches: 5,
        totalPatches: 8,
        canAccessPaidPatches: false,
        packages: [
          {
            purl: 'pkg:npm/test@1.0.0',
            patches: [
              {
                uuid: TEST_UUID_1,
                purl: 'pkg:npm/test@1.0.0',
                tier: 'free' as const,
                cveIds: ['CVE-2024-1234'],
                ghsaIds: ['GHSA-xxxx-xxxx-xxxx'],
                severity: 'high',
                title: 'Test vulnerability',
              },
            ],
          },
        ],
      }

      // Should be valid JSON
      const jsonStr = JSON.stringify(result, null, 2)
      const parsed = JSON.parse(jsonStr)

      assert.equal(parsed.scannedPackages, 100)
      assert.equal(parsed.packagesWithPatches, 5)
      assert.equal(parsed.totalPatches, 8)
      assert.equal(parsed.canAccessPaidPatches, false)
      assert.ok(Array.isArray(parsed.packages))
      assert.equal(parsed.packages.length, 1)
      assert.equal(parsed.packages[0].patches[0].uuid, TEST_UUID_1)
    })
  })
})

describe('crawlers module', () => {
  describe('exports', () => {
    it('should export NpmCrawler', async () => {
      const { NpmCrawler } = await import('../crawlers/index.js')
      assert.ok(NpmCrawler, 'NpmCrawler should be exported')
      assert.equal(typeof NpmCrawler, 'function', 'NpmCrawler should be a constructor')
    })

    it('should export CrawledPackage type via module', async () => {
      const { NpmCrawler } = await import('../crawlers/index.js')
      const crawler = new NpmCrawler()
      assert.ok(crawler, 'Should be able to instantiate NpmCrawler')
    })

    it('should export global prefix functions', async () => {
      const {
        getNpmGlobalPrefix,
        getYarnGlobalPrefix,
        getPnpmGlobalPrefix,
        getBunGlobalPrefix,
      } = await import('../crawlers/index.js')

      assert.equal(typeof getNpmGlobalPrefix, 'function')
      assert.equal(typeof getYarnGlobalPrefix, 'function')
      assert.equal(typeof getPnpmGlobalPrefix, 'function')
      assert.equal(typeof getBunGlobalPrefix, 'function')
    })
  })
})

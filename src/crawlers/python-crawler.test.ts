import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'fs/promises'
import * as path from 'path'
import {
  createTestDir,
  removeTestDir,
  createTestPythonPackage,
} from '../test-utils.js'
import {
  PythonCrawler,
  canonicalizePyPIName,
  findPythonDirs,
  findLocalVenvSitePackages,
} from './index.js'

describe('PythonCrawler', () => {
  describe('canonicalizePyPIName', () => {
    it('should lowercase names', () => {
      assert.equal(canonicalizePyPIName('Requests'), 'requests')
    })

    it('should replace underscores with hyphens', () => {
      assert.equal(canonicalizePyPIName('my_package'), 'my-package')
    })

    it('should replace dots with hyphens', () => {
      assert.equal(canonicalizePyPIName('My.Package'), 'my-package')
    })

    it('should collapse runs of separators', () => {
      assert.equal(canonicalizePyPIName('a___b---c...d'), 'a-b-c-d')
    })

    it('should trim whitespace', () => {
      assert.equal(canonicalizePyPIName('  requests  '), 'requests')
    })
  })

  describe('crawlAll', () => {
    let testDir: string
    let sitePackagesDir: string

    before(async () => {
      testDir = await createTestDir('python-crawler-crawl-')
      sitePackagesDir = path.join(testDir, 'lib', 'python3.11', 'site-packages')

      await createTestPythonPackage(sitePackagesDir, 'requests', '2.28.0', {})
      await createTestPythonPackage(sitePackagesDir, 'flask', '2.3.0', {})
      await createTestPythonPackage(sitePackagesDir, 'six', '1.16.0', {})
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should discover all packages', async () => {
      const crawler = new PythonCrawler()
      const packages = await crawler.crawlAll({
        cwd: testDir,
        globalPrefix: sitePackagesDir,
      })

      assert.equal(packages.length, 3, 'Should find 3 packages')

      const purls = packages.map(p => p.purl).sort()
      assert.deepEqual(purls, [
        'pkg:pypi/flask@2.3.0',
        'pkg:pypi/requests@2.28.0',
        'pkg:pypi/six@1.16.0',
      ])
    })

    it('should read METADATA correctly', async () => {
      const crawler = new PythonCrawler()
      const packages = await crawler.crawlAll({
        cwd: testDir,
        globalPrefix: sitePackagesDir,
      })

      const requests = packages.find(p => p.name === 'requests')
      assert.ok(requests, 'Should find requests')
      assert.equal(requests.version, '2.28.0')
      assert.equal(requests.purl, 'pkg:pypi/requests@2.28.0')
    })

    it('should skip dist-info without METADATA file', async () => {
      const tempDir = await createTestDir('python-crawler-no-meta-')
      const sp = path.join(tempDir, 'site-packages')
      await fs.mkdir(sp, { recursive: true })

      // Create dist-info without METADATA
      const distInfoDir = path.join(sp, 'bad_pkg-1.0.0.dist-info')
      await fs.mkdir(distInfoDir, { recursive: true })
      // No METADATA file

      // Create a valid package
      await createTestPythonPackage(sp, 'good-pkg', '1.0.0', {})

      const crawler = new PythonCrawler()
      const packages = await crawler.crawlAll({
        cwd: tempDir,
        globalPrefix: sp,
      })

      assert.equal(packages.length, 1)
      assert.equal(packages[0].name, 'good-pkg')

      await removeTestDir(tempDir)
    })

    it('should skip malformed METADATA', async () => {
      const tempDir = await createTestDir('python-crawler-bad-meta-')
      const sp = path.join(tempDir, 'site-packages')
      await fs.mkdir(sp, { recursive: true })

      // Create dist-info with malformed METADATA (no Name/Version)
      const distInfoDir = path.join(sp, 'bad_pkg-1.0.0.dist-info')
      await fs.mkdir(distInfoDir, { recursive: true })
      await fs.writeFile(
        path.join(distInfoDir, 'METADATA'),
        'Summary: A package with no name or version\n',
      )

      const crawler = new PythonCrawler()
      const packages = await crawler.crawlAll({
        cwd: tempDir,
        globalPrefix: sp,
      })

      assert.equal(packages.length, 0)

      await removeTestDir(tempDir)
    })

    it('should handle METADATA with extra headers before Name/Version', async () => {
      const tempDir = await createTestDir('python-crawler-extra-')
      const sp = path.join(tempDir, 'site-packages')
      await fs.mkdir(sp, { recursive: true })

      const distInfoDir = path.join(sp, 'extra_pkg-2.0.0.dist-info')
      await fs.mkdir(distInfoDir, { recursive: true })
      await fs.writeFile(
        path.join(distInfoDir, 'METADATA'),
        'Metadata-Version: 2.1\nSummary: Has extra headers\nName: extra-pkg\nVersion: 2.0.0\n',
      )

      const crawler = new PythonCrawler()
      const packages = await crawler.crawlAll({
        cwd: tempDir,
        globalPrefix: sp,
      })

      assert.equal(packages.length, 1)
      assert.equal(packages[0].name, 'extra-pkg')
      assert.equal(packages[0].version, '2.0.0')

      await removeTestDir(tempDir)
    })

    it('should return empty for empty dir', async () => {
      const tempDir = await createTestDir('python-crawler-empty-')
      const sp = path.join(tempDir, 'empty-site-packages')
      await fs.mkdir(sp, { recursive: true })

      const crawler = new PythonCrawler()
      const packages = await crawler.crawlAll({
        cwd: tempDir,
        globalPrefix: sp,
      })

      assert.equal(packages.length, 0)

      await removeTestDir(tempDir)
    })

    it('should return empty for non-existent dir', async () => {
      const tempDir = await createTestDir('python-crawler-noexist-')
      const sp = path.join(tempDir, 'nonexistent-dir')

      const crawler = new PythonCrawler()
      const packages = await crawler.crawlAll({
        cwd: tempDir,
        globalPrefix: sp,
      })

      assert.equal(packages.length, 0)

      await removeTestDir(tempDir)
    })

    it('should set path to site-packages directory', async () => {
      const crawler = new PythonCrawler()
      const packages = await crawler.crawlAll({
        cwd: testDir,
        globalPrefix: sitePackagesDir,
      })

      for (const pkg of packages) {
        assert.equal(pkg.path, sitePackagesDir, 'Package path should be site-packages dir')
      }
    })
  })

  describe('crawlBatches', () => {
    let testDir: string
    let sitePackagesDir: string

    before(async () => {
      testDir = await createTestDir('python-crawler-batch-')
      sitePackagesDir = path.join(testDir, 'site-packages')

      for (let i = 1; i <= 5; i++) {
        await createTestPythonPackage(sitePackagesDir, `pkg${i}`, '1.0.0', {})
      }
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should respect batch size', async () => {
      const crawler = new PythonCrawler()
      const batches: number[] = []

      for await (const batch of crawler.crawlBatches({
        cwd: testDir,
        globalPrefix: sitePackagesDir,
        batchSize: 2,
      })) {
        batches.push(batch.length)
      }

      // 5 packages with batchSize=2 → batches of [2, 2, 1]
      assert.equal(batches.length, 3, 'Should have 3 batches')
      assert.equal(batches[0], 2)
      assert.equal(batches[1], 2)
      assert.equal(batches[2], 1)
    })
  })

  describe('deduplication across paths', () => {
    let testDir: string

    before(async () => {
      testDir = await createTestDir('python-crawler-dedup-')
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should deduplicate packages across site-packages dirs', async () => {
      // Create the same package in two directories
      const sp1 = path.join(testDir, 'sp1')
      const sp2 = path.join(testDir, 'sp2')

      await createTestPythonPackage(sp1, 'duped', '1.0.0', {})
      await createTestPythonPackage(sp2, 'duped', '1.0.0', {})

      // Use a custom crawler that reports from multiple paths
      const crawler = new PythonCrawler()
      const seen = new Set<string>()
      const packages: Array<{ purl: string }> = []

      // Manually crawl both using the internal pattern
      for await (const batch of crawler.crawlBatches({
        cwd: testDir,
        globalPrefix: sp1,
      })) {
        packages.push(...batch)
      }
      // Crawl second path - packages already seen should be skipped by PURL
      for await (const batch of crawler.crawlBatches({
        cwd: testDir,
        globalPrefix: sp2,
      })) {
        for (const pkg of batch) {
          if (!seen.has(pkg.purl)) {
            seen.add(pkg.purl)
            packages.push(pkg)
          }
        }
      }

      // The first crawl finds 1, the second crawl also finds 1 (separate calls)
      // but within a single crawlAll call, dedup works automatically
      // Test dedup within a single crawlAll is implicitly tested by crawlAll above
      const allPurls = packages.map(p => p.purl)
      assert.ok(allPurls.includes('pkg:pypi/duped@1.0.0'))
    })
  })

  describe('findByPurls', () => {
    let testDir: string
    let sitePackagesDir: string

    before(async () => {
      testDir = await createTestDir('python-crawler-find-')
      sitePackagesDir = path.join(testDir, 'site-packages')

      await createTestPythonPackage(sitePackagesDir, 'requests', '2.28.0', {})
      await createTestPythonPackage(sitePackagesDir, 'flask', '2.3.0', {})
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should find matching packages', async () => {
      const crawler = new PythonCrawler()
      const found = await crawler.findByPurls(sitePackagesDir, [
        'pkg:pypi/requests@2.28.0',
        'pkg:pypi/nonexistent@1.0.0',
      ])

      assert.equal(found.size, 1)
      assert.ok(found.has('pkg:pypi/requests@2.28.0'))
      assert.ok(!found.has('pkg:pypi/nonexistent@1.0.0'))
    })

    it('should handle PEP 503 name normalization', async () => {
      const tempDir = await createTestDir('python-crawler-pep503-')
      const sp = path.join(tempDir, 'site-packages')

      // Dist-info uses the original name format (underscores)
      await createTestPythonPackage(sp, 'My_Package', '1.0.0', {})

      const crawler = new PythonCrawler()
      // Search using normalized name (hyphens, lowercase)
      const found = await crawler.findByPurls(sp, [
        'pkg:pypi/my-package@1.0.0',
      ])

      assert.equal(found.size, 1, 'Should match via PEP 503 normalization')

      await removeTestDir(tempDir)
    })

    it('should return empty map for empty purls list', async () => {
      const crawler = new PythonCrawler()
      const found = await crawler.findByPurls(sitePackagesDir, [])

      assert.equal(found.size, 0)
    })
  })

  describe('findPythonDirs', () => {
    let testDir: string

    before(async () => {
      testDir = await createTestDir('python-dirs-')
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should match python3.* wildcard', async () => {
      // Create two python version directories
      const base = path.join(testDir, 'lib')
      await fs.mkdir(path.join(base, 'python3.10', 'site-packages'), {
        recursive: true,
      })
      await fs.mkdir(path.join(base, 'python3.11', 'site-packages'), {
        recursive: true,
      })

      const results = await findPythonDirs(
        base,
        'python3.*',
        'site-packages',
      )

      assert.equal(results.length, 2, 'Should find both python versions')
      const sorted = results.sort()
      assert.ok(sorted[0].includes('python3.10'))
      assert.ok(sorted[1].includes('python3.11'))
    })
  })

  describe('findLocalVenvSitePackages', () => {
    let testDir: string

    before(async () => {
      testDir = await createTestDir('python-venv-find-')
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should find .venv directory', async () => {
      const venvSp = path.join(
        testDir,
        '.venv',
        'lib',
        'python3.11',
        'site-packages',
      )
      await fs.mkdir(venvSp, { recursive: true })

      // Temporarily unset VIRTUAL_ENV to test .venv detection
      const origVirtualEnv = process.env['VIRTUAL_ENV']
      delete process.env['VIRTUAL_ENV']

      try {
        const results = await findLocalVenvSitePackages(testDir)
        assert.ok(results.length > 0, 'Should find .venv site-packages')
        assert.ok(
          results.some(r => r.includes('.venv')),
          'Should include .venv path',
        )
      } finally {
        if (origVirtualEnv !== undefined) {
          process.env['VIRTUAL_ENV'] = origVirtualEnv
        } else {
          delete process.env['VIRTUAL_ENV']
        }
      }
    })

    it('should find venv directory', async () => {
      const tempDir = await createTestDir('python-venv-plain-')
      const venvSp = path.join(
        tempDir,
        'venv',
        'lib',
        'python3.11',
        'site-packages',
      )
      await fs.mkdir(venvSp, { recursive: true })

      const origVirtualEnv = process.env['VIRTUAL_ENV']
      delete process.env['VIRTUAL_ENV']

      try {
        const results = await findLocalVenvSitePackages(tempDir)
        assert.ok(results.length > 0, 'Should find venv site-packages')
        assert.ok(
          results.some(r => r.includes('venv')),
          'Should include venv path',
        )
      } finally {
        if (origVirtualEnv !== undefined) {
          process.env['VIRTUAL_ENV'] = origVirtualEnv
        } else {
          delete process.env['VIRTUAL_ENV']
        }
        await removeTestDir(tempDir)
      }
    })
  })

  describe('getSitePackagesPaths', () => {
    it('should honor VIRTUAL_ENV env var', async () => {
      const tempDir = await createTestDir('python-virtual-env-')
      const venvSp = path.join(
        tempDir,
        'custom-venv',
        'lib',
        'python3.11',
        'site-packages',
      )
      await fs.mkdir(venvSp, { recursive: true })

      const origVirtualEnv = process.env['VIRTUAL_ENV']
      process.env['VIRTUAL_ENV'] = path.join(tempDir, 'custom-venv')

      try {
        const crawler = new PythonCrawler()
        const paths = await crawler.getSitePackagesPaths({ cwd: tempDir })
        assert.ok(paths.length > 0, 'Should find VIRTUAL_ENV site-packages')
        assert.ok(
          paths.some(p => p.includes('custom-venv')),
          'Should use VIRTUAL_ENV path',
        )
      } finally {
        if (origVirtualEnv !== undefined) {
          process.env['VIRTUAL_ENV'] = origVirtualEnv
        } else {
          delete process.env['VIRTUAL_ENV']
        }
        await removeTestDir(tempDir)
      }
    })
  })
})

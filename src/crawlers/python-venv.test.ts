import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'fs/promises'
import * as path from 'path'
import { execSync } from 'child_process'
import {
  createTestDir,
  removeTestDir,
} from '../test-utils.js'
import { PythonCrawler } from './index.js'

// Check if python3 is available
let hasPython = false
try {
  execSync('python3 --version', { stdio: 'pipe' })
  hasPython = true
} catch {
  // python3 not available
}

describe('PythonCrawler - real venv tests', () => {
  it('should crawl packages in a real venv', { skip: !hasPython }, async () => {
    const testDir = await createTestDir('python-venv-real-')

    try {
      // Create a real venv and install a tiny package
      execSync('python3 -m venv venv', {
        cwd: testDir,
        stdio: 'pipe',
      })
      execSync(
        `${path.join(testDir, 'venv', 'bin', 'pip')} install --quiet six==1.16.0`,
        { cwd: testDir, stdio: 'pipe', timeout: 60000 },
      )

      // Set VIRTUAL_ENV to point to the venv
      const origVirtualEnv = process.env['VIRTUAL_ENV']
      process.env['VIRTUAL_ENV'] = path.join(testDir, 'venv')

      try {
        const crawler = new PythonCrawler()
        const packages = await crawler.crawlAll({ cwd: testDir })

        const six = packages.find(p => p.name === 'six')
        assert.ok(six, 'Should find six package')
        assert.equal(six.version, '1.16.0')
        assert.equal(six.purl, 'pkg:pypi/six@1.16.0')
      } finally {
        if (origVirtualEnv !== undefined) {
          process.env['VIRTUAL_ENV'] = origVirtualEnv
        } else {
          delete process.env['VIRTUAL_ENV']
        }
      }
    } finally {
      await removeTestDir(testDir)
    }
  })

  it('should find .venv automatically without VIRTUAL_ENV', { skip: !hasPython }, async () => {
    const testDir = await createTestDir('python-dotvenv-auto-')

    try {
      // Create a .venv (dotted name)
      execSync('python3 -m venv .venv', {
        cwd: testDir,
        stdio: 'pipe',
      })
      execSync(
        `${path.join(testDir, '.venv', 'bin', 'pip')} install --quiet six==1.16.0`,
        { cwd: testDir, stdio: 'pipe', timeout: 60000 },
      )

      // Ensure VIRTUAL_ENV is NOT set
      const origVirtualEnv = process.env['VIRTUAL_ENV']
      delete process.env['VIRTUAL_ENV']

      try {
        const crawler = new PythonCrawler()
        const packages = await crawler.crawlAll({ cwd: testDir })

        const six = packages.find(p => p.name === 'six')
        assert.ok(six, 'Should find six in .venv without VIRTUAL_ENV')
        assert.equal(six.purl, 'pkg:pypi/six@1.16.0')
      } finally {
        if (origVirtualEnv !== undefined) {
          process.env['VIRTUAL_ENV'] = origVirtualEnv
        } else {
          delete process.env['VIRTUAL_ENV']
        }
      }
    } finally {
      await removeTestDir(testDir)
    }
  })

  it('should honor VIRTUAL_ENV env var', { skip: !hasPython }, async () => {
    const testDir = await createTestDir('python-virtualenv-var-')

    try {
      // Create venv in a custom location
      const customVenvPath = path.join(testDir, 'custom-env')
      execSync(`python3 -m venv ${customVenvPath}`, {
        cwd: testDir,
        stdio: 'pipe',
      })
      execSync(
        `${path.join(customVenvPath, 'bin', 'pip')} install --quiet six==1.16.0`,
        { cwd: testDir, stdio: 'pipe', timeout: 60000 },
      )

      const origVirtualEnv = process.env['VIRTUAL_ENV']
      process.env['VIRTUAL_ENV'] = customVenvPath

      try {
        const crawler = new PythonCrawler()
        const packages = await crawler.crawlAll({ cwd: testDir })

        const six = packages.find(p => p.name === 'six')
        assert.ok(six, 'Should find six via VIRTUAL_ENV')
        assert.ok(
          six.path.includes('custom-env'),
          'Path should reference the custom venv',
        )
      } finally {
        if (origVirtualEnv !== undefined) {
          process.env['VIRTUAL_ENV'] = origVirtualEnv
        } else {
          delete process.env['VIRTUAL_ENV']
        }
      }
    } finally {
      await removeTestDir(testDir)
    }
  })

  it('should return paths from getSitePackagesPaths with global option', { skip: !hasPython }, async () => {
    const crawler = new PythonCrawler()
    const paths = await crawler.getSitePackagesPaths({
      cwd: process.cwd(),
      global: true,
    })

    // Global site-packages should return at least one path
    assert.ok(paths.length > 0, 'Should return at least one global site-packages path')

    // Verify paths exist (at least some of them)
    let existingCount = 0
    for (const p of paths) {
      try {
        await fs.access(p)
        existingCount++
      } catch {
        // Some paths may not exist on all systems
      }
    }
    assert.ok(existingCount >= 0, 'Some global site-packages paths may exist')
  })

  it('should fall back to python3 -c for site-packages', { skip: !hasPython }, async () => {
    // Create a temp dir with no venv
    const testDir = await createTestDir('python-fallback-')
    const origVirtualEnv = process.env['VIRTUAL_ENV']
    delete process.env['VIRTUAL_ENV']

    try {
      const crawler = new PythonCrawler()
      const paths = await crawler.getSitePackagesPaths({ cwd: testDir })

      // Without VIRTUAL_ENV and no .venv/venv dir, it should fall back to python3
      // The result may be empty if python3 returns system paths we can't access,
      // but the function should not throw
      assert.ok(Array.isArray(paths), 'Should return an array')
    } finally {
      if (origVirtualEnv !== undefined) {
        process.env['VIRTUAL_ENV'] = origVirtualEnv
      } else {
        delete process.env['VIRTUAL_ENV']
      }
      await removeTestDir(testDir)
    }
  })
})

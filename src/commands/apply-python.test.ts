import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as path from 'path'
import {
  createTestDir,
  removeTestDir,
  setupTestEnvironment,
  computeTestHash,
} from '../test-utils.js'
import { applyPackagePatch } from '../patch/apply.js'
import * as fs from 'fs/promises'

// Valid UUIDs for testing
const TEST_UUID_PY1 = 'aaaa1111-1111-4111-8111-111111111111'
const TEST_UUID_PY2 = 'aaaa2222-2222-4222-8222-222222222222'
const TEST_UUID_NPM1 = 'bbbb1111-1111-4111-8111-111111111111'

describe('apply command - Python packages', () => {
  let testDir: string

  before(async () => {
    testDir = await createTestDir('apply-python-')
  })

  after(async () => {
    await removeTestDir(testDir)
  })

  it('should apply patch to pypi package', async () => {
    const beforeContent = 'import os\nprint("vulnerable")\n'
    const afterContent = 'import os\nprint("patched")\n'

    const { blobsDir, sitePackagesDir } = await setupTestEnvironment({
      testDir: path.join(testDir, 'test-apply'),
      patches: [
        {
          purl: 'pkg:pypi/requests@2.28.0',
          uuid: TEST_UUID_PY1,
          files: {
            'requests/__init__.py': { beforeContent, afterContent },
          },
        },
      ],
      initialState: 'before',
    })

    const beforeHash = computeTestHash(beforeContent)
    const afterHash = computeTestHash(afterContent)

    const result = await applyPackagePatch(
      'pkg:pypi/requests@2.28.0',
      sitePackagesDir,
      { 'requests/__init__.py': { beforeHash, afterHash } },
      blobsDir,
      false,
    )

    assert.equal(result.success, true)
    assert.equal(result.filesPatched.length, 1)

    // Verify file was changed
    const content = await fs.readFile(
      path.join(sitePackagesDir, 'requests/__init__.py'),
      'utf-8',
    )
    assert.equal(content, afterContent)
  })

  it('should apply patches to both pypi and npm packages', async () => {
    const pyBefore = 'py_before'
    const pyAfter = 'py_after'
    const npmBefore = 'npm_before'
    const npmAfter = 'npm_after'

    const { blobsDir, nodeModulesDir, sitePackagesDir } =
      await setupTestEnvironment({
        testDir: path.join(testDir, 'test-mixed'),
        patches: [
          {
            purl: 'pkg:pypi/flask@2.3.0',
            uuid: TEST_UUID_PY2,
            files: {
              'flask/__init__.py': {
                beforeContent: pyBefore,
                afterContent: pyAfter,
              },
            },
          },
          {
            purl: 'pkg:npm/lodash@4.17.21',
            uuid: TEST_UUID_NPM1,
            files: {
              'package/index.js': {
                beforeContent: npmBefore,
                afterContent: npmAfter,
              },
            },
          },
        ],
        initialState: 'before',
      })

    // Apply Python patch
    const pyResult = await applyPackagePatch(
      'pkg:pypi/flask@2.3.0',
      sitePackagesDir,
      {
        'flask/__init__.py': {
          beforeHash: computeTestHash(pyBefore),
          afterHash: computeTestHash(pyAfter),
        },
      },
      blobsDir,
      false,
    )
    assert.equal(pyResult.success, true)

    // Apply npm patch
    const npmPkgDir = path.join(nodeModulesDir, 'lodash')
    const npmResult = await applyPackagePatch(
      'pkg:npm/lodash@4.17.21',
      npmPkgDir,
      {
        'package/index.js': {
          beforeHash: computeTestHash(npmBefore),
          afterHash: computeTestHash(npmAfter),
        },
      },
      blobsDir,
      false,
    )
    assert.equal(npmResult.success, true)
  })

  it('should skip uninstalled pypi package with not-found status', async () => {
    const beforeContent = 'original'
    const afterContent = 'patched'
    const beforeHash = computeTestHash(beforeContent)
    const afterHash = computeTestHash(afterContent)

    const { blobsDir, sitePackagesDir } = await setupTestEnvironment({
      testDir: path.join(testDir, 'test-uninstalled'),
      patches: [],
      initialState: 'before',
    })

    // Apply to a file that doesn't exist in site-packages
    const result = await applyPackagePatch(
      'pkg:pypi/nonexistent@1.0.0',
      sitePackagesDir,
      { 'nonexistent/__init__.py': { beforeHash, afterHash } },
      blobsDir,
      false,
    )

    assert.equal(result.success, false)
    assert.ok(result.error?.includes('not-found') || result.error?.includes('File not found'))
  })

  it('should not modify pypi files in dry-run mode', async () => {
    const beforeContent = 'import six\noriginal = True\n'
    const afterContent = 'import six\noriginal = False\n'

    const { blobsDir, sitePackagesDir } = await setupTestEnvironment({
      testDir: path.join(testDir, 'test-dryrun'),
      patches: [
        {
          purl: 'pkg:pypi/six@1.16.0',
          uuid: TEST_UUID_PY1,
          files: {
            'six.py': { beforeContent, afterContent },
          },
        },
      ],
      initialState: 'before',
    })

    const result = await applyPackagePatch(
      'pkg:pypi/six@1.16.0',
      sitePackagesDir,
      {
        'six.py': {
          beforeHash: computeTestHash(beforeContent),
          afterHash: computeTestHash(afterContent),
        },
      },
      blobsDir,
      true, // dry-run
    )

    assert.equal(result.success, true)
    assert.equal(result.filesPatched.length, 0)

    // File should be unchanged
    const content = await fs.readFile(
      path.join(sitePackagesDir, 'six.py'),
      'utf-8',
    )
    assert.equal(content, beforeContent)
  })

  it('should skip already-patched pypi package', async () => {
    const beforeContent = 'original_code'
    const afterContent = 'patched_code'

    const { blobsDir, sitePackagesDir } = await setupTestEnvironment({
      testDir: path.join(testDir, 'test-already'),
      patches: [
        {
          purl: 'pkg:pypi/requests@2.28.0',
          uuid: TEST_UUID_PY1,
          files: {
            'requests/__init__.py': { beforeContent, afterContent },
          },
        },
      ],
      initialState: 'after', // Start in patched state
    })

    const result = await applyPackagePatch(
      'pkg:pypi/requests@2.28.0',
      sitePackagesDir,
      {
        'requests/__init__.py': {
          beforeHash: computeTestHash(beforeContent),
          afterHash: computeTestHash(afterContent),
        },
      },
      blobsDir,
      false,
    )

    assert.equal(result.success, true)
    assert.equal(result.filesPatched.length, 0, 'No files should be patched')
    assert.equal(
      result.filesVerified[0].status,
      'already-patched',
    )
  })
})

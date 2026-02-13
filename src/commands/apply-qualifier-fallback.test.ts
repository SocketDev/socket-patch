import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'fs/promises'
import * as path from 'path'
import {
  createTestDir,
  removeTestDir,
  createTestPythonPackage,
  writeTestBlobs,
  computeTestHash,
} from '../test-utils.js'
import { applyPackagePatch, verifyFilePatch } from '../patch/apply.js'

describe('apply command - qualifier variant fallback', () => {
  let testDir: string

  before(async () => {
    testDir = await createTestDir('apply-qualifier-')
  })

  after(async () => {
    await removeTestDir(testDir)
  })

  it('should apply first matching variant when hash matches', async () => {
    const fileContent = 'original content v1'
    const patchedContent = 'patched content v1'
    const beforeHash = computeTestHash(fileContent)
    const afterHash = computeTestHash(patchedContent)

    // Setup: file on disk matches variant 1
    const dir = path.join(testDir, 'test-first')
    const sp = path.join(dir, 'site-packages')
    await createTestPythonPackage(sp, 'requests', '2.28.0', {
      'requests/__init__.py': fileContent,
    })

    const blobsDir = path.join(dir, 'blobs')
    await writeTestBlobs(blobsDir, {
      [beforeHash]: fileContent,
      [afterHash]: patchedContent,
    })

    const result = await applyPackagePatch(
      'pkg:pypi/requests@2.28.0?artifact_id=aaa',
      sp,
      { 'requests/__init__.py': { beforeHash, afterHash } },
      blobsDir,
      false,
    )

    assert.equal(result.success, true)
    assert.equal(result.filesPatched.length, 1)

    const content = await fs.readFile(
      path.join(sp, 'requests/__init__.py'),
      'utf-8',
    )
    assert.equal(content, patchedContent)
  })

  it('should try second variant when first hash mismatches', async () => {
    const variant1Before = 'variant 1 before'
    const variant2Before = 'variant 2 before - actual file content'
    const variant2After = 'variant 2 after'

    // The file on disk matches variant 2, not variant 1
    const dir = path.join(testDir, 'test-second')
    const sp = path.join(dir, 'site-packages')
    await createTestPythonPackage(sp, 'requests', '2.28.0', {
      'requests/__init__.py': variant2Before,
    })

    const blobsDir = path.join(dir, 'blobs')
    const v2BeforeHash = computeTestHash(variant2Before)
    const v2AfterHash = computeTestHash(variant2After)
    await writeTestBlobs(blobsDir, {
      [computeTestHash(variant1Before)]: variant1Before,
      [v2BeforeHash]: variant2Before,
      [v2AfterHash]: variant2After,
    })

    // First check variant 1 - should mismatch
    const verify1 = await verifyFilePatch(
      sp,
      'requests/__init__.py',
      {
        beforeHash: computeTestHash(variant1Before),
        afterHash: computeTestHash('variant 1 after'),
      },
    )
    assert.equal(verify1.status, 'hash-mismatch', 'Variant 1 should mismatch')

    // Then variant 2 - should be ready
    const verify2 = await verifyFilePatch(
      sp,
      'requests/__init__.py',
      { beforeHash: v2BeforeHash, afterHash: v2AfterHash },
    )
    assert.equal(verify2.status, 'ready', 'Variant 2 should be ready')

    // Apply variant 2
    const result = await applyPackagePatch(
      'pkg:pypi/requests@2.28.0?artifact_id=bbb',
      sp,
      { 'requests/__init__.py': { beforeHash: v2BeforeHash, afterHash: v2AfterHash } },
      blobsDir,
      false,
    )

    assert.equal(result.success, true)
    const content = await fs.readFile(
      path.join(sp, 'requests/__init__.py'),
      'utf-8',
    )
    assert.equal(content, variant2After)
  })

  it('should fail when no variant matches', async () => {
    const fileContent = 'completely different content'
    const dir = path.join(testDir, 'test-nomatch')
    const sp = path.join(dir, 'site-packages')
    await createTestPythonPackage(sp, 'requests', '2.28.0', {
      'requests/__init__.py': fileContent,
    })

    const blobsDir = path.join(dir, 'blobs')
    await fs.mkdir(blobsDir, { recursive: true })

    // Both variants have mismatching beforeHash
    const verify = await verifyFilePatch(
      sp,
      'requests/__init__.py',
      {
        beforeHash: computeTestHash('wrong before 1'),
        afterHash: computeTestHash('wrong after 1'),
      },
    )

    assert.equal(verify.status, 'hash-mismatch', 'No variant should match')
  })

  it('should skip second variant after first succeeds (appliedBasePurls)', async () => {
    const beforeContent = 'original'
    const afterContent = 'patched'
    const beforeHash = computeTestHash(beforeContent)
    const afterHash = computeTestHash(afterContent)

    const dir = path.join(testDir, 'test-dedup')
    const sp = path.join(dir, 'site-packages')
    await createTestPythonPackage(sp, 'requests', '2.28.0', {
      'requests/__init__.py': beforeContent,
    })

    const blobsDir = path.join(dir, 'blobs')
    await writeTestBlobs(blobsDir, {
      [beforeHash]: beforeContent,
      [afterHash]: afterContent,
    })

    // Apply first variant
    const result1 = await applyPackagePatch(
      'pkg:pypi/requests@2.28.0?artifact_id=aaa',
      sp,
      { 'requests/__init__.py': { beforeHash, afterHash } },
      blobsDir,
      false,
    )
    assert.equal(result1.success, true)

    // After first variant succeeds, applying same base PURL should see already-patched
    const result2 = await applyPackagePatch(
      'pkg:pypi/requests@2.28.0?artifact_id=bbb',
      sp,
      { 'requests/__init__.py': { beforeHash, afterHash } },
      blobsDir,
      false,
    )
    assert.equal(result2.success, true)
    assert.equal(result2.filesPatched.length, 0, 'Should not re-patch')
    assert.equal(result2.filesVerified[0].status, 'already-patched')
  })

  it('should find package via base PURL for rollback', async () => {
    // This tests that the rollback command correctly maps
    // qualified PURL back to the base PURL for package lookup
    const beforeContent = 'rollback_before'
    const afterContent = 'rollback_after'
    const beforeHash = computeTestHash(beforeContent)
    const afterHash = computeTestHash(afterContent)

    const dir = path.join(testDir, 'test-rollback-map')
    const sp = path.join(dir, 'site-packages')
    await createTestPythonPackage(sp, 'requests', '2.28.0', {
      'requests/__init__.py': afterContent, // Start in patched state
    })

    const blobsDir = path.join(dir, 'blobs')
    await writeTestBlobs(blobsDir, {
      [beforeHash]: beforeContent,
      [afterHash]: afterContent,
    })

    // Import rollback function
    const { rollbackPackagePatch } = await import('../patch/rollback.js')

    const result = await rollbackPackagePatch(
      'pkg:pypi/requests@2.28.0?artifact_id=aaa',
      sp,
      { 'requests/__init__.py': { beforeHash, afterHash } },
      blobsDir,
      false,
    )

    assert.equal(result.success, true)
    assert.equal(result.filesRolledBack.length, 1)

    const content = await fs.readFile(
      path.join(sp, 'requests/__init__.py'),
      'utf-8',
    )
    assert.equal(content, beforeContent)
  })
})

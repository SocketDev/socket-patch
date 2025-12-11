import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'fs/promises'
import * as path from 'path'
import {
  createTestDir,
  removeTestDir,
  setupTestEnvironment,
  readPackageFile,
  computeTestHash,
} from '../test-utils.js'
import { rollbackPackagePatch } from '../patch/rollback.js'
import { rollbackPatches } from './rollback.js'

// Valid UUIDs for testing
const TEST_UUID_1 = '11111111-1111-4111-8111-111111111111'
const TEST_UUID_2 = '22222222-2222-4222-8222-222222222222'
const TEST_UUID_3 = '33333333-3333-4333-8333-333333333333'
const TEST_UUID_4 = '44444444-4444-4444-8444-444444444444'
const TEST_UUID_5 = '55555555-5555-4555-8555-555555555555'
const TEST_UUID_6 = '66666666-6666-4666-8666-666666666666'
const TEST_UUID_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const TEST_UUID_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const TEST_UUID_SCOPED = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'

describe('rollback command', () => {
  describe('rollbackPackagePatch', () => {
    let testDir: string

    before(async () => {
      testDir = await createTestDir('rollback-pkg-')
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should restore files to original state when in patched state', async () => {
      const beforeContent = 'console.log("original");'
      const afterContent = 'console.log("patched");'

      const { blobsDir, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'test1'),
        patches: [
          {
            purl: 'pkg:npm/test-pkg@1.0.0',
            uuid: TEST_UUID_1,
            files: {
              'package/index.js': { beforeContent, afterContent },
            },
          },
        ],
        initialState: 'after', // Package starts in patched state
      })

      const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!
      const beforeHash = computeTestHash(beforeContent)
      const afterHash = computeTestHash(afterContent)

      const result = await rollbackPackagePatch(
        'pkg:npm/test-pkg@1.0.0',
        pkgDir,
        { 'package/index.js': { beforeHash, afterHash } },
        blobsDir,
        false,
      )

      assert.equal(result.success, true)
      assert.equal(result.filesRolledBack.length, 1)
      assert.equal(result.filesRolledBack[0], 'package/index.js')

      const fileContent = await readPackageFile(pkgDir, 'index.js')
      assert.equal(fileContent, beforeContent)
    })

    it('should skip files already in original state', async () => {
      const beforeContent = 'console.log("original");'
      const afterContent = 'console.log("patched");'

      const { blobsDir, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'test2'),
        patches: [
          {
            purl: 'pkg:npm/test-pkg@1.0.0',
            uuid: TEST_UUID_2,
            files: {
              'package/index.js': { beforeContent, afterContent },
            },
          },
        ],
        initialState: 'before', // Package starts in original state
      })

      const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!
      const beforeHash = computeTestHash(beforeContent)
      const afterHash = computeTestHash(afterContent)

      const result = await rollbackPackagePatch(
        'pkg:npm/test-pkg@1.0.0',
        pkgDir,
        { 'package/index.js': { beforeHash, afterHash } },
        blobsDir,
        false,
      )

      assert.equal(result.success, true)
      assert.equal(result.filesRolledBack.length, 0)
      assert.equal(result.filesVerified[0].status, 'already-original')
    })

    it('should fail if file has been modified after patching', async () => {
      const beforeContent = 'console.log("original");'
      const afterContent = 'console.log("patched");'
      const modifiedContent = 'console.log("user modified");'

      const { blobsDir, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'test3'),
        patches: [
          {
            purl: 'pkg:npm/test-pkg@1.0.0',
            uuid: TEST_UUID_3,
            files: {
              'package/index.js': { beforeContent, afterContent },
            },
          },
        ],
        initialState: 'after',
      })

      const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!

      // Modify the file to simulate user changes
      await fs.writeFile(path.join(pkgDir, 'index.js'), modifiedContent)

      const beforeHash = computeTestHash(beforeContent)
      const afterHash = computeTestHash(afterContent)

      const result = await rollbackPackagePatch(
        'pkg:npm/test-pkg@1.0.0',
        pkgDir,
        { 'package/index.js': { beforeHash, afterHash } },
        blobsDir,
        false,
      )

      assert.equal(result.success, false)
      assert.ok(result.error?.includes('modified after patching'))
    })

    it('should fail if before blob is missing', async () => {
      const beforeContent = 'console.log("original");'
      const afterContent = 'console.log("patched");'

      const { blobsDir, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'test4'),
        patches: [
          {
            purl: 'pkg:npm/test-pkg@1.0.0',
            uuid: TEST_UUID_4,
            files: {
              'package/index.js': { beforeContent, afterContent },
            },
          },
        ],
        initialState: 'after',
      })

      const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!
      const beforeHash = computeTestHash(beforeContent)
      const afterHash = computeTestHash(afterContent)

      // Delete the before blob
      await fs.unlink(path.join(blobsDir, beforeHash))

      const result = await rollbackPackagePatch(
        'pkg:npm/test-pkg@1.0.0',
        pkgDir,
        { 'package/index.js': { beforeHash, afterHash } },
        blobsDir,
        false,
      )

      assert.equal(result.success, false)
      assert.ok(result.error?.includes('Before blob not found'))
    })

    it('should not modify files in dry-run mode', async () => {
      const beforeContent = 'console.log("original");'
      const afterContent = 'console.log("patched");'

      const { blobsDir, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'test5'),
        patches: [
          {
            purl: 'pkg:npm/test-pkg@1.0.0',
            uuid: TEST_UUID_5,
            files: {
              'package/index.js': { beforeContent, afterContent },
            },
          },
        ],
        initialState: 'after',
      })

      const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!
      const beforeHash = computeTestHash(beforeContent)
      const afterHash = computeTestHash(afterContent)

      const result = await rollbackPackagePatch(
        'pkg:npm/test-pkg@1.0.0',
        pkgDir,
        { 'package/index.js': { beforeHash, afterHash } },
        blobsDir,
        true, // dry-run
      )

      assert.equal(result.success, true)
      assert.equal(result.filesRolledBack.length, 0)

      // File should still be in patched state
      const fileContent = await readPackageFile(pkgDir, 'index.js')
      assert.equal(fileContent, afterContent)
    })

    it('should handle multiple files in a package', async () => {
      const files = {
        'package/index.js': {
          beforeContent: 'export default 1;',
          afterContent: 'export default 2;',
        },
        'package/lib/utils.js': {
          beforeContent: 'const a = 1;',
          afterContent: 'const a = 2;',
        },
      }

      const { blobsDir, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'test6'),
        patches: [
          {
            purl: 'pkg:npm/test-pkg@1.0.0',
            uuid: TEST_UUID_6,
            files,
          },
        ],
        initialState: 'after',
      })

      const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!
      const patchFiles: Record<string, { beforeHash: string; afterHash: string }> = {}

      for (const [filePath, { beforeContent, afterContent }] of Object.entries(files)) {
        patchFiles[filePath] = {
          beforeHash: computeTestHash(beforeContent),
          afterHash: computeTestHash(afterContent),
        }
      }

      const result = await rollbackPackagePatch(
        'pkg:npm/test-pkg@1.0.0',
        pkgDir,
        patchFiles,
        blobsDir,
        false,
      )

      assert.equal(result.success, true)
      assert.equal(result.filesRolledBack.length, 2)

      // Verify all files are restored
      assert.equal(
        await readPackageFile(pkgDir, 'index.js'),
        files['package/index.js'].beforeContent,
      )
      assert.equal(
        await readPackageFile(pkgDir, 'lib/utils.js'),
        files['package/lib/utils.js'].beforeContent,
      )
    })
  })

  describe('rollbackPatches', () => {
    let testDir: string

    before(async () => {
      testDir = await createTestDir('rollback-patches-')
    })

    after(async () => {
      await removeTestDir(testDir)
    })

    it('should rollback all patches when no identifier provided', async () => {
      const { manifestPath, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'all1'),
        patches: [
          {
            purl: 'pkg:npm/pkg-a@1.0.0',
            uuid: TEST_UUID_A,
            files: {
              'package/index.js': {
                beforeContent: 'a-before',
                afterContent: 'a-after',
              },
            },
          },
          {
            purl: 'pkg:npm/pkg-b@2.0.0',
            uuid: TEST_UUID_B,
            files: {
              'package/index.js': {
                beforeContent: 'b-before',
                afterContent: 'b-after',
              },
            },
          },
        ],
        initialState: 'after',
      })

      const { success, results } = await rollbackPatches(
        path.dirname(manifestPath).replace('/.socket', ''),
        manifestPath,
        undefined, // no identifier = all patches
        false,
        true,
      )

      assert.equal(success, true)
      assert.equal(results.length, 2)

      // Verify both packages are rolled back
      const pkgADir = packageDirs.get('pkg:npm/pkg-a@1.0.0')!
      const pkgBDir = packageDirs.get('pkg:npm/pkg-b@2.0.0')!

      assert.equal(await readPackageFile(pkgADir, 'index.js'), 'a-before')
      assert.equal(await readPackageFile(pkgBDir, 'index.js'), 'b-before')
    })

    it('should rollback only specified patch by PURL', async () => {
      const { manifestPath, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'purl1'),
        patches: [
          {
            purl: 'pkg:npm/pkg-a@1.0.0',
            uuid: TEST_UUID_A,
            files: {
              'package/index.js': {
                beforeContent: 'a-before',
                afterContent: 'a-after',
              },
            },
          },
          {
            purl: 'pkg:npm/pkg-b@2.0.0',
            uuid: TEST_UUID_B,
            files: {
              'package/index.js': {
                beforeContent: 'b-before',
                afterContent: 'b-after',
              },
            },
          },
        ],
        initialState: 'after',
      })

      const { success, results } = await rollbackPatches(
        path.dirname(manifestPath).replace('/.socket', ''),
        manifestPath,
        'pkg:npm/pkg-a@1.0.0', // Only rollback pkg-a
        false,
        true,
      )

      assert.equal(success, true)
      assert.equal(results.length, 1)
      assert.equal(results[0].packageKey, 'pkg:npm/pkg-a@1.0.0')

      // Verify only pkg-a is rolled back
      const pkgADir = packageDirs.get('pkg:npm/pkg-a@1.0.0')!
      const pkgBDir = packageDirs.get('pkg:npm/pkg-b@2.0.0')!

      assert.equal(await readPackageFile(pkgADir, 'index.js'), 'a-before')
      assert.equal(await readPackageFile(pkgBDir, 'index.js'), 'b-after') // Still patched
    })

    it('should rollback only specified patch by UUID', async () => {
      const { manifestPath, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'uuid1'),
        patches: [
          {
            purl: 'pkg:npm/pkg-a@1.0.0',
            uuid: TEST_UUID_A,
            files: {
              'package/index.js': {
                beforeContent: 'a-before',
                afterContent: 'a-after',
              },
            },
          },
          {
            purl: 'pkg:npm/pkg-b@2.0.0',
            uuid: TEST_UUID_B,
            files: {
              'package/index.js': {
                beforeContent: 'b-before',
                afterContent: 'b-after',
              },
            },
          },
        ],
        initialState: 'after',
      })

      const { success, results } = await rollbackPatches(
        path.dirname(manifestPath).replace('/.socket', ''),
        manifestPath,
        TEST_UUID_B, // Rollback by UUID
        false,
        true,
      )

      assert.equal(success, true)
      assert.equal(results.length, 1)
      assert.equal(results[0].packageKey, 'pkg:npm/pkg-b@2.0.0')

      // Verify only pkg-b is rolled back
      const pkgADir = packageDirs.get('pkg:npm/pkg-a@1.0.0')!
      const pkgBDir = packageDirs.get('pkg:npm/pkg-b@2.0.0')!

      assert.equal(await readPackageFile(pkgADir, 'index.js'), 'a-after') // Still patched
      assert.equal(await readPackageFile(pkgBDir, 'index.js'), 'b-before')
    })

    it('should error if patch not found by PURL', async () => {
      const { manifestPath } = await setupTestEnvironment({
        testDir: path.join(testDir, 'notfound1'),
        patches: [
          {
            purl: 'pkg:npm/pkg-a@1.0.0',
            uuid: TEST_UUID_A,
            files: {
              'package/index.js': {
                beforeContent: 'a-before',
                afterContent: 'a-after',
              },
            },
          },
        ],
        initialState: 'after',
      })

      await assert.rejects(
        async () => {
          await rollbackPatches(
            path.dirname(manifestPath).replace('/.socket', ''),
            manifestPath,
            'pkg:npm/nonexistent@1.0.0',
            false,
            true,
          )
        },
        /No patch found matching identifier/,
      )
    })

    it('should error if patch not found by UUID', async () => {
      const { manifestPath } = await setupTestEnvironment({
        testDir: path.join(testDir, 'notfound2'),
        patches: [
          {
            purl: 'pkg:npm/pkg-a@1.0.0',
            uuid: TEST_UUID_A,
            files: {
              'package/index.js': {
                beforeContent: 'a-before',
                afterContent: 'a-after',
              },
            },
          },
        ],
        initialState: 'after',
      })

      await assert.rejects(
        async () => {
          await rollbackPatches(
            path.dirname(manifestPath).replace('/.socket', ''),
            manifestPath,
            'dddddddd-dddd-4ddd-8ddd-dddddddddddd', // nonexistent UUID
            false,
            true,
          )
        },
        /No patch found matching identifier/,
      )
    })

    it('should handle scoped packages', async () => {
      const { manifestPath, packageDirs } = await setupTestEnvironment({
        testDir: path.join(testDir, 'scoped1'),
        patches: [
          {
            purl: 'pkg:npm/@scope/pkg-a@1.0.0',
            uuid: TEST_UUID_SCOPED,
            files: {
              'package/index.js': {
                beforeContent: 'scoped-before',
                afterContent: 'scoped-after',
              },
            },
          },
        ],
        initialState: 'after',
      })

      const { success, results } = await rollbackPatches(
        path.dirname(manifestPath).replace('/.socket', ''),
        manifestPath,
        'pkg:npm/@scope/pkg-a@1.0.0',
        false,
        true,
      )

      assert.equal(success, true)
      assert.equal(results.length, 1)

      const pkgDir = packageDirs.get('pkg:npm/@scope/pkg-a@1.0.0')!
      assert.equal(await readPackageFile(pkgDir, 'index.js'), 'scoped-before')
    })
  })
})

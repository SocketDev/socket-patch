import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'fs/promises'
import * as path from 'path'
import {
  createTestDir,
  removeTestDir,
  setupTestEnvironment,
  readPackageFile,
} from '../test-utils.js'
import { PatchManifestSchema } from '../schema/manifest-schema.js'

// Valid UUIDs for testing
const TEST_UUID_1 = '11111111-1111-4111-8111-111111111111'
const TEST_UUID_2 = '22222222-2222-4222-8222-222222222222'
const TEST_UUID_3 = '33333333-3333-4333-8333-333333333333'
const TEST_UUID_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const TEST_UUID_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const TEST_UUID_SPECIFIC = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'

describe('remove command with rollback', () => {
  let testDir: string

  before(async () => {
    testDir = await createTestDir('remove-test-')
  })

  after(async () => {
    await removeTestDir(testDir)
  })

  it('should rollback files before removing from manifest', async () => {
    const { manifestPath, packageDirs } = await setupTestEnvironment({
      testDir: path.join(testDir, 'rollback1'),
      patches: [
        {
          purl: 'pkg:npm/test-pkg@1.0.0',
          uuid: TEST_UUID_1,
          files: {
            'package/index.js': {
              beforeContent: 'original content',
              afterContent: 'patched content',
            },
          },
        },
      ],
      initialState: 'after', // Start in patched state
    })

    const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!

    // Verify file is in patched state before remove
    assert.equal(await readPackageFile(pkgDir, 'index.js'), 'patched content')

    // Simulate the remove command behavior with rollback
    // First, import and call rollbackPatches
    const { rollbackPatches } = await import('./rollback.js')

    const cwd = path.dirname(manifestPath).replace('/.socket', '')

    const { success: rollbackSuccess } = await rollbackPatches(
      cwd,
      manifestPath,
      'pkg:npm/test-pkg@1.0.0',
      false,
      true,
      false, // not offline
    )

    assert.equal(rollbackSuccess, true)

    // Verify file is restored to original state
    assert.equal(await readPackageFile(pkgDir, 'index.js'), 'original content')

    // Now remove from manifest
    const manifestContent = await fs.readFile(manifestPath, 'utf-8')
    const manifest = PatchManifestSchema.parse(JSON.parse(manifestContent))

    delete manifest.patches['pkg:npm/test-pkg@1.0.0']
    await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n')

    // Verify manifest is updated
    const updatedManifest = JSON.parse(await fs.readFile(manifestPath, 'utf-8'))
    assert.equal(updatedManifest.patches['pkg:npm/test-pkg@1.0.0'], undefined)
  })

  it('should allow removal without rollback using --skip-rollback flag', async () => {
    const { manifestPath, packageDirs } = await setupTestEnvironment({
      testDir: path.join(testDir, 'norollback1'),
      patches: [
        {
          purl: 'pkg:npm/test-pkg@1.0.0',
          uuid: TEST_UUID_2,
          files: {
            'package/index.js': {
              beforeContent: 'original content',
              afterContent: 'patched content',
            },
          },
        },
      ],
      initialState: 'after',
    })

    const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!

    // Simulate --skip-rollback: only remove from manifest without rollback
    const manifestContent = await fs.readFile(manifestPath, 'utf-8')
    const manifest = PatchManifestSchema.parse(JSON.parse(manifestContent))

    delete manifest.patches['pkg:npm/test-pkg@1.0.0']
    await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n')

    // File should still be in patched state (no rollback performed)
    assert.equal(await readPackageFile(pkgDir, 'index.js'), 'patched content')

    // Manifest should be updated
    const updatedManifest = JSON.parse(await fs.readFile(manifestPath, 'utf-8'))
    assert.equal(updatedManifest.patches['pkg:npm/test-pkg@1.0.0'], undefined)
  })

  it('should fail if rollback fails (file modified)', async () => {
    const { manifestPath, packageDirs } = await setupTestEnvironment({
      testDir: path.join(testDir, 'fail1'),
      patches: [
        {
          purl: 'pkg:npm/test-pkg@1.0.0',
          uuid: TEST_UUID_3,
          files: {
            'package/index.js': {
              beforeContent: 'original content',
              afterContent: 'patched content',
            },
          },
        },
      ],
      initialState: 'after',
    })

    const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!

    // Modify the file to simulate user changes
    await fs.writeFile(path.join(pkgDir, 'index.js'), 'user modified content')

    const { rollbackPatches } = await import('./rollback.js')

    const cwd = path.dirname(manifestPath).replace('/.socket', '')

    const { success } = await rollbackPatches(
      cwd,
      manifestPath,
      'pkg:npm/test-pkg@1.0.0',
      false,
      true,
      false, // not offline
    )

    // Rollback should fail due to hash mismatch
    assert.equal(success, false)

    // Manifest should still have the patch
    const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf-8'))
    assert.ok(manifest.patches['pkg:npm/test-pkg@1.0.0'])
  })

  it('should remove by UUID and rollback', async () => {
    const { manifestPath, packageDirs } = await setupTestEnvironment({
      testDir: path.join(testDir, 'uuid1'),
      patches: [
        {
          purl: 'pkg:npm/test-pkg@1.0.0',
          uuid: TEST_UUID_SPECIFIC,
          files: {
            'package/index.js': {
              beforeContent: 'original by uuid',
              afterContent: 'patched by uuid',
            },
          },
        },
      ],
      initialState: 'after',
    })

    const pkgDir = packageDirs.get('pkg:npm/test-pkg@1.0.0')!

    const { rollbackPatches } = await import('./rollback.js')

    const cwd = path.dirname(manifestPath).replace('/.socket', '')

    // Rollback by UUID
    const { success } = await rollbackPatches(
      cwd,
      manifestPath,
      TEST_UUID_SPECIFIC,
      false,
      true,
      false, // not offline
    )

    assert.equal(success, true)
    assert.equal(await readPackageFile(pkgDir, 'index.js'), 'original by uuid')
  })

  it('should handle removing one of multiple patches', async () => {
    const { manifestPath, packageDirs } = await setupTestEnvironment({
      testDir: path.join(testDir, 'multi1'),
      patches: [
        {
          purl: 'pkg:npm/pkg-a@1.0.0',
          uuid: TEST_UUID_A,
          files: {
            'package/index.js': {
              beforeContent: 'a-original',
              afterContent: 'a-patched',
            },
          },
        },
        {
          purl: 'pkg:npm/pkg-b@2.0.0',
          uuid: TEST_UUID_B,
          files: {
            'package/index.js': {
              beforeContent: 'b-original',
              afterContent: 'b-patched',
            },
          },
        },
      ],
      initialState: 'after',
    })

    const pkgADir = packageDirs.get('pkg:npm/pkg-a@1.0.0')!
    const pkgBDir = packageDirs.get('pkg:npm/pkg-b@2.0.0')!

    const { rollbackPatches } = await import('./rollback.js')

    const cwd = path.dirname(manifestPath).replace('/.socket', '')

    // Rollback only pkg-a
    const { success } = await rollbackPatches(
      cwd,
      manifestPath,
      'pkg:npm/pkg-a@1.0.0',
      false,
      true,
      false, // not offline
    )

    assert.equal(success, true)

    // pkg-a should be rolled back, pkg-b should remain patched
    assert.equal(await readPackageFile(pkgADir, 'index.js'), 'a-original')
    assert.equal(await readPackageFile(pkgBDir, 'index.js'), 'b-patched')

    // Remove pkg-a from manifest
    const manifestContent = await fs.readFile(manifestPath, 'utf-8')
    const manifest = PatchManifestSchema.parse(JSON.parse(manifestContent))

    delete manifest.patches['pkg:npm/pkg-a@1.0.0']
    await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n')

    // Verify manifest still has pkg-b
    const updatedManifest = JSON.parse(await fs.readFile(manifestPath, 'utf-8'))
    assert.equal(updatedManifest.patches['pkg:npm/pkg-a@1.0.0'], undefined)
    assert.ok(updatedManifest.patches['pkg:npm/pkg-b@2.0.0'])
  })
})

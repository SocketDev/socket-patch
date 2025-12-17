import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'fs/promises'
import * as path from 'path'
import * as os from 'os'
import { cleanupUnusedBlobs } from './cleanup-blobs.js'
import type { PatchManifest } from '../schema/manifest-schema.js'

// Valid UUIDs for testing
const TEST_UUID = '11111111-1111-4111-8111-111111111111'

// Sample hashes for testing
const BEFORE_HASH_1 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111'
const AFTER_HASH_1 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111'
const BEFORE_HASH_2 = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2222'
const AFTER_HASH_2 = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2222'
const ORPHAN_HASH = 'oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'

function createTestManifest(): PatchManifest {
  return {
    patches: {
      'pkg:npm/pkg-a@1.0.0': {
        uuid: TEST_UUID,
        exportedAt: '2024-01-01T00:00:00Z',
        files: {
          'package/index.js': {
            beforeHash: BEFORE_HASH_1,
            afterHash: AFTER_HASH_1,
          },
          'package/lib/utils.js': {
            beforeHash: BEFORE_HASH_2,
            afterHash: AFTER_HASH_2,
          },
        },
        vulnerabilities: {},
        description: 'Test patch',
        license: 'MIT',
        tier: 'free',
      },
    },
  }
}

describe('cleanup-blobs', () => {
  let tempDir: string
  let blobsDir: string

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'socket-patch-test-'))
    blobsDir = path.join(tempDir, 'blobs')
    await fs.mkdir(blobsDir, { recursive: true })
  })

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  describe('cleanupUnusedBlobs', () => {
    it('should keep afterHash blobs and remove orphan blobs', async () => {
      const manifest = createTestManifest()

      // Create blobs on disk
      await fs.writeFile(path.join(blobsDir, AFTER_HASH_1), 'after content 1')
      await fs.writeFile(path.join(blobsDir, AFTER_HASH_2), 'after content 2')
      await fs.writeFile(path.join(blobsDir, ORPHAN_HASH), 'orphan content')

      const result = await cleanupUnusedBlobs(manifest, blobsDir)

      // Should remove only the orphan blob
      assert.equal(result.blobsRemoved, 1)
      assert.ok(result.removedBlobs.includes(ORPHAN_HASH))

      // afterHash blobs should still exist
      await fs.access(path.join(blobsDir, AFTER_HASH_1))
      await fs.access(path.join(blobsDir, AFTER_HASH_2))

      // Orphan blob should be removed
      await assert.rejects(
        fs.access(path.join(blobsDir, ORPHAN_HASH)),
        /ENOENT/,
      )
    })

    it('should remove beforeHash blobs since they are downloaded on-demand', async () => {
      const manifest = createTestManifest()

      // Create both beforeHash and afterHash blobs
      await fs.writeFile(path.join(blobsDir, BEFORE_HASH_1), 'before content 1')
      await fs.writeFile(path.join(blobsDir, BEFORE_HASH_2), 'before content 2')
      await fs.writeFile(path.join(blobsDir, AFTER_HASH_1), 'after content 1')
      await fs.writeFile(path.join(blobsDir, AFTER_HASH_2), 'after content 2')

      const result = await cleanupUnusedBlobs(manifest, blobsDir)

      // Should remove the beforeHash blobs (they're downloaded on-demand during rollback)
      assert.equal(result.blobsRemoved, 2)
      assert.ok(result.removedBlobs.includes(BEFORE_HASH_1))
      assert.ok(result.removedBlobs.includes(BEFORE_HASH_2))

      // afterHash blobs should still exist
      await fs.access(path.join(blobsDir, AFTER_HASH_1))
      await fs.access(path.join(blobsDir, AFTER_HASH_2))

      // beforeHash blobs should be removed
      await assert.rejects(
        fs.access(path.join(blobsDir, BEFORE_HASH_1)),
        /ENOENT/,
      )
      await assert.rejects(
        fs.access(path.join(blobsDir, BEFORE_HASH_2)),
        /ENOENT/,
      )
    })

    it('should not remove anything in dry-run mode', async () => {
      const manifest = createTestManifest()

      // Create blobs on disk (including beforeHash blobs which should be marked for removal)
      await fs.writeFile(path.join(blobsDir, BEFORE_HASH_1), 'before content 1')
      await fs.writeFile(path.join(blobsDir, AFTER_HASH_1), 'after content 1')

      const result = await cleanupUnusedBlobs(manifest, blobsDir, true) // dry-run

      // Should report beforeHash as would-be-removed
      assert.equal(result.blobsRemoved, 1)
      assert.ok(result.removedBlobs.includes(BEFORE_HASH_1))

      // But both blobs should still exist
      await fs.access(path.join(blobsDir, BEFORE_HASH_1))
      await fs.access(path.join(blobsDir, AFTER_HASH_1))
    })

    it('should handle empty manifest (remove all blobs)', async () => {
      const manifest: PatchManifest = { patches: {} }

      // Create some blobs
      await fs.writeFile(path.join(blobsDir, AFTER_HASH_1), 'content 1')
      await fs.writeFile(path.join(blobsDir, BEFORE_HASH_1), 'content 2')

      const result = await cleanupUnusedBlobs(manifest, blobsDir)

      // Should remove all blobs since none are referenced
      assert.equal(result.blobsRemoved, 2)
    })

    it('should handle non-existent blobs directory', async () => {
      const manifest = createTestManifest()
      const nonExistentDir = path.join(tempDir, 'non-existent')

      const result = await cleanupUnusedBlobs(manifest, nonExistentDir)

      // Should return empty result
      assert.equal(result.blobsChecked, 0)
      assert.equal(result.blobsRemoved, 0)
    })
  })
})

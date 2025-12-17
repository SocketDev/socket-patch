import { describe, it, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'fs/promises'
import * as path from 'path'
import * as os from 'os'
import { getMissingBlobs } from './blob-fetcher.js'
import type { PatchManifest } from '../schema/manifest-schema.js'

// Valid UUIDs for testing
const TEST_UUID = '11111111-1111-4111-8111-111111111111'

// Sample hashes for testing
const BEFORE_HASH_1 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111'
const AFTER_HASH_1 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111'
const BEFORE_HASH_2 = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2222'
const AFTER_HASH_2 = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2222'

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

describe('blob-fetcher', () => {
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

  describe('getMissingBlobs', () => {
    it('should return only missing afterHash blobs when all blobs are missing', async () => {
      const manifest = createTestManifest()
      const missing = await getMissingBlobs(manifest, blobsDir)

      // Should only include afterHash blobs, NOT beforeHash blobs
      assert.equal(missing.size, 2)
      assert.ok(missing.has(AFTER_HASH_1))
      assert.ok(missing.has(AFTER_HASH_2))
      assert.ok(!missing.has(BEFORE_HASH_1))
      assert.ok(!missing.has(BEFORE_HASH_2))
    })

    it('should not include afterHash blobs that already exist', async () => {
      const manifest = createTestManifest()

      // Create one of the afterHash blobs
      await fs.writeFile(path.join(blobsDir, AFTER_HASH_1), 'test content')

      const missing = await getMissingBlobs(manifest, blobsDir)

      // Should only include the missing afterHash blob
      assert.equal(missing.size, 1)
      assert.ok(!missing.has(AFTER_HASH_1)) // exists on disk
      assert.ok(missing.has(AFTER_HASH_2))  // missing
    })

    it('should return empty set when all afterHash blobs exist', async () => {
      const manifest = createTestManifest()

      // Create all afterHash blobs
      await fs.writeFile(path.join(blobsDir, AFTER_HASH_1), 'test content 1')
      await fs.writeFile(path.join(blobsDir, AFTER_HASH_2), 'test content 2')

      const missing = await getMissingBlobs(manifest, blobsDir)

      // Should be empty - all required blobs exist
      assert.equal(missing.size, 0)
    })

    it('should ignore beforeHash blobs even if they exist on disk', async () => {
      const manifest = createTestManifest()

      // Create beforeHash blobs (not afterHash blobs)
      await fs.writeFile(path.join(blobsDir, BEFORE_HASH_1), 'before content 1')
      await fs.writeFile(path.join(blobsDir, BEFORE_HASH_2), 'before content 2')

      const missing = await getMissingBlobs(manifest, blobsDir)

      // Should still report afterHash blobs as missing
      assert.equal(missing.size, 2)
      assert.ok(missing.has(AFTER_HASH_1))
      assert.ok(missing.has(AFTER_HASH_2))
    })

    it('should return empty set for empty manifest', async () => {
      const manifest: PatchManifest = { patches: {} }
      const missing = await getMissingBlobs(manifest, blobsDir)
      assert.equal(missing.size, 0)
    })

    it('should work even if blobs directory does not exist', async () => {
      const manifest = createTestManifest()
      const nonExistentDir = path.join(tempDir, 'non-existent-blobs')

      const missing = await getMissingBlobs(manifest, nonExistentDir)

      // Should return all afterHash blobs as missing
      assert.equal(missing.size, 2)
      assert.ok(missing.has(AFTER_HASH_1))
      assert.ok(missing.has(AFTER_HASH_2))
    })
  })
})

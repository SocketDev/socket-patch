import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  getReferencedBlobs,
  getAfterHashBlobs,
  getBeforeHashBlobs,
} from './operations.js'
import type { PatchManifest } from '../schema/manifest-schema.js'

// Valid UUIDs for testing
const TEST_UUID_1 = '11111111-1111-4111-8111-111111111111'
const TEST_UUID_2 = '22222222-2222-4222-8222-222222222222'

// Sample hashes for testing
const BEFORE_HASH_1 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111'
const AFTER_HASH_1 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111'
const BEFORE_HASH_2 = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2222'
const AFTER_HASH_2 = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2222'
const BEFORE_HASH_3 = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee3333'
const AFTER_HASH_3 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3333'

function createTestManifest(): PatchManifest {
  return {
    patches: {
      'pkg:npm/pkg-a@1.0.0': {
        uuid: TEST_UUID_1,
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
        description: 'Test patch 1',
        license: 'MIT',
        tier: 'free',
      },
      'pkg:npm/pkg-b@2.0.0': {
        uuid: TEST_UUID_2,
        exportedAt: '2024-01-01T00:00:00Z',
        files: {
          'package/main.js': {
            beforeHash: BEFORE_HASH_3,
            afterHash: AFTER_HASH_3,
          },
        },
        vulnerabilities: {},
        description: 'Test patch 2',
        license: 'MIT',
        tier: 'free',
      },
    },
  }
}

describe('manifest operations', () => {
  describe('getReferencedBlobs', () => {
    it('should return all blobs (both beforeHash and afterHash)', () => {
      const manifest = createTestManifest()
      const blobs = getReferencedBlobs(manifest)

      // Should contain all 6 hashes (3 before + 3 after)
      assert.equal(blobs.size, 6)
      assert.ok(blobs.has(BEFORE_HASH_1))
      assert.ok(blobs.has(AFTER_HASH_1))
      assert.ok(blobs.has(BEFORE_HASH_2))
      assert.ok(blobs.has(AFTER_HASH_2))
      assert.ok(blobs.has(BEFORE_HASH_3))
      assert.ok(blobs.has(AFTER_HASH_3))
    })

    it('should return empty set for empty manifest', () => {
      const manifest: PatchManifest = { patches: {} }
      const blobs = getReferencedBlobs(manifest)
      assert.equal(blobs.size, 0)
    })

    it('should deduplicate blobs with same hash', () => {
      // Create a manifest where two files have the same beforeHash
      const manifest: PatchManifest = {
        patches: {
          'pkg:npm/pkg-a@1.0.0': {
            uuid: TEST_UUID_1,
            exportedAt: '2024-01-01T00:00:00Z',
            files: {
              'package/file1.js': {
                beforeHash: BEFORE_HASH_1,
                afterHash: AFTER_HASH_1,
              },
              'package/file2.js': {
                beforeHash: BEFORE_HASH_1, // Same beforeHash as file1
                afterHash: AFTER_HASH_2,
              },
            },
            vulnerabilities: {},
            description: 'Test',
            license: 'MIT',
            tier: 'free',
          },
        },
      }

      const blobs = getReferencedBlobs(manifest)
      // Should be 3 unique hashes, not 4
      assert.equal(blobs.size, 3)
    })
  })

  describe('getAfterHashBlobs', () => {
    it('should return only afterHash blobs', () => {
      const manifest = createTestManifest()
      const blobs = getAfterHashBlobs(manifest)

      // Should contain only 3 afterHash blobs
      assert.equal(blobs.size, 3)
      assert.ok(blobs.has(AFTER_HASH_1))
      assert.ok(blobs.has(AFTER_HASH_2))
      assert.ok(blobs.has(AFTER_HASH_3))

      // Should NOT contain beforeHash blobs
      assert.ok(!blobs.has(BEFORE_HASH_1))
      assert.ok(!blobs.has(BEFORE_HASH_2))
      assert.ok(!blobs.has(BEFORE_HASH_3))
    })

    it('should return empty set for empty manifest', () => {
      const manifest: PatchManifest = { patches: {} }
      const blobs = getAfterHashBlobs(manifest)
      assert.equal(blobs.size, 0)
    })
  })

  describe('getBeforeHashBlobs', () => {
    it('should return only beforeHash blobs', () => {
      const manifest = createTestManifest()
      const blobs = getBeforeHashBlobs(manifest)

      // Should contain only 3 beforeHash blobs
      assert.equal(blobs.size, 3)
      assert.ok(blobs.has(BEFORE_HASH_1))
      assert.ok(blobs.has(BEFORE_HASH_2))
      assert.ok(blobs.has(BEFORE_HASH_3))

      // Should NOT contain afterHash blobs
      assert.ok(!blobs.has(AFTER_HASH_1))
      assert.ok(!blobs.has(AFTER_HASH_2))
      assert.ok(!blobs.has(AFTER_HASH_3))
    })

    it('should return empty set for empty manifest', () => {
      const manifest: PatchManifest = { patches: {} }
      const blobs = getBeforeHashBlobs(manifest)
      assert.equal(blobs.size, 0)
    })
  })

  describe('relationship between functions', () => {
    it('afterHash + beforeHash should equal all referenced blobs', () => {
      const manifest = createTestManifest()
      const allBlobs = getReferencedBlobs(manifest)
      const afterBlobs = getAfterHashBlobs(manifest)
      const beforeBlobs = getBeforeHashBlobs(manifest)

      // Union of afterBlobs and beforeBlobs should equal allBlobs
      const union = new Set([...afterBlobs, ...beforeBlobs])
      assert.equal(union.size, allBlobs.size)
      for (const blob of allBlobs) {
        assert.ok(union.has(blob))
      }
    })

    it('afterHash and beforeHash should be disjoint (no overlap) in typical cases', () => {
      const manifest = createTestManifest()
      const afterBlobs = getAfterHashBlobs(manifest)
      const beforeBlobs = getBeforeHashBlobs(manifest)

      // Check no overlap
      for (const blob of afterBlobs) {
        assert.ok(!beforeBlobs.has(blob), `${blob} appears in both sets`)
      }
    })
  })
})

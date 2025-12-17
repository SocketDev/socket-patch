import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'fs/promises'
import * as path from 'path'
import {
  createTestDir,
  removeTestDir,
  computeTestHash,
} from '../test-utils.js'
import type { PatchResponse } from '../utils/api-client.js'

/**
 * Simulates the savePatch function behavior to test blob saving logic
 * This mirrors the logic in download.ts
 * NOTE: Only saves afterHash blobs - beforeHash blobs are downloaded on-demand during rollback
 */
async function simulateSavePatch(
  patch: PatchResponse,
  blobsDir: string,
): Promise<Record<string, { beforeHash?: string; afterHash?: string }>> {
  const files: Record<string, { beforeHash?: string; afterHash?: string }> = {}

  for (const [filePath, fileInfo] of Object.entries(patch.files)) {
    if (fileInfo.afterHash) {
      files[filePath] = {
        beforeHash: fileInfo.beforeHash,
        afterHash: fileInfo.afterHash,
      }
    }

    // Save after blob content if provided
    // Note: beforeHash blobs are NOT saved here - they are downloaded on-demand during rollback
    if (fileInfo.blobContent && fileInfo.afterHash) {
      const blobPath = path.join(blobsDir, fileInfo.afterHash)
      const blobBuffer = Buffer.from(fileInfo.blobContent, 'base64')
      await fs.writeFile(blobPath, blobBuffer)
    }
  }

  return files
}

describe('download command', () => {
  let testDir: string

  before(async () => {
    testDir = await createTestDir('download-test-')
  })

  after(async () => {
    await removeTestDir(testDir)
  })

  describe('savePatch blob storage', () => {
    it('should only save after blobs (before blobs are downloaded on-demand)', async () => {
      const blobsDir = path.join(testDir, 'blobs1')
      await fs.mkdir(blobsDir, { recursive: true })

      const beforeContent = 'console.log("original");'
      const afterContent = 'console.log("patched");'

      const beforeHash = computeTestHash(beforeContent)
      const afterHash = computeTestHash(afterContent)

      const patch: PatchResponse = {
        uuid: 'test-uuid-1',
        purl: 'pkg:npm/test@1.0.0',
        publishedAt: new Date().toISOString(),
        files: {
          'package/index.js': {
            beforeHash,
            afterHash,
            blobContent: Buffer.from(afterContent).toString('base64'),
            beforeBlobContent: Buffer.from(beforeContent).toString('base64'),
          },
        },
        vulnerabilities: {},
        description: 'Test patch',
        license: 'MIT',
        tier: 'free',
      }

      await simulateSavePatch(patch, blobsDir)

      // Verify only after blob is saved (before blobs are downloaded on-demand during rollback)
      const beforeBlobPath = path.join(blobsDir, beforeHash)
      const afterBlobPath = path.join(blobsDir, afterHash)

      const afterBlobContent = await fs.readFile(afterBlobPath, 'utf-8')
      assert.equal(afterBlobContent, afterContent)

      // Before blob should NOT exist (downloaded on-demand during rollback)
      await assert.rejects(
        async () => fs.access(beforeBlobPath),
        /ENOENT/,
      )
    })

    it('should only save after blob when before blob content is not provided', async () => {
      const blobsDir = path.join(testDir, 'blobs2')
      await fs.mkdir(blobsDir, { recursive: true })

      const beforeContent = 'console.log("original");'
      const afterContent = 'console.log("patched");'

      const beforeHash = computeTestHash(beforeContent)
      const afterHash = computeTestHash(afterContent)

      const patch: PatchResponse = {
        uuid: 'test-uuid-2',
        purl: 'pkg:npm/test@1.0.0',
        publishedAt: new Date().toISOString(),
        files: {
          'package/index.js': {
            beforeHash,
            afterHash,
            blobContent: Buffer.from(afterContent).toString('base64'),
            // beforeBlobContent is NOT provided
          },
        },
        vulnerabilities: {},
        description: 'Test patch',
        license: 'MIT',
        tier: 'free',
      }

      await simulateSavePatch(patch, blobsDir)

      // Verify only after blob is saved
      const afterBlobPath = path.join(blobsDir, afterHash)
      const afterBlobContent = await fs.readFile(afterBlobPath, 'utf-8')
      assert.equal(afterBlobContent, afterContent)

      // Before blob should not exist
      const beforeBlobPath = path.join(blobsDir, beforeHash)
      await assert.rejects(
        async () => fs.access(beforeBlobPath),
        /ENOENT/,
      )
    })

    it('should handle multiple files with blobs (only after blobs saved)', async () => {
      const blobsDir = path.join(testDir, 'blobs3')
      await fs.mkdir(blobsDir, { recursive: true })

      const files = {
        'package/index.js': {
          before: 'index-before',
          after: 'index-after',
        },
        'package/lib/utils.js': {
          before: 'utils-before',
          after: 'utils-after',
        },
      }

      const patch: PatchResponse = {
        uuid: 'test-uuid-3',
        purl: 'pkg:npm/test@1.0.0',
        publishedAt: new Date().toISOString(),
        files: {},
        vulnerabilities: {},
        description: 'Test patch',
        license: 'MIT',
        tier: 'free',
      }

      for (const [filePath, { before, after }] of Object.entries(files)) {
        patch.files[filePath] = {
          beforeHash: computeTestHash(before),
          afterHash: computeTestHash(after),
          blobContent: Buffer.from(after).toString('base64'),
          beforeBlobContent: Buffer.from(before).toString('base64'),
        }
      }

      await simulateSavePatch(patch, blobsDir)

      // Verify only after blobs are saved (before blobs are downloaded on-demand)
      for (const [, { before, after }] of Object.entries(files)) {
        const beforeHash = computeTestHash(before)
        const afterHash = computeTestHash(after)

        // After blob should exist
        const afterBlobContent = await fs.readFile(
          path.join(blobsDir, afterHash),
          'utf-8',
        )
        assert.equal(afterBlobContent, after)

        // Before blob should NOT exist
        await assert.rejects(
          async () => fs.access(path.join(blobsDir, beforeHash)),
          /ENOENT/,
        )
      }
    })

    it('should handle binary file content (only after blob saved)', async () => {
      const blobsDir = path.join(testDir, 'blobs4')
      await fs.mkdir(blobsDir, { recursive: true })

      // Create binary content
      const beforeContent = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xff])
      const afterContent = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xfe])

      const beforeHash = computeTestHash(beforeContent.toString('binary'))
      const afterHash = computeTestHash(afterContent.toString('binary'))

      const patch: PatchResponse = {
        uuid: 'test-uuid-4',
        purl: 'pkg:npm/test@1.0.0',
        publishedAt: new Date().toISOString(),
        files: {
          'package/binary.bin': {
            beforeHash,
            afterHash,
            blobContent: afterContent.toString('base64'),
            beforeBlobContent: beforeContent.toString('base64'),
          },
        },
        vulnerabilities: {},
        description: 'Test patch',
        license: 'MIT',
        tier: 'free',
      }

      await simulateSavePatch(patch, blobsDir)

      // Verify only after binary blob is saved
      const afterBlobBuffer = await fs.readFile(path.join(blobsDir, afterHash))
      assert.deepEqual(afterBlobBuffer, afterContent)

      // Before blob should NOT exist
      await assert.rejects(
        async () => fs.access(path.join(blobsDir, beforeHash)),
        /ENOENT/,
      )
    })

    it('should deduplicate after blobs with same content', async () => {
      const blobsDir = path.join(testDir, 'blobs5')
      await fs.mkdir(blobsDir, { recursive: true })

      // Same after content for two different files (to test deduplication)
      const sharedAfterContent = 'shared after content'
      const beforeContent1 = 'before1'
      const beforeContent2 = 'before2'

      const sharedAfterHash = computeTestHash(sharedAfterContent)

      const patch: PatchResponse = {
        uuid: 'test-uuid-5',
        purl: 'pkg:npm/test@1.0.0',
        publishedAt: new Date().toISOString(),
        files: {
          'package/file1.js': {
            beforeHash: computeTestHash(beforeContent1),
            afterHash: sharedAfterHash, // Same after hash
            blobContent: Buffer.from(sharedAfterContent).toString('base64'),
            beforeBlobContent: Buffer.from(beforeContent1).toString('base64'),
          },
          'package/file2.js': {
            beforeHash: computeTestHash(beforeContent2),
            afterHash: sharedAfterHash, // Same after hash
            blobContent: Buffer.from(sharedAfterContent).toString('base64'),
            beforeBlobContent: Buffer.from(beforeContent2).toString('base64'),
          },
        },
        vulnerabilities: {},
        description: 'Test patch',
        license: 'MIT',
        tier: 'free',
      }

      await simulateSavePatch(patch, blobsDir)

      // Shared after blob should exist only once (content-addressable)
      const blobFiles = await fs.readdir(blobsDir)
      const sharedBlobCount = blobFiles.filter(f => f === sharedAfterHash).length
      assert.equal(sharedBlobCount, 1)

      // Only 1 blob should be saved (the shared after blob)
      // Before blobs are NOT saved
      assert.equal(blobFiles.length, 1)

      // Content should be correct
      const blobContent = await fs.readFile(path.join(blobsDir, sharedAfterHash), 'utf-8')
      assert.equal(blobContent, sharedAfterContent)
    })
  })
})

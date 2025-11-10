import * as fs from 'fs'
import * as fsp from 'fs/promises'
import { computeGitSHA256FromChunks } from '../hash/git-sha256.js'

/**
 * Compute Git-compatible SHA256 hash of file contents using streaming
 */
export async function computeFileGitSHA256(filepath: string): Promise<string> {
  // Get file size first
  const stats = await fsp.stat(filepath)
  const fileSize = stats.size

  // Create async iterable from read stream
  async function* readFileChunks() {
    const stream = fs.createReadStream(filepath)
    for await (const chunk of stream) {
      yield chunk as Buffer
    }
  }

  return computeGitSHA256FromChunks(fileSize, readFileChunks())
}

import * as crypto from 'crypto'

/**
 * Compute Git-compatible SHA256 hash for a buffer
 * @param buffer - Buffer or Uint8Array to hash
 * @returns Git-compatible SHA256 hash (hex string)
 */
export function computeGitSHA256FromBuffer(
  buffer: Buffer | Uint8Array,
): string {
  const gitHash = crypto.createHash('sha256')
  const header = `blob ${buffer.length}\0`
  gitHash.update(header)
  gitHash.update(buffer)
  return gitHash.digest('hex')
}

/**
 * Compute Git-compatible SHA256 hash from an async iterable of chunks
 * @param size - Total size of the file in bytes
 * @param chunks - Async iterable of Buffer or Uint8Array chunks
 * @returns Git-compatible SHA256 hash (hex string)
 */
export async function computeGitSHA256FromChunks(
  size: number,
  chunks: AsyncIterable<Buffer | Uint8Array>,
): Promise<string> {
  const gitHash = crypto.createHash('sha256')
  const header = `blob ${size}\0`
  gitHash.update(header)

  for await (const chunk of chunks) {
    gitHash.update(chunk)
  }

  return gitHash.digest('hex')
}

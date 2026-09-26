import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = path.resolve(packageDir, '..', '..', '..')
const profile = process.env.SOCKET_PATCH_NODE_CARGO_PROFILE || 'release'
const targetDir = process.env.CARGO_TARGET_DIR
  ? path.resolve(process.env.CARGO_TARGET_DIR)
  : path.join(repoRoot, 'target')

const cargo = spawnSync(
  'cargo',
  ['build', '--locked', '--profile', profile, '-p', 'socket-patch-node'],
  { cwd: repoRoot, stdio: 'inherit' },
)
if (cargo.error) {
  throw cargo.error
}
if (cargo.status !== 0) {
  process.exit(cargo.status ?? 1)
}

const libraryName =
  process.platform === 'win32'
    ? 'socket_patch_node.dll'
    : process.platform === 'darwin'
      ? 'libsocket_patch_node.dylib'
      : 'libsocket_patch_node.so'
const profileDir = profile === 'dev' ? 'debug' : profile
const built = path.join(targetDir, profileDir, libraryName)
if (!existsSync(built)) {
  console.error(`build:addon: ${built} was not produced`)
  process.exit(1)
}
const destination = path.join(packageDir, 'socket_patch_node.node')
copyFileSync(built, destination)
console.log(`build:addon: copied ${built} -> ${destination}`)

#!/usr/bin/env node
// Regenerates crates/socket-patch-core/tests/fixtures/pnpm-registry-overrides.
//
// Hosted mode can route a patched npm package through a pnpm named registry:
// pnpm-workspace.yaml declares the patch server's registry of each patch
// under `namedRegistries` (`socket-<first digits of the patch UUID>`) and
// points an `overrides` entry per patched release at its own, and
// pnpm-lock.yaml carries what pnpm itself resolves for that configuration. The scan writes that lock without running pnpm, so these
// fixtures pin its output to pnpm's: each case holds a project as pnpm locked
// it (`project/`), the patches a scan is granted (`patches.json`), and the
// files pnpm ends with once the workspace file routes those patches
// (`expected/`).
//
//   node scripts/gen-pnpm-registry-override-golden.mjs <pnpm> [<pnpm>...]
//
// Every argument is a pnpm executable (>= 11.20). The first one writes the
// fixtures; each of the others must produce byte-identical lockfiles, or the
// script fails. No network is used: a registry stub on a loopback port serves
// a handful of synthetic packages as the default registry, and a second one
// stands in for the patch server. Like the real one it answers, under the
// directory each patch is served from
// (`/patch/npm/<name>/<version>/<token>/<patch uuid>/`), the one-version
// document of that patch's package, with the package's own dependency fields
// and the tarball URL in that same directory, and a 404 for every other name;
// it lists no `deprecated` (that is the upstream registry's state, not the
// tarball's). The patch server's loopback origin is replaced by
// `https://patch.test` in what is written, so the fixtures do not depend on
// the port.
//
// `expected/pnpm-workspace.yaml` is not pnpm's output: the script writes it
// the way the scan does (the tests assert the scan writes the same bytes),
// and pnpm resolves the lock from it.

import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import zlib from 'node:zlib'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

// PNPM_REGISTRY_GOLDEN_OUT writes somewhere else, to compare pnpm releases
// without touching the committed fixtures.
const FIXTURES =
  process.env.PNPM_REGISTRY_GOLDEN_OUT ??
  path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    '../crates/socket-patch-core/tests/fixtures/pnpm-registry-overrides',
  )
const ORIGIN = 'https://patch.test'
const TOKEN = '22222222-2222-4222-8222-222222222222'
const uuid = n => `${n.repeat(8)}-${n.repeat(4)}-4${n.repeat(3)}-8${n.repeat(3)}-${n.repeat(12)}`

// The synthetic registry: name -> version -> the manifest fields pnpm reads.
const PACKAGES = {
  leaf: { '1.0.0': { engines: { node: '>=8' } }, '2.0.0': {} },
  mid: { '1.0.0': { dependencies: { leaf: '^1.0.0' } } },
  '@scope/direct': { '1.0.0': { dependencies: { leaf: '^1.0.0' }, bin: { direct: 'index.js' } } },
  host: { '1.0.0': {}, '1.1.0': {} },
  'peer-user': { '1.0.0': { peerDependencies: { host: '^1.0.0' }, dependencies: { leaf: '^1.0.0' } } },
  'peer-parent': { '1.0.0': { peerDependencies: { host: '^1.0.0' }, dependencies: { child: '^1.0.0' } } },
  'peer-of-peer': { '1.0.0': { peerDependencies: { 'peer-user': '^1.0.0', host: '^1.0.0' } } },
  child: { '1.0.0': {} },
  'uses-two': { '1.0.0': { dependencies: { leaf: '^2.0.0' } } },
  other: { '1.0.0': {}, '1.1.0': {} },
  old: { '1.0.0': { deprecated: 'use something else' } },
  // A deprecation message of several lines, which pnpm locks as a block
  // scalar (`deprecated: |-` and its lines).
  'old-notes': { '1.0.0': { deprecated: 'use something else\nsecond line: with a colon\n  indented third' } },
  native: { '1.0.0': { os: ['darwin', 'linux'], cpu: ['x64', 'arm64'] } },
  'opt-peers': {
    '1.0.0': {
      peerDependencies: { host: '^1.0.0', other: '^1.0.0' },
      peerDependenciesMeta: { host: { optional: true }, other: { optional: true } },
    },
  },
}

// A patch of `name@version`; `id` is one hex digit (repeated into a UUID) or
// a whole UUID.
const patch = (name, version, id) => ({ name, version, uuid: id.length === 1 ? uuid(id) : id })

// `manifests`: importer directory -> package.json fields. `workspace`: the
// pnpm-workspace.yaml the project already has. `pin`: package.json names the running pnpm in `packageManager`, which pnpm
// 12 records in the lock as a second YAML document; `pnpm`: the case is
// generated only by the first pnpm whose version starts with this.
// `refuses`: pnpm does not lock the routed project as a respelling of the
// plain one, so the scan refuses the route with this reason; `expected/` is
// then the first pnpm's lock, kept as the record of what pnpm does.
const CASES = {
  'transitive-leaf': {
    manifests: { '.': { dependencies: { mid: '1.0.0' } } },
    patches: [patch('leaf', '1.0.0', '1')],
  },
  'scoped-direct': {
    manifests: { '.': { dependencies: { '@scope/direct': '^1.0.0' } } },
    patches: [patch('@scope/direct', '1.0.0', '1')],
  },
  'own-peers': {
    manifests: { '.': { dependencies: { 'peer-user': '1.0.0', host: '1.0.0' } } },
    patches: [patch('peer-user', '1.0.0', '1')],
  },
  'peer-suffixed-parent': {
    manifests: { '.': { dependencies: { 'peer-parent': '1.0.0', host: '1.0.0' } } },
    patches: [patch('child', '1.0.0', '1')],
  },
  'patched-peer': {
    manifests: { '.': { dependencies: { 'peer-user': '1.0.0', host: '1.0.0' } } },
    patches: [patch('host', '1.0.0', '1')],
  },
  'peers-both': {
    manifests: { '.': { dependencies: { 'peer-user': '1.0.0', host: '1.0.0', 'peer-of-peer': '1.0.0' } } },
    patches: [patch('host', '1.0.0', '1'), patch('peer-user', '1.0.0', '2')],
  },
  // One package in two peer contexts, only one of which holds the patched
  // release. pnpm 12 records no `version:` for that package, pnpm 11 does.
  'peer-variants': {
    refuses: 'both with and without host@1.0.0 as its peer',
    workspace: "packages:\n  - 'packages/*'\n",
    manifests: {
      '.': {},
      'packages/a': { dependencies: { 'peer-user': '1.0.0', host: '1.0.0' } },
      'packages/b': { dependencies: { 'peer-user': '1.0.0', host: '1.1.0' } },
    },
    patches: [patch('host', '1.0.0', '1')],
  },
  // The patched release as an optional peer: pnpm resolves the copy of the
  // importer that does not depend on it from the default registry, around
  // the override, so that copy stays unpatched.
  'optional-peer': {
    refuses: 'host@1.0.0 as an optional peer of opt-peers@1.0.0',
    workspace: "packages:\n  - 'packages/*'\n",
    manifests: {
      '.': {},
      'packages/a': { dependencies: { 'opt-peers': '1.0.0', host: '1.0.0' } },
      'packages/b': { dependencies: { 'opt-peers': '1.0.0', other: '1.0.0' } },
    },
    patches: [patch('host', '1.0.0', '1')],
  },
  'sibling-version': {
    manifests: { '.': { dependencies: { mid: '1.0.0', 'uses-two': '1.0.0' } } },
    patches: [patch('leaf', '1.0.0', '1')],
  },
  'both-versions': {
    manifests: { '.': { dependencies: { mid: '1.0.0', 'uses-two': '1.0.0' } } },
    patches: [patch('leaf', '1.0.0', '1'), patch('leaf', '2.0.0', '2')],
  },
  'workspace-importers': {
    workspace: "packages:\n  - 'packages/*'\n",
    manifests: {
      '.': { devDependencies: { leaf: '^1.0.0' } },
      'packages/a': { dependencies: { leaf: '1.0.0', mid: '1.0.0' } },
      'packages/b': { optionalDependencies: { leaf: '~1.0.0' }, dependencies: { host: '^1.0.0' } },
    },
    patches: [patch('leaf', '1.0.0', '1')],
  },
  // Each member installs from its own lock, and every one of them records
  // the workspace file's overrides, the member with no patched package too.
  'member-locks': {
    workspace: "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
    manifests: {
      '.': { devDependencies: { leaf: '^1.0.0' } },
      'packages/a': { dependencies: { leaf: '1.0.0', mid: '1.0.0' } },
      'packages/b': { dependencies: { host: '^1.0.0' } },
    },
    patches: [patch('leaf', '1.0.0', '1')],
  },
  'user-overrides': {
    workspace: '# pinned by the team\noverrides:\n  other: 1.0.0\n',
    manifests: { '.': { dependencies: { mid: '1.0.0', other: '^1.0.0' } } },
    patches: [patch('leaf', '1.0.0', '1')],
  },
  // The project has registries of its own, one of them under the very name
  // the patch's registry would take: ours takes four more digits.
  'user-registry': {
    workspace: 'namedRegistries:\n  socket: https://npm.corp.example/\n  socket-11111111: https://npm.work.example/\n',
    manifests: { '.': { dependencies: { mid: '1.0.0' } } },
    patches: [patch('leaf', '1.0.0', '1')],
  },
  // Two patches whose UUIDs start with the same eight digits: both names
  // take four more.
  'shared-digits': {
    manifests: { '.': { dependencies: { '@scope/direct': '1.0.0' } } },
    patches: [
      patch('leaf', '1.0.0', 'aaaaaaaa-1111-4111-8111-111111111111'),
      patch('@scope/direct', '1.0.0', 'aaaaaaaa-2222-4222-8222-222222222222'),
    ],
  },
  // A transitive leaf, a package with peer dependencies, a scoped direct
  // dependency.
  'three-packages': {
    manifests: { '.': { dependencies: { '@scope/direct': '1.0.0', 'peer-user': '1.0.0', host: '1.0.0' } } },
    patches: [patch('leaf', '1.0.0', '3'), patch('peer-user', '1.0.0', '2'), patch('@scope/direct', '1.0.0', '1')],
  },
  several: {
    manifests: { '.': { dependencies: { '@scope/direct': '1.0.0', mid: '1.0.0', old: '1.0.0', native: '1.0.0' } } },
    patches: [patch('leaf', '1.0.0', '3'), patch('@scope/direct', '1.0.0', '1'), patch('old', '1.0.0', '2'), patch('native', '1.0.0', '4')],
  },
  // The upstream registry's remark on the patched release spans lines:
  // the routed entry carries none of it.
  'deprecated-block': {
    manifests: { '.': { dependencies: { 'old-notes': '1.0.0', mid: '1.0.0' } } },
    patches: [patch('old-notes', '1.0.0', '1')],
  },
  'pinned-pnpm': {
    pnpm: '12.',
    pin: true,
    manifests: { '.': { dependencies: { mid: '1.0.0' } } },
    patches: [patch('leaf', '1.0.0', '1')],
  },
}

// ── the stub registry ───────────────────────────────────────────────────────

const leafOf = name => name.split('/').pop()
const sri = bytes => `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`

/** A package tarball: the same bytes on every platform and Node version. */
function tarball(name, version, patched) {
  const manifest = `${JSON.stringify({ name, version, ...PACKAGES[name][version] }, null, 2)}\n`
  const index = `${patched ? '/* patched */\n' : ''}module.exports = ${JSON.stringify(`${name}@${version}`)}\n`
  const blocks = []
  for (const [file, text] of [['package/package.json', manifest], ['package/index.js', index]]) {
    const body = Buffer.from(text)
    const header = Buffer.alloc(512)
    header.write(file, 0)
    header.write('0000644\0', 100)
    header.write('0000000\0', 108)
    header.write('0000000\0', 116)
    header.write(`${body.length.toString(8).padStart(11, '0')}\0`, 124)
    header.write('00000000000\0', 136)
    header.write('        ', 148)
    header.write('0', 156)
    header.write('ustar\x0000', 257)
    let sum = 0
    for (const byte of header) sum += byte
    header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148)
    blocks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512))
  }
  blocks.push(Buffer.alloc(1024))
  // Stored blocks and a fixed OS byte: no zlib build changes the bytes.
  const gz = zlib.gzipSync(Buffer.concat(blocks), { level: 0 })
  gz[9] = 3
  return gz
}

const patchPath = p => `/patch/npm/${p.name}/${p.version}/${TOKEN}/${p.uuid}/`
const artifactUrl = (origin, p) => `${origin}${patchPath(p)}${leafOf(p.name)}-${p.version}.tgz`

/** A patch's registry address: the directory its tarball is served from. */
const registryAddress = (origin, p) => `${origin}${patchPath(p)}`

const digitsOf = p => p.uuid.replaceAll('-', '')
/** The names the workspace file `text` declares registries under. */
const declaredNames = text =>
  [...(text ?? '').matchAll(/^ {2}([^\s:#'"]+):/gm)].map(match => match[1])
/**
 * A patch's registry name, as the scan picks it: `socket-` and the first
 * eight hex digits of the patch UUID, four more at a time while another
 * patch of the project starts with the same digits or the project declares
 * that name itself.
 */
function aliasOf(p, patches, workspace) {
  const digits = digitsOf(p)
  const taken = declaredNames(workspace)
  for (let length = 8; length <= 32; length += 4) {
    const head = digits.slice(0, length)
    const shared = patches.some(other => other.uuid !== p.uuid && digitsOf(other).startsWith(head))
    if (!shared && !taken.includes(`socket-${head}`)) return `socket-${head}`
  }
  throw new Error(`no registry name is free for ${p.uuid}`)
}

/** The fields a registry lists for a version; `upstream` adds the registry's own state. */
function versionDocument(name, version, tarballUrl, patched) {
  const { deprecated, ...manifest } = PACKAGES[name][version]
  const bytes = tarball(name, version, patched)
  const document = { name, version, ...manifest, dist: { tarball: tarballUrl, integrity: sri(bytes) } }
  return !patched && deprecated ? { ...document, deprecated } : document
}

/** One loopback server answering `handler(url, origin)` with `[status, body, type?]`. */
function serve(handler) {
  const server = http.createServer((req, res) => {
    const origin = `http://127.0.0.1:${server.address().port}`
    const [status, body, type = 'application/json'] = handler(decodeURIComponent(req.url.split('?')[0]), origin)
    const bytes = Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body))
    res.writeHead(status, { 'content-type': type, 'content-length': bytes.length })
    res.end(bytes)
  })
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => resolve({ server, origin: `http://127.0.0.1:${server.address().port}` }))
  })
}

const NOT_FOUND = [404, { error: 'not found' }]

/** The default registry: every synthetic package, as npm serves one. */
function startRegistry() {
  return serve((url, origin) => {
    const file = url.match(/^\/(.+)\/-\/.+-(\d+\.\d+\.\d+)\.tgz$/)
    if (file && PACKAGES[file[1]]?.[file[2]]) {
      return [200, tarball(file[1], file[2], false), 'application/octet-stream']
    }
    const name = url.slice(1)
    const versions = PACKAGES[name]
    if (!versions) return NOT_FOUND
    const published = '2020-01-01T00:00:00.000Z'
    const time = { created: published, modified: published }
    const documents = {}
    for (const version of Object.keys(versions)) {
      documents[version] = versionDocument(name, version, `${origin}/${name}/-/${leafOf(name)}-${version}.tgz`, false)
      time[version] = published
    }
    return [200, { name, 'dist-tags': { latest: Object.keys(versions).pop() }, versions: documents, time }]
  })
}

/**
 * The patch server, on its own origin as in production. Under the directory
 * a patch is served from it answers the one-version document of that patch's
 * package, the tarball listed in that same directory, and the tarball
 * itself; every other name there is a 404.
 */
function startPatchServer(patches) {
  return serve((url, origin) => {
    for (const p of patches) {
      if (url === `${patchPath(p)}${p.name}`) {
        const versions = { [p.version]: versionDocument(p.name, p.version, artifactUrl(origin, p), true) }
        return [200, { name: p.name, 'dist-tags': { latest: p.version }, versions }]
      }
      if (url === new URL(artifactUrl(origin, p)).pathname) {
        return [200, tarball(p.name, p.version, true), 'application/octet-stream']
      }
    }
    return NOT_FOUND
  })
}

// ── pnpm ────────────────────────────────────────────────────────────────────

function run(bin, cwd, sandbox, args) {
  const env = { PATH: process.env.PATH, CI: '1', HOME: path.join(sandbox, 'home') }
  for (const dir of ['CACHE', 'DATA', 'STATE', 'CONFIG']) {
    env[`XDG_${dir}_HOME`] = path.join(sandbox, dir.toLowerCase())
  }
  return new Promise(resolve => {
    const child = spawn(bin, [...args, '--store-dir', path.join(sandbox, 'store')], { cwd, env })
    let text = ''
    child.stdout.on('data', chunk => (text += chunk))
    child.stderr.on('data', chunk => (text += chunk))
    child.on('close', code => resolve({ code, text }))
  })
}

/** Every `pnpm-lock.yaml` of the project, by project-relative path. */
function locks(proj) {
  const found = {}
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules') continue
      const file = path.join(dir, entry.name)
      if (entry.isDirectory()) walk(file)
      else if (entry.name === 'pnpm-lock.yaml') found[path.relative(proj, file).split(path.sep).join('/')] = fs.readFileSync(file, 'utf8')
    }
  }
  walk(proj)
  return found
}

async function lockfileOnly(bin, proj, sandbox, what) {
  const { code, text } = await run(bin, proj, sandbox, ['install', '--lockfile-only'])
  if (code !== 0) throw new Error(`${what}: pnpm install --lockfile-only failed\n${text}`)
  return locks(proj)
}

// ── the workspace file, as the scan writes it ───────────────────────────────

const overrideKey = p => `${p.name}@${p.version}`

function scanWorkspace(existing, origin, patches) {
  const alias = p => aliasOf(p, patches, existing)
  const registries = [...patches]
    .sort((a, b) => (alias(a) < alias(b) ? -1 : 1))
    .map(p => `  ${alias(p)}: ${registryAddress(origin, p)}`)
  const overrides = [...patches]
    .sort((a, b) => (overrideKey(a) < overrideKey(b) ? -1 : 1))
    .map(p => `  '${overrideKey(p)}': '${alias(p)}:${p.version}'`)
  if (existing == null) {
    return ['packages:', "  - '.'", 'namedRegistries:', ...registries, 'overrides:', ...overrides, ''].join('\n')
  }
  const lines = existing.replace(/\n$/, '').split('\n')
  // An existing map takes its entries after its own; a missing one is appended.
  for (const [map, entries] of [['namedRegistries:', registries], ['overrides:', overrides]]) {
    const at = lines.indexOf(map)
    if (at === -1) {
      lines.push(map, ...entries)
      continue
    }
    let end = at + 1
    while (end < lines.length && lines[end].startsWith(' ')) end++
    lines.splice(end, 0, ...entries)
  }
  return [...lines, ''].join('\n')
}

// ── main ────────────────────────────────────────────────────────────────────

async function generate(bin, name, c) {
  const registry = await startRegistry()
  const { server, origin } = await startPatchServer(c.patches)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pnpm-registry-golden-'))
  try {
    const proj = path.join(tmp, 'proj')
    const version = (await run(bin, tmp, path.join(tmp, 'sandbox'), ['--version'])).text.trim().split('\n').pop()
    const files = {}
    for (const [dir, manifest] of Object.entries(c.manifests)) {
      const fields = { name: dir === '.' ? 'app' : path.basename(dir), version: '1.0.0', private: true }
      if (dir === '.' && c.pin) fields.packageManager = `pnpm@${version}`
      files[path.join(dir, 'package.json')] = `${JSON.stringify({ ...fields, ...manifest }, null, 2)}\n`
    }
    if (c.workspace) files['pnpm-workspace.yaml'] = c.workspace
    for (const [rel, text] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(proj, rel)), { recursive: true })
      fs.writeFileSync(path.join(proj, rel), text)
    }
    fs.writeFileSync(path.join(proj, '.npmrc'), `registry=${registry.origin}/\n`)
    const sandbox = path.join(tmp, 'sandbox')
    const normal = text => text.split(origin).join(ORIGIN)
    const under = (dir, texts) => Object.fromEntries(Object.entries(texts).map(([rel, text]) => [`${dir}/${rel}`, normal(text)]))

    const before = await lockfileOnly(bin, proj, sandbox, `${name} (before)`)
    const workspace = scanWorkspace(c.workspace, origin, c.patches)
    fs.writeFileSync(path.join(proj, 'pnpm-workspace.yaml'), workspace)
    const after = await lockfileOnly(bin, proj, sandbox, `${name} (after)`)
    if (fs.readFileSync(path.join(proj, 'pnpm-workspace.yaml'), 'utf8') !== workspace) {
      throw new Error(`${name}: pnpm rewrote pnpm-workspace.yaml`)
    }
    const patches = c.patches.map(p => ({
      name: p.name,
      version: p.version,
      uuid: p.uuid,
      artifactUrl: artifactUrl(ORIGIN, p),
      npmRegistryUrl: registryAddress(ORIGIN, p),
      sha512: sri(tarball(p.name, p.version, true)),
    }))
    return {
      ...under('project', before),
      ...under('project', files),
      'patches.json': `${JSON.stringify(patches, null, 2)}\n`,
      ...under('expected', after),
      'expected/pnpm-workspace.yaml': normal(workspace),
      ...(c.refuses ? { 'refuses.txt': `${c.refuses}\n` } : {}),
    }
  } finally {
    server.close()
    registry.server.close()
    fs.rmSync(tmp, { recursive: true, force: true })
  }
}

const bins = process.argv.slice(2)
if (bins.length === 0) {
  console.error('usage: gen-pnpm-registry-override-golden.mjs <pnpm> [<pnpm>...]')
  process.exit(2)
}
const versions = []
for (const bin of bins) {
  const { text } = await run(bin, os.tmpdir(), fs.mkdtempSync(path.join(os.tmpdir(), 'pnpm-version-')), ['--version'])
  versions.push(text.trim().split('\n').pop())
}
let failed = false
for (const [name, c] of Object.entries(CASES)) {
  const use = bins.filter((_, i) => !c.pnpm || versions[i].startsWith(c.pnpm))
  // A lock that holds the pnpm that wrote it has no second pnpm to agree with.
  if (c.pnpm) use.splice(1)
  if (use.length === 0) {
    console.log(`${name}: skipped (needs pnpm ${c.pnpm}x; the committed fixture is kept)`)
    continue
  }
  const first = await generate(use[0], name, c)
  for (const bin of use.slice(1)) {
    const other = await generate(bin, name, c)
    for (const rel of Object.keys(first).filter(rel => rel.endsWith('pnpm-lock.yaml'))) {
      if (c.refuses && rel.startsWith('expected/')) continue
      if (other[rel] !== first[rel]) {
        console.error(`${name}: ${rel} differs between ${use[0]} and ${bin}`)
        failed = true
      }
    }
  }
  const dir = path.join(FIXTURES, name)
  fs.rmSync(dir, { recursive: true, force: true })
  for (const [rel, text] of Object.entries(first)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true })
    fs.writeFileSync(path.join(dir, rel), text)
  }
  console.log(`${name}: written (pnpm ${use.map(bin => versions[bins.indexOf(bin)]).join(', ')})`)
}
process.exit(failed ? 1 : 0)

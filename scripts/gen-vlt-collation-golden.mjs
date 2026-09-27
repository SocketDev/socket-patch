#!/usr/bin/env node
// Prints crates/socket-patch-core/tests/fixtures/vlt/collation-golden.json:
// vlt's lockfile orders (graph/src/lockfile/save.ts formatNodes/formatEdges)
// over DepIDs of every era, computed by Node's ICU. Regenerate with Node
// 24.21 under LANG=C LC_ALL=C:
//
//   node scripts/gen-vlt-collation-golden.mjs \
//     > crates/socket-patch-core/tests/fixtures/vlt/collation-golden.json

const EXPECTED_NODE = '24.21.0'
if (process.versions.node !== EXPECTED_NODE) {
  process.stderr.write(
    `warning: generated with Node ${process.versions.node}; the golden is pinned to ${EXPECTED_NODE}\n`,
  )
}

const collate = (a, b) => a.localeCompare(b, 'en')

const alphabet = []
for (let c = 0x20; c < 0x7f; c++) {
  alphabet.push(String.fromCharCode(c))
}
alphabet.push('·', '§')
alphabet.sort(collate)
const inTable = new Set(alphabet)

const TILDE_ESCAPE = {
  _: '__',
  '+': '_p',
  '\\': '_b',
  ':': '_c',
  '~': '_t',
  '<': '_l',
  '>': '_g',
  '"': '_q',
  '|': '_i',
  '?': '_m',
  '*': '_a',
  ' ': '_s',
}

const encodeTilde = s => {
  let out = ''
  for (const ch of s) {
    if (ch === '/') {
      out += '+'
    } else if (TILDE_ESCAPE[ch]) {
      out += TILDE_ESCAPE[ch]
    } else if (ch.charCodeAt(0) <= 0x1f) {
      out += '_' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')
    } else {
      out += ch
    }
  }
  return out.endsWith('.') ? `${out.slice(0, -1)}_d` : out
}

const encodeLegacy = s =>
  encodeURIComponent(s).replaceAll('%40', '@').replaceAll('%2F', '§')

const ERAS = {
  legacy: { d: '·', enc: encodeLegacy, root: 'file·.' },
  tilde: { d: '~', enc: encodeTilde, root: 'file~_d' },
}

const registryId = (era, segment, nameVersion, extra) => {
  const { d, enc } = ERAS[era]
  const tail = extra === undefined ? '' : `${d}${enc(extra)}`
  return `${d}${enc(segment)}${d}${enc(nameVersion)}${tail}`
}

const typedId = (era, type, first, second) => {
  const { d, enc } = ERAS[era]
  const tail = second === undefined ? '' : `${d}${enc(second)}`
  return `${type}${d}${enc(first)}${tail}`
}

const NAMES = [
  'a',
  'A',
  'ab',
  'aB',
  'Ab',
  'a-b',
  'a_b',
  'a__b',
  'a.b',
  'a1',
  'a~b',
  'ms',
  'MS',
  'z',
  'zz',
  '0x',
  'is-number',
  'react-dom',
  'react',
  'left-pad',
  'JSONStream',
  'use-sync-external-store',
  '@a/b',
  '@A/b',
  '@scope/bar',
  '@scope/bar-baz',
  '@scope_x/bar',
  '@isaacs/string-locale-compare',
  '@sindresorhus/is',
  '@jsr/std__semver',
]
const VERSIONS = ['1.0.0', '1.0.0-rc.1', '1.0.0+build.1', '2.1.3', '10.0.0']
const SEGMENTS = {
  legacy: ['', 'npm', 'acme', 'http://127.0.0.1:4873/'],
  tilde: ['npm', 'acme', 'jsr', 'https://registry.example.com/npm/'],
}
const EXTRAS = {
  legacy: [undefined, ':root > #debug > #ms', 'ṗ:3'],
  tilde: [
    undefined,
    'peer.2',
    'peer.dbd5ca8b03a66489',
    ':root > #to-regex-range > #is-number',
  ],
}
const UUIDS = [
  '0b1f6e2a-3c4d-4e5f-8a9b-0c1d2e3f4a5b',
  '80630680-4da6-45f9-bba8-b888e0ffd58c',
  'ffffffff-2222-4333-8444-555555555555',
]

const vendoredDir = (uuid, name, version) => {
  const slash = name.indexOf('/')
  const leaf =
    slash < 0 ? `${name}-${version}` : `${name.slice(0, slash)}/${name.slice(slash + 1)}-${version}`
  return `.socket/vendor/npm/${uuid}/${leaf}/node_modules/${name}`
}

const ids = new Set()
for (const era of Object.keys(ERAS)) {
  NAMES.forEach((name, n) => {
    VERSIONS.forEach((version, v) => {
      const segment = SEGMENTS[era][(n + v) % SEGMENTS[era].length]
      ids.add(registryId(era, segment, `${name}@${version}`))
      ids.add(registryId(era, SEGMENTS[era][0], `${name}@${version}`))
      const extra = EXTRAS[era][(n * 3 + v) % EXTRAS[era].length]
      if (extra !== undefined) {
        ids.add(registryId(era, SEGMENTS[era][1], `${name}@${version}`, extra))
      }
    })
    const uuid = UUIDS[n % UUIDS.length]
    ids.add(typedId(era, 'file', vendoredDir(uuid, name, VERSIONS[n % VERSIONS.length])))
  })
  const { root } = ERAS[era]
  ids.add(root)
  for (const path of ['packages/a', 'packages/b', 'packages/my_lib', 'apps/web-1']) {
    ids.add(typedId(era, 'workspace', path))
  }
  for (const path of ['..', '../x', 'vendor/x', 'vendor/x.tgz', './packages/a', 'a b/c']) {
    ids.add(typedId(era, 'file', path))
  }
  for (const url of ['https://e.com/r-1.0.0.tgz', 'https://e.com/R-1.0.0.tgz', 'http://h/x.tgz']) {
    ids.add(typedId(era, 'remote', url))
  }
  for (const [remote, selector] of [
    ['github:user/proj', 'v1.0.0'],
    ['github:user/proj', 'semver:^1'],
    ['git+ssh://git@host/x.git', 'main'],
  ]) {
    ids.add(typedId(era, 'git', remote, selector))
  }
}

const nodes = [...ids]
for (const id of nodes) {
  for (const ch of id) {
    if (!inTable.has(ch)) {
      throw new Error(`${JSON.stringify(id)} holds ${JSON.stringify(ch)}, outside the table`)
    }
  }
}
if (nodes.length < 400) {
  throw new Error(`only ${nodes.length} DepIDs`)
}
nodes.sort(collate)
for (let i = 1; i < nodes.length; i++) {
  if (collate(nodes[i - 1], nodes[i]) >= 0) {
    throw new Error(`tie between ${nodes[i - 1]} and ${nodes[i]}`)
  }
}

const isImporter = id =>
  id === 'file~_d' ||
  id === 'file·.' ||
  /^workspace[~·]./.test(id)

const TYPES = ['prod', 'dev', 'optional', 'peer', 'peerOptional']
const registryNodes = nodes.filter(id => id.startsWith('~') || id.startsWith('·'))
const importers = nodes.filter(isImporter)
const sources = [...importers, ...registryNodes.filter((_, i) => i % 17 === 0)]
const edges = []
const seen = new Set()
sources.forEach((from, f) => {
  for (let k = 0; k < 4; k++) {
    const type = TYPES[(f + k) % TYPES.length]
    const to =
      (f + k) % 11 === 0 ? 'MISSING' : registryNodes[(f * 7 + k * 13) % registryNodes.length]
    const tieKey = `${from} ${type} ${to}`
    if (seen.has(tieKey)) {
      continue
    }
    seen.add(tieKey)
    edges.push({ from, type, to, name: `dep-${f}-${k}`, spec: k % 2 ? '^1.0.0 || ^2' : '1.0.0' })
  }
})
const toId = e => (e.to === 'MISSING' ? '' : e.to)
edges.sort(
  (a, b) =>
    Number(isImporter(b.from)) - Number(isImporter(a.from)) ||
    collate(a.from, b.from) ||
    collate(a.type, b.type) ||
    collate(toId(a), toId(b)),
)
for (let i = 1; i < edges.length; i++) {
  const [a, b] = [edges[i - 1], edges[i]]
  if (
    isImporter(a.from) === isImporter(b.from) &&
    collate(a.from, b.from) === 0 &&
    collate(a.type, b.type) === 0 &&
    collate(toId(a), toId(b)) === 0
  ) {
    throw new Error(`edge tie at ${i}`)
  }
}

process.stdout.write(
  `${JSON.stringify(
    {
      alphabet: alphabet.join(''),
      nodes,
      edges: edges.map(e => [`${e.from} ${e.name}`, `${e.type} ${e.spec} ${e.to}`]),
    },
    null,
    2,
  )}\n`,
)

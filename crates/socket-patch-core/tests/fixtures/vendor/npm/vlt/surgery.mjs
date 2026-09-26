// Independent JS reading of DESIGN §4.5 (vendored vlt wiring of a direct
// target), used only to build the byte-stability fixtures: its output is
// handed to real `vlt ci`, and the lock vlt writes back is the expected
// lock. Orders with Node's own `localeCompare(…, 'en')`, like vlt.
//
// usage: node surgery.mjs <project> <name@version> <uuid>
// prints {"refusal": code, "detail": …} or {"rel": …, "fileId": …}
import fs from 'node:fs'
import path from 'node:path'

const [proj, target, uuid] = process.argv.slice(2)
const at = target.lastIndexOf('@')
const name = target.slice(0, at)
const version = target.slice(at + 1)

const lockPath = path.join(proj, 'vlt-lock.json')
const text = fs.readFileSync(lockPath, 'utf8')
const lock = JSON.parse(text)
const v1 = lock.lockfileVersion === 1
const D = v1 ? '~' : '·'
const options = lock.options ?? {}

const TILDE_ESC = {
  _: '__', '+': '_p', '\\': '_b', ':': '_c', '~': '_t', '<': '_l', '>': '_g',
  '"': '_q', '|': '_i', '?': '_m', '*': '_a', ' ': '_s',
}
const TILDE_UNESC = Object.fromEntries(
  Object.entries(TILDE_ESC).map(([k, v]) => [v, k]),
)
const enc = s => {
  if (!v1) {
    return encodeURIComponent(s).replaceAll('%40', '@').replaceAll('%2F', '§')
  }
  const out = [...s].map(c => (c === '/' ? '+' : (TILDE_ESC[c] ?? c))).join('')
  return out.endsWith('.') ? out.slice(0, -1) + '_d' : out
}
const dec = s => {
  if (!v1) {
    return decodeURIComponent(s.replaceAll('@', '%40').replaceAll('§', '%2F'))
  }
  let out = ''
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '_') {
      const two = s.slice(i, i + 2)
      if (two === '_d' && i + 2 === s.length) {
        out += '.'
      } else if (TILDE_UNESC[two]) {
        out += TILDE_UNESC[two]
      } else {
        throw new Error('undecodable ' + s)
      }
      i++
    } else {
      out += s[i] === '+' ? '/' : s[i]
    }
  }
  return out
}

const lines = text.split('\n')
const block = header => {
  const open = lines.findIndex(l => l.replace(/\r$/, '') === `  "${header}": {`)
  let close = open + 1
  while (!/^  },?\r?$/.test(lines[close])) close++
  return [open, close]
}
const ENTRY = /^    ("(?:[^"\\]|\\.)*"): (.*?)(,?)(\r?)$/
const entries = ([open, close]) =>
  lines.slice(open + 1, close).map(l => {
    const m = ENTRY.exec(l)
    return { key: JSON.parse(m[1]), val: m[2], cr: m[4] }
  })
const [nOpen, nClose] = block('nodes')
const [eOpen, eClose] = block('edges')
let nodes = entries([nOpen, nClose])
let edges = entries([eOpen, eClose])

const refuse = (code, detail) => {
  console.log(JSON.stringify({ refusal: code, detail }))
  process.exit(0)
}

const registryOf = key => {
  const parts = key.split(D)
  if (parts[0] !== '' || parts.length < 3 || parts.length > 4) return null
  const second = dec(parts[2])
  const i = second.lastIndexOf('@')
  return {
    segment: dec(parts[1]),
    name: second.slice(0, i),
    version: second.slice(i + 1),
    extra: parts[3],
  }
}
const withSlash = u => (u.endsWith('/') ? u : u + '/')
const isDefault = seg => {
  const alias = typeof options['default-registry-alias'] === 'string'
    ? options['default-registry-alias'] : 'npm'
  if (seg === '' || seg === alias) return true
  const reg = options.registry
  return typeof reg === 'string' && /^https?:/.test(seg) &&
    withSlash(seg) === withSlash(reg)
}
const instances = nodes
  .map(n => ({ n, r: registryOf(n.key) }))
  .filter(({ r }) => r && r.name === name && r.version === version)
if (instances.some(({ r }) => !isDefault(r.segment))) {
  refuse('vendor_lock_entry_unsupported', "not from vlt's default registry")
}
if (instances.length > 1 || instances.some(({ r }) => r.extra !== undefined)) {
  refuse('vendor_lock_entry_unsupported', 'peer/modifier variants; use --mode hosted')
}
if (instances.length === 0) refuse('vendor_lock_entry_not_found', `${target}`)
const reg = instances[0].n

const isImporter = id =>
  id === 'file~_d' || id === 'file·.' ||
  (id.startsWith('workspace~') && id.length > 10) ||
  (id.startsWith('workspace·') && id.length > 10)
const parseEdge = e => {
  const from = e.key.slice(0, e.key.indexOf(' '))
  const dep = e.key.slice(e.key.indexOf(' ') + 1)
  const v = JSON.parse(e.val)
  const type = v.slice(0, v.indexOf(' '))
  const to = v.slice(v.lastIndexOf(' ') + 1)
  const spec = v.slice(v.indexOf(' ') + 1, v.lastIndexOf(' '))
  return { from, dep, type, spec, to }
}
const inbound = edges.filter(e => parseEdge(e).to === reg.key)
for (const e of inbound) {
  const p = parseEdge(e)
  if (!isImporter(p.from)) refuse('vendor_vlt_transitive_unsupported', e.key)
  if (!['prod', 'dev', 'optional'].includes(p.type)) {
    refuse('vendor_lock_entry_unsupported', 'peer edge')
  }
}

const scope = name.startsWith('@') ? name.slice(0, name.indexOf('/') + 1) : ''
const bare = name.slice(scope.length)
const rel = `.socket/vendor/npm/${uuid}/${scope}${bare}-${version}/node_modules/${name}`
const fileId = 'file' + D + enc(rel)

const tuple = JSON.parse(reg.val)
const tail = reg.val.slice(1, -1)
const elems = []
{
  let depth = 0, inStr = false, start = 0
  for (let i = 0; i < tail.length; i++) {
    const c = tail[i]
    if (inStr) {
      if (c === '\\') i++
      else if (c === '"') inStr = false
    } else if (c === '"') inStr = true
    else if (c === '[' || c === '{') depth++
    else if (c === ']' || c === '}') depth--
    else if (c === ',' && depth === 0) {
      elems.push(tail.slice(start, i))
      start = i + 1
    }
  }
  elems.push(tail.slice(start))
}
if (elems.length !== tuple.length) throw new Error('tuple split')
const fileElems = [elems[0], elems[1], 'null', JSON.stringify(rel), ...elems.slice(4)]
const newNode = { key: fileId, val: `[${fileElems.join(',')}]`, cr: reg.cr }

const pkgs = new Map()
const readPkg = dir => {
  if (!pkgs.has(dir)) {
    const file = path.join(proj, dir, 'package.json')
    pkgs.set(dir, { file, json: JSON.parse(fs.readFileSync(file, 'utf8')) })
  }
  return pkgs.get(dir)
}
const FIELD = { prod: 'dependencies', dev: 'devDependencies', optional: 'optionalDependencies' }
const pkgEdits = []
const importerEdges = []
for (const e of inbound) {
  const p = parseEdge(e)
  const dir = p.from.startsWith('workspace') ? dec(p.from.slice(10)) : ''
  const r = path.posix.relative(dir || '.', rel)
  const spec = 'file:' + (r.startsWith('../') ? r : './' + r)
  const pkg = readPkg(dir)
  const declared = ['dependencies', 'devDependencies', 'optionalDependencies']
    .filter(f => pkg.json[f] && Object.hasOwn(pkg.json[f], p.dep))
  if (declared.length > 1) {
    refuse('vendor_lock_entry_unsupported', 'declared in multiple dependency fields')
  }
  const field = FIELD[p.type]
  if (pkg.json[field]?.[p.dep] !== p.spec) refuse('vendor_vlt_lock_out_of_sync', e.key)
  pkgEdits.push({ dir, field, dep: p.dep, spec, pkg })
  importerEdges.push({
    key: e.key,
    val: JSON.stringify(`${p.type} ${spec} ${fileId}`),
    cr: e.cr,
  })
}
pkgEdits.sort((a, b) =>
  a.dir < b.dir ? -1 : a.dir > b.dir ? 1
    : a.field < b.field ? -1 : a.field > b.field ? 1
      : a.dep < b.dep ? -1 : a.dep > b.dep ? 1 : 0)
const outgoing = edges
  .filter(e => parseEdge(e).from === reg.key)
  .map(e => ({ key: fileId + e.key.slice(reg.key.length), val: e.val, cr: e.cr }))

const touchedEdgeKeys = new Set([...inbound, ...edges.filter(e => parseEdge(e).from === reg.key)]
  .map(e => e.key))
nodes = nodes.filter(n => n.key !== reg.key)
edges = edges.filter(e => !touchedEdgeKeys.has(e.key))

const coll = (a, b) => a.localeCompare(b, 'en')
const edgeCmp = (a, b) => {
  const A = parseEdge(a)
  const B = parseEdge(b)
  const toA = A.to === 'MISSING' ? '' : A.to
  const toB = B.to === 'MISSING' ? '' : B.to
  return (Number(isImporter(B.from)) - Number(isImporter(A.from))) ||
    coll(A.from, B.from) || coll(A.type, B.type) || coll(toA, toB)
}
const insert = (list, items, cmp) => {
  for (const it of items) {
    let i = list.findIndex(x => cmp(it, x) < 0)
    if (i < 0) i = list.length
    list.splice(i, 0, it)
  }
  return list
}
nodes = insert(nodes, [newNode], (a, b) => coll(a.key, b.key))
edges = insert(edges, [...importerEdges, ...outgoing], edgeCmp)
const render = list =>
  list.map((x, i) => `    ${JSON.stringify(x.key)}: ${x.val}${i < list.length - 1 ? ',' : ''}${x.cr}`)
const out = [
  ...lines.slice(0, nOpen + 1), ...render(nodes),
  ...lines.slice(nClose, eOpen + 1), ...render(edges),
  ...lines.slice(eClose),
]
fs.writeFileSync(lockPath, out.join('\n'))
for (const { field, dep, spec, pkg } of pkgEdits) pkg.json[field][dep] = spec
for (const pkg of pkgs.values()) {
  fs.writeFileSync(pkg.file, JSON.stringify(pkg.json, null, 2) + '\n')
}
console.log(JSON.stringify({ rel, fileId }))

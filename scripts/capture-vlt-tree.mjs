#!/usr/bin/env node
// Prints the on-disk layout of a vlt-installed project as the listing the
// crawler tests stage (crates/socket-patch-core/tests/fixtures/vlt-trees/):
// every node_modules/.vlt entry (real package dirs with their package.json
// identity, dependency links, other real dirs), the store's top-level files,
// the internal hoist dir, and the importer node_modules of the root and of
// each workspace member. Store entry names are kept byte for byte.
//
//   node scripts/capture-vlt-tree.mjs <project-root> <vlt-version> \
//     > crates/socket-patch-core/tests/fixtures/vlt-trees/<vlt-version>/listing.json

import fs from 'node:fs'
import path from 'node:path'

const [root, vltVersion] = process.argv.slice(2)
if (!root || !vltVersion) {
  process.stderr.write('usage: capture-vlt-tree.mjs <project-root> <vlt-version>\n')
  process.exit(2)
}

const byteOrder = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))
const sortedDir = (dir) => fs.readdirSync(dir).sort(byteOrder)

const identity = (dir) => {
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'))
  return { name: pkg.name, version: pkg.version }
}

const describe = (full) => {
  const st = fs.lstatSync(full)
  if (st.isSymbolicLink()) {
    return { link: fs.readlinkSync(full) }
  }
  if (st.isDirectory() && fs.existsSync(path.join(full, 'package.json'))) {
    return { pkg: identity(full) }
  }
  if (st.isDirectory()) {
    return { dir: true }
  }
  return { file: true }
}

const listModules = (nm) => {
  const out = {}
  if (!fs.existsSync(nm)) {
    return out
  }
  for (const child of sortedDir(nm)) {
    const full = path.join(nm, child)
    const st = fs.lstatSync(full)
    if (child.startsWith('@') && st.isDirectory() && !st.isSymbolicLink()) {
      for (const scoped of sortedDir(full)) {
        out[`${child}/${scoped}`] = describe(path.join(full, scoped))
      }
    } else if (child === '.bin' && st.isDirectory()) {
      out[child] = { dir: true }
    } else {
      out[child] = describe(full)
    }
  }
  return out
}

const nm = path.join(root, 'node_modules')
const store = path.join(nm, '.vlt')
const lockPath = path.join(root, 'vlt-lock.json')
const lock = fs.existsSync(lockPath) ? JSON.parse(fs.readFileSync(lockPath, 'utf8')) : {}

const entries = []
const storeFiles = []
for (const name of sortedDir(store)) {
  const full = path.join(store, name)
  const st = fs.lstatSync(full)
  if (name === 'node_modules' || !st.isDirectory()) {
    if (!st.isDirectory()) {
      storeFiles.push(name)
    }
    continue
  }
  entries.push({ id: name, node_modules: listModules(path.join(full, 'node_modules')) })
}

const importers = listModules(nm)
delete importers['.vlt']
delete importers['.vlt-lock.json']

const members = {}
const linkTargets = {}
const recordTarget = (from, value) => {
  if (!value.link) {
    return
  }
  const target = path.relative(root, path.resolve(path.dirname(from), value.link))
  if (target.split(path.sep).includes('node_modules')) {
    return
  }
  const full = path.join(root, target)
  if (fs.existsSync(path.join(full, 'package.json'))) {
    linkTargets[target.split(path.sep).join('/')] = identity(full)
  }
}
for (const [rel, value] of Object.entries(importers)) {
  recordTarget(path.join(nm, rel), value)
}
const walkMembers = (dir) => {
  for (const child of sortedDir(dir)) {
    if (child === 'node_modules' || child.startsWith('.')) {
      continue
    }
    const full = path.join(dir, child)
    if (!fs.lstatSync(full).isDirectory()) {
      continue
    }
    const memberNm = path.join(full, 'node_modules')
    if (fs.existsSync(memberNm)) {
      const rel = path.relative(root, full).split(path.sep).join('/')
      members[rel] = listModules(memberNm)
      for (const [dep, value] of Object.entries(members[rel])) {
        recordTarget(path.join(memberNm, dep), value)
      }
    }
    walkMembers(full)
  }
}
walkMembers(root)

const listing = {
  vlt: vltVersion,
  lockfileVersion: lock.lockfileVersion ?? null,
  storeFiles,
  hoist: listModules(path.join(store, 'node_modules')),
  store: entries,
  importers,
  members,
  linkTargets,
}
process.stdout.write(`${JSON.stringify(listing, null, 1)}\n`)

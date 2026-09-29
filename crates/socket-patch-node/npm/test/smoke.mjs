import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const addon = require('../index.js')

const here = path.dirname(fileURLToPath(import.meta.url))
const fixtureDir = path.resolve(
  here,
  '../../../socket-patch-core/tests/fixtures/redirect/npm/package-lock-v3/basic',
)
const inputLock = readFileSync(path.join(fixtureDir, 'input/package-lock.json'))
const expectedLock = readFileSync(path.join(fixtureDir, 'expected/package-lock.json'), 'utf8')
const overrides = JSON.parse(readFileSync(path.join(fixtureDir, 'overrides.json'), 'utf8'))

const patches = overrides.map((o) => ({
  purl: `pkg:${o.ecosystem}/${o.namespace ? `${o.namespace}/` : ''}${o.name}@${o.version}`,
  uuid: o.patchUuid,
  reference: {
    status: 'granted',
    url: o.artifactUrl,
    purl: null,
    artifacts: [{ kind: 'tarball', url: o.artifactUrl, integrity: o.integrity }],
    registryOverride: o.registryOverride ?? null,
  },
}))

const vulnerabilities = {
  'GHSA-test-aaaa-bbbb': {
    cves: ['CVE-2024-0001'],
    summary: 's',
    severity: 'high',
    description: 'd',
  },
}

function fakeProvider(overridesByMethod = {}) {
  const calls = {
    searchPatchesBatch: 0,
    searchPatchesByPackage: 0,
    fetchRegistryReferences: 0,
    fetchPatch: 0,
    downloadArtifact: 0,
  }
  const base = {
    async searchPatchesBatch({ components }) {
      const packages = []
      for (const { purl } of components) {
        const matches = patches.filter((p) => p.purl === purl)
        if (matches.length > 0) {
          packages.push({
            purl,
            patches: matches.map((p) => ({
              uuid: p.uuid,
              purl,
              tier: 'free',
              cveIds: [],
              ghsaIds: ['GHSA-test-aaaa-bbbb'],
              severity: 'high',
              title: 'fixture',
            })),
          })
        }
      }
      return { ok: true, value: { packages, canAccessPaidPatches: false } }
    },
    async searchPatchesByPackage({ purl }) {
      return {
        ok: true,
        value: {
          patches: patches
            .filter((p) => p.purl === purl)
            .map((p) => ({
              uuid: p.uuid,
              purl,
              publishedAt: '2024-01-01T00:00:00Z',
              description: 'fixture',
              license: 'MIT',
              tier: 'free',
              vulnerabilities,
            })),
          canAccessPaidPatches: false,
        },
      }
    },
    async fetchRegistryReferences({ uuids }) {
      const results = {}
      for (const uuid of uuids) {
        const patch = patches.find((p) => p.uuid === uuid)
        if (patch) {
          results[uuid] = patch.reference
        }
      }
      return { ok: true, value: { results } }
    },
    async fetchPatch({ uuid }) {
      const patch = patches.find((p) => p.uuid === uuid)
      if (!patch) {
        return { ok: true, value: null }
      }
      return {
        ok: true,
        value: {
          uuid: patch.uuid,
          purl: patch.purl,
          publishedAt: '2024-01-01T00:00:00Z',
          files: {
            'package/index.js': { beforeHash: 'a'.repeat(64), afterHash: 'b'.repeat(64) },
          },
          vulnerabilities,
          description: 'fixture',
          license: 'MIT',
          tier: 'free',
        },
      }
    },
    async downloadArtifact() {
      return { ok: false, error: { kind: 'not_found', message: 'no artifacts in this fixture' } }
    },
  }
  const provider = {}
  for (const method of Object.keys(calls)) {
    const impl = overridesByMethod[method] ?? base[method]
    provider[method] = (request) => {
      calls[method] += 1
      return impl(request)
    }
  }
  return { provider, calls }
}

const tree = [
  { path: 'package.json', mode: '100644', type: 'blob', size: 40 },
  { path: 'package-lock.json', mode: '100644', type: 'blob', size: inputLock.length },
  { path: 'src', mode: '040000', type: 'tree' },
  { path: 'src/index.js', mode: '100644', type: 'blob', size: 10 },
  { path: 'node_modules/left-pad/package-lock.json', mode: '100644', type: 'blob', size: 10 },
  { path: 'test/fixtures/app/package-lock.json', mode: '100644', type: 'blob', size: 10 },
]

const files = {
  'package-lock.json': inputLock,
  'package.json': Buffer.from('{"name":"consumer","version":"1.0.0"}\n'),
}

function streamSelection(session, selection, chunkSize = 7) {
  for (const file of [...selection.fetchText, ...selection.fetchBinary]) {
    const bytes = files[file]
    if (bytes === undefined) {
      session.markPresent(file, 'present')
      continue
    }
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      session.pushChunk(file, bytes.subarray(offset, offset + chunkSize))
    }
    session.endFile(file)
  }
  for (const file of selection.presentOnly) {
    session.markPresent(file, 'present')
  }
  for (const file of selection.symlinks) {
    session.markPresent(file, 'symlink')
  }
}

test('engineVersion and hostedScanCandidateFiles', () => {
  assert.match(addon.engineVersion(), /^\d+\.\d+\.\d+\+.+$/)
  const candidates = addon.hostedScanCandidateFiles()
  assert.ok(Array.isArray(candidates))
  assert.ok(candidates.includes('package-lock.json'))
})

test('selectHostedScanPaths picks the root lockfile and ignores vendored trees', () => {
  const selection = addon.selectHostedScanPaths(tree)
  assert.deepEqual(selection.roots, [''])
  assert.ok(selection.fetchText.includes('package-lock.json'))
  assert.ok(!selection.fetchText.includes('node_modules/left-pad/package-lock.json'))
  assert.ok(!selection.fetchText.includes('test/fixtures/app/package-lock.json'))
  assert.deepEqual(selection.fetchBinary, [])
  assert.equal(typeof selection.ignoredCount, 'number')
  assert.ok(selection.ignoredSample.length <= 100)
})

test('streamed session redirects the package-lock fixture', async () => {
  const { provider, calls } = fakeProvider()
  const selection = addon.selectHostedScanPaths(tree, { ecosystems: ['npm'] })
  const session = new addon.HostedScanSession(
    { orgSlug: 'test-org', ecosystems: ['npm'] },
    provider,
  )
  streamSelection(session, selection)
  const result = await session.finish()

  assert.equal(result.projects.length, 1)
  const [project] = result.projects
  assert.equal(project.root, '')
  assert.equal(project.error, undefined)
  assert.deepEqual(project.redirected, [
    { purl: 'pkg:npm/left-pad@1.3.0', uuid: '22222222-2222-2222-2222-222222222222' },
  ])
  assert.equal(typeof project.redirect, 'object')

  const lock = result.changedFiles.find((f) => f.path === 'package-lock.json')
  assert.ok(lock, 'package-lock.json changed')
  assert.equal(lock.content, expectedLock)
  const paths = result.changedFiles.map((f) => f.path)
  assert.deepEqual(paths, [...paths].sort())
  assert.ok(
    !paths.some((p) => p.startsWith('.socket/')),
    `v5 hosted mode writes only lockfile/config edits, no ledger (changed: ${paths.join(', ')})`,
  )
  assert.deepEqual(result.changedBinaryFiles, [])
  assert.deepEqual(result.deletedFiles, [])
  assert.equal(result.engineVersion, addon.engineVersion())
  assert.equal(result.stats.patchesRedirected, 1)
  assert.equal(calls.searchPatchesBatch, 1)
  assert.equal(calls.fetchRegistryReferences, 1)
  assert.ok(calls.fetchPatch >= 1)
})

test('dry run previews the lockfile without patch fetches', async () => {
  const { provider, calls } = fakeProvider()
  const selection = addon.selectHostedScanPaths(tree)
  const session = new addon.HostedScanSession({ orgSlug: 'test-org', dryRun: true }, provider)
  streamSelection(session, selection, 4096)
  const result = await session.finish()
  const paths = result.changedFiles.map((f) => f.path)
  assert.ok(paths.includes('package-lock.json'))
  assert.ok(!paths.some((p) => p.startsWith('.socket/')))
  assert.equal(calls.fetchPatch, 0)
})

test('maxNewPatches defers new patches and reports the rollout block', async () => {
  const { provider } = fakeProvider()
  const selection = addon.selectHostedScanPaths(tree)
  const session = new addon.HostedScanSession({ orgSlug: 'test-org', maxNewPatches: 0 }, provider)
  streamSelection(session, selection)
  const result = await session.finish()
  const [project] = result.projects
  assert.deepEqual(project.redirected, [])
  assert.deepEqual(
    project.deferred.map((d) => [d.purl, d.rank]),
    [['pkg:npm/left-pad@1.3.0', 1]],
  )
  assert.ok(project.skipped.some((s) => s.reason === 'rollout_deferred'))
  assert.deepEqual(result.rollout.maxNewPatches, { value: 0, source: 'flag' })
  assert.deepEqual(result.rollout.counts, { new: 0, deferred: 1, upgrade: 0, already: 0 })
  assert.deepEqual(result.changedFiles, [])
})

test('provider failures become project errors, never rejections', async () => {
  for (const searchPatchesBatch of [
    async () => ({ ok: false, error: { kind: 'unauthorized', message: 'token revoked' } }),
    async () => {
      throw new Error('database unavailable')
    },
    () => {
      throw new Error('synchronous provider bug')
    },
    async () => ({ nonsense: true }),
  ]) {
    const { provider } = fakeProvider({ searchPatchesBatch })
    const selection = addon.selectHostedScanPaths(tree)
    const session = new addon.HostedScanSession({ orgSlug: 'test-org' }, provider)
    streamSelection(session, selection)
    const result = await session.finish()
    assert.equal(result.projects.length, 1)
    assert.equal(result.projects[0].error?.code, 'patch_lookup_failed')
    assert.deepEqual(result.changedFiles, [])
  }
})

test('cancel rejects a running finish with code cancelled', async () => {
  let entered
  const reached = new Promise((resolve) => {
    entered = resolve
  })
  const { provider } = fakeProvider({
    searchPatchesBatch: () => {
      entered()
      return new Promise(() => {})
    },
  })
  const selection = addon.selectHostedScanPaths(tree)
  const session = new addon.HostedScanSession({ orgSlug: 'test-org' }, provider)
  streamSelection(session, selection)
  const pending = session.finish()
  await reached
  session.cancel()
  await assert.rejects(pending, (error) => {
    assert.equal(error.code, 'cancelled')
    assert.equal(error.kind, 'cancelled')
    return true
  })
  await assert.rejects(session.finish(), (error) => error.code === 'cancelled')
})

test('a provider call that never settles times out into a project error', async () => {
  const { provider } = fakeProvider({ searchPatchesBatch: () => new Promise(() => {}) })
  const selection = addon.selectHostedScanPaths(tree)
  const session = new addon.HostedScanSession(
    { orgSlug: 'test-org', requestTimeoutMs: 50 },
    provider,
  )
  streamSelection(session, selection)
  const result = await session.finish()
  assert.equal(result.projects[0].error?.code, 'patch_lookup_failed')
})

test('cancel before finish rejects and blocks further input', async () => {
  const { provider, calls } = fakeProvider()
  const session = new addon.HostedScanSession({ orgSlug: 'test-org' }, provider)
  session.cancel()
  assert.throws(
    () => session.pushChunk('package-lock.json', inputLock),
    (error) => error.code === 'cancelled',
  )
  await assert.rejects(session.finish(), (error) => error.code === 'cancelled')
  assert.equal(calls.searchPatchesBatch, 0)
})

test('cancel before finish frees the buffered input right away', async () => {
  const { provider } = fakeProvider()
  // One whole-file chunk each: one allocation per file, which every
  // allocator returns to the OS on free, so RSS reflects what is retained.
  const fileMiB = 16
  const chunk = Buffer.alloc(fileMiB * 1024 * 1024, 0x61)
  const roots = ['a', 'b', 'c']
  const sessions = []
  const before = process.memoryUsage().rss
  for (let i = 0; i < 10; i += 1) {
    const session = new addon.HostedScanSession({ orgSlug: 'test-org' }, provider)
    for (const root of roots) {
      session.pushChunk(`${root}/package-lock.json`, chunk)
    }
    session.cancel()
    sessions.push(session)
  }
  const grownMiB = (process.memoryUsage().rss - before) / (1024 * 1024)
  const bufferedMiB = sessions.length * roots.length * fileMiB
  assert.ok(
    grownMiB < bufferedMiB / 3,
    `RSS grew ${grownMiB.toFixed(0)} MiB while ${bufferedMiB} MiB was buffered and cancelled`,
  )
  for (const session of sessions) {
    await assert.rejects(session.finish(), (error) => error.code === 'cancelled')
  }
})

function bigLock(count) {
  const packages = { '': { name: 'big', version: '1.0.0', dependencies: {} } }
  for (let i = 0; i < count; i += 1) {
    const name = `pkg-${i}`
    packages[''].dependencies[name] = '1.0.0'
    packages[`node_modules/${name}`] = {
      version: '1.0.0',
      resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`,
      integrity: `sha512-${'A'.repeat(86)}==`,
    }
  }
  return Buffer.from(
    JSON.stringify({ name: 'big', version: '1.0.0', lockfileVersion: 3, requires: true, packages }),
  )
}

test('cancel settles finish without waiting out a synchronous engine phase', async () => {
  const lock = bigLock(60000)
  const roots = ['a', 'b', 'c']
  const { provider } = fakeProvider({
    searchPatchesBatch: async () => ({
      ok: true,
      value: { packages: [], canAccessPaidPatches: false },
    }),
  })
  const start = () => {
    const session = new addon.HostedScanSession(
      { orgSlug: 'test-org', dryRun: true, projectRoots: roots, limits: { maxPurls: 200000 } },
      provider,
    )
    for (const root of roots) {
      session.pushChunk(`${root}/package-lock.json`, lock)
      session.endFile(`${root}/package-lock.json`)
      session.markPresent(`${root}/package.json`, 'present')
    }
    return session
  }

  const baselineStart = performance.now()
  const baseline = await start().finish()
  const baselineMs = performance.now() - baselineStart
  assert.equal(baseline.projects.length, roots.length)
  const inventoryMs = baseline.stats.phaseMs.inventory
  if (inventoryMs < 150) {
    return
  }

  const session = start()
  const pending = session.finish()
  await new Promise((resolve) => setTimeout(resolve, 20))
  const cancelledAt = performance.now()
  session.cancel()
  await assert.rejects(pending, (error) => error.code === 'cancelled')
  const latencyMs = performance.now() - cancelledAt
  assert.ok(
    latencyMs < inventoryMs / 3,
    `finish() settled ${latencyMs.toFixed(0)} ms after cancel (inventory ${inventoryMs} ms, run ${baselineMs.toFixed(0)} ms)`,
  )
})

test('not_found failures map per method like the HTTP API 404', async () => {
  const notFound = async () => ({ ok: false, error: { kind: 'not_found', message: 'missing' } })
  const run = async (overrides) => {
    const { provider, calls } = fakeProvider(overrides)
    const selection = addon.selectHostedScanPaths(tree)
    const session = new addon.HostedScanSession({ orgSlug: 'test-org' }, provider)
    streamSelection(session, selection)
    const result = await session.finish()
    assert.equal(result.projects.length, 1)
    return { project: result.projects[0], result, calls }
  }

  const byPackage = await run({ searchPatchesByPackage: notFound })
  assert.equal(byPackage.calls.searchPatchesByPackage, 1)
  assert.equal(byPackage.project.error, undefined)
  assert.deepEqual(byPackage.project.redirected, [])

  const references = await run({ fetchRegistryReferences: notFound })
  assert.equal(references.calls.fetchRegistryReferences, 1)
  assert.equal(references.project.error, undefined)
  assert.deepEqual(references.project.redirected, [])

  const patch = await run({ fetchPatch: notFound })
  assert.ok(patch.calls.fetchPatch >= 1)
  assert.equal(patch.project.error, undefined)

  const batch = await run({ searchPatchesBatch: notFound })
  assert.equal(batch.project.error?.code, 'patch_lookup_failed')
  assert.match(batch.project.error.message, /not_found/)
  assert.deepEqual(batch.result.changedFiles, [])
})

test('limits are enforced while streaming and poison the session', async () => {
  const { provider } = fakeProvider()
  const session = new addon.HostedScanSession(
    { orgSlug: 'test-org', limits: { maxFileBytes: 16 } },
    provider,
  )
  session.pushChunk('package-lock.json', inputLock.subarray(0, 10))
  assert.throws(
    () => session.pushChunk('package-lock.json', inputLock.subarray(10, 30)),
    (error) => error.code === 'max_file_bytes' && error.kind === 'limit',
  )
  assert.throws(
    () => session.endFile('package-lock.json'),
    (error) => error.code === 'max_file_bytes',
  )
  await assert.rejects(session.finish(), (error) => error.code === 'max_file_bytes')
})

test('invalid options and inputs throw typed errors', () => {
  const { provider } = fakeProvider()
  assert.throws(
    () => new addon.HostedScanSession({ orgSlug: 'test-org', batchSize: 0 }, provider),
    (error) => error.code === 'invalid_batch_size' && error.kind === 'invalid_input',
  )
  assert.throws(
    () => new addon.HostedScanSession({ orgSlug: 'test-org' }, null),
    TypeError,
  )
  const session = new addon.HostedScanSession({ orgSlug: 'test-org' }, provider)
  assert.throws(
    () => session.markPresent('.pnp.cjs', 'bogus'),
    (error) => error.code === 'invalid_mark_kind',
  )
})

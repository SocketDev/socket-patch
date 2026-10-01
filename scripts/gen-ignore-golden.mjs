// Regenerates crates/socket-patch-core/tests/fixtures/ignore_golden.json:
// the (patterns, path, ignored) table the socket.yml path matcher must
// agree with. The expected values come from the npm `ignore` package, the
// matcher the Socket backend applies to `projectIgnorePaths`.
//
//   cd "$(mktemp -d)" && npm init -y >/dev/null && npm i ignore@7.0.10 \
//     && NODE_PATH="$PWD/node_modules" node /path/to/scripts/gen-ignore-golden.mjs
import { createRequire } from 'node:module'
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(join(process.env.NODE_PATH ?? '.', 'x.js'))
const ignore = require('ignore')
const version = require('ignore/package.json').version

const paths = [
  'package-lock.json',
  'Cargo.lock',
  'a/package-lock.json',
  'a/b/package-lock.json',
  'a/b/c/yarn.lock',
  'services/api/package-lock.json',
  'services/payments/package-lock.json',
  'services/payments/sub/pnpm-lock.yaml',
  'legacy/requirements.txt',
  'Legacy/requirements.txt',
  'test/package-lock.json',
  'Test/package-lock.json',
  'tests/fixtures/app/package-lock.json',
  'e2e/tests/package-lock.json',
  'e2e/tests/keep/package-lock.json',
  'crates/x/tests/fixtures/app/Cargo.lock',
  'crates/x/fixtures/keep/Cargo.lock',
  'a/fixtures/keep/yarn.lock',
  'examples/demo/package-lock.json',
  'examples/package-lock.json',
  'docs/examples/package-lock.json',
  'testdata/go.sum',
  'pkg/testdata/go.sum',
  '__fixtures__/x/package.json',
  'a.lock/yarn.lock',
  'foo bar/package-lock.json',
  'x[1]/package-lock.json',
]

const sets = [
  [],
  ['/package-lock.json'],
  ['package-lock.json'],
  ['**/yarn.lock'],
  ['examples/**'],
  ['examples/'],
  ['/examples/'],
  ['examples'],
  ['crates/x/fixtures/**'],
  ['crates/*/tests/fixtures/**'],
  ['/legacy/'],
  ['legacy/'],
  ['/services/payments/'],
  ['/services/*/'],
  ['services/**/package-lock.json'],
  ['/*', '!/*/'],
  ['*', '!*/'],
  ['fixtures/', '!/a/fixtures/keep/'],
  ['fixtures/', '!fixtures/'],
  ['test/', 'tests/', 'fixtures/', '__fixtures__/', 'testdata/'],
  ['test/', 'tests/', 'fixtures/', '__fixtures__/', 'testdata/', '!/e2e/tests/'],
  ['test/', 'tests/', 'fixtures/', '__fixtures__/', 'testdata/', '!tests/'],
  ['test/', 'tests/', 'fixtures/', '__fixtures__/', 'testdata/', '/legacy/'],
  ['a/', '!a/b/'],
  ['a/*', '!a/b/'],
  ['a/**', '!a/b/**'],
  ['a/**/yarn.lock'],
  ['**/b/**'],
  ['*.lock'],
  ['*.json', '!package-lock.json'],
  ['!package-lock.json'],
  ['a/b'],
  ['/a/b/'],
  ['b/'],
  ['**/c/'],
  ['LEGACY/'],
  ['Services/API/'],
  ['foo bar/'],
  ['foo\\ bar/'],
  ['x\\[1\\]/'],
  ['x[1]/'],
  ['?.lock/'],
  ['a.lock/'],
  ['a/b/c/'],
  ['**'],
  ['**/'],
  ['/**/package-lock.json'],
  ['services/'],
  ['#comment', 'legacy/'],
  ['\\#x', 'legacy/'],
  ['legacy/   '],
]

const cases = []
for (const patterns of sets) {
  const ig = ignore().add(patterns)
  for (const path of paths) {
    cases.push({ patterns, path, ignored: ig.ignores(path) })
  }
}

const here = dirname(fileURLToPath(import.meta.url))
const out = join(here, '..', 'crates', 'socket-patch-core', 'tests', 'fixtures', 'ignore_golden.json')
const body = cases.map((c) => '  ' + JSON.stringify(c)).join(',\n')
writeFileSync(out, `{"generator": "ignore@${version}", "cases": [\n${body}\n]}\n`)
console.log(`wrote ${cases.length} cases to ${out}`)

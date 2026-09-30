// Regenerate with archiver@7.0.1, the patch server's repackDirToZip encoder.
// npm install --prefix /tmp/jvm-repack --ignore-scripts archiver@7.0.1
// NODE_PATH=/tmp/jvm-repack/node_modules node generate.cjs
const fs = require('node:fs');
const path = require('node:path');
const archiver = require('archiver');
(async () => {
  const zip = archiver('zip', { zlib: { level: 0 }, store: true });
  const chunks = [];
  zip.on('data', chunk => chunks.push(chunk));
  zip.on('error', error => { throw error; });
  zip.on('end', () => fs.writeFileSync(path.join(__dirname, 'archiver-7.0.1.jar'), Buffer.concat(chunks)));
  for (const [name, body, mode] of [['z.txt', 'first\n', 0o644], ['META-INF/NOTICE.txt', 'patched\n', 0o644], ['bin/run', 'exec\n', 0o755], ['café.txt', 'unicode\n', 0o644]]) {
    zip.append(Buffer.from(body), { name, date: new Date(0), mode });
  }
  await zip.finalize();
})();

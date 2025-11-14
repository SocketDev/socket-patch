import * as fs from 'fs/promises'
import * as path from 'path'
import type { CommandModule } from 'yargs'
import {
  PatchManifestSchema,
  DEFAULT_PATCH_MANIFEST_PATH,
} from '../schema/manifest-schema.js'

interface ListArgs {
  cwd: string
  'manifest-path': string
  json: boolean
}

async function listPatches(
  manifestPath: string,
  outputJson: boolean,
): Promise<void> {
  // Read and parse manifest
  const manifestContent = await fs.readFile(manifestPath, 'utf-8')
  const manifestData = JSON.parse(manifestContent)
  const manifest = PatchManifestSchema.parse(manifestData)

  const patchEntries = Object.entries(manifest.patches)

  if (patchEntries.length === 0) {
    if (outputJson) {
      console.log(JSON.stringify({ patches: [] }, null, 2))
    } else {
      console.log('No patches found in manifest.')
    }
    return
  }

  if (outputJson) {
    // Output as JSON for machine consumption
    const jsonOutput = {
      patches: patchEntries.map(([purl, patch]) => ({
        purl,
        uuid: patch.uuid,
        exportedAt: patch.exportedAt,
        tier: patch.tier,
        license: patch.license,
        description: patch.description,
        files: Object.keys(patch.files),
        vulnerabilities: Object.entries(patch.vulnerabilities).map(
          ([id, vuln]) => ({
            id,
            cves: vuln.cves,
            summary: vuln.summary,
            severity: vuln.severity,
            description: vuln.description,
          }),
        ),
      })),
    }
    console.log(JSON.stringify(jsonOutput, null, 2))
  } else {
    // Human-readable output
    console.log(`Found ${patchEntries.length} patch(es):\n`)

    for (const [purl, patch] of patchEntries) {
      console.log(`Package: ${purl}`)
      console.log(`  UUID: ${patch.uuid}`)
      console.log(`  Tier: ${patch.tier}`)
      console.log(`  License: ${patch.license}`)
      console.log(`  Exported: ${patch.exportedAt}`)

      if (patch.description) {
        console.log(`  Description: ${patch.description}`)
      }

      // List vulnerabilities
      const vulnEntries = Object.entries(patch.vulnerabilities)
      if (vulnEntries.length > 0) {
        console.log(`  Vulnerabilities (${vulnEntries.length}):`)
        for (const [id, vuln] of vulnEntries) {
          const cveList = vuln.cves.length > 0 ? ` (${vuln.cves.join(', ')})` : ''
          console.log(`    - ${id}${cveList}`)
          console.log(`      Severity: ${vuln.severity}`)
          console.log(`      Summary: ${vuln.summary}`)
        }
      }

      // List files being patched
      const fileList = Object.keys(patch.files)
      if (fileList.length > 0) {
        console.log(`  Files patched (${fileList.length}):`)
        for (const filePath of fileList) {
          console.log(`    - ${filePath}`)
        }
      }

      console.log('') // Empty line between patches
    }
  }
}

export const listCommand: CommandModule<{}, ListArgs> = {
  command: 'list',
  describe: 'List all patches in the local manifest',
  builder: yargs => {
    return yargs
      .option('cwd', {
        describe: 'Working directory',
        type: 'string',
        default: process.cwd(),
      })
      .option('manifest-path', {
        alias: 'm',
        describe: 'Path to patch manifest file',
        type: 'string',
        default: DEFAULT_PATCH_MANIFEST_PATH,
      })
      .option('json', {
        describe: 'Output as JSON',
        type: 'boolean',
        default: false,
      })
  },
  handler: async argv => {
    try {
      const manifestPath = path.isAbsolute(argv['manifest-path'])
        ? argv['manifest-path']
        : path.join(argv.cwd, argv['manifest-path'])

      // Check if manifest exists
      try {
        await fs.access(manifestPath)
      } catch {
        if (argv.json) {
          console.log(JSON.stringify({ error: 'Manifest not found', path: manifestPath }, null, 2))
        } else {
          console.error(`Manifest not found at ${manifestPath}`)
        }
        process.exit(1)
      }

      await listPatches(manifestPath, argv.json)
      process.exit(0)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      if (argv.json) {
        console.log(JSON.stringify({ error: errorMessage }, null, 2))
      } else {
        console.error(`Error: ${errorMessage}`)
      }
      process.exit(1)
    }
  },
}

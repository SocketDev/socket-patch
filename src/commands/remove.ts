import * as fs from 'fs/promises'
import * as path from 'path'
import type { CommandModule } from 'yargs'
import {
  PatchManifestSchema,
  DEFAULT_PATCH_MANIFEST_PATH,
} from '../schema/manifest-schema.js'

interface RemoveArgs {
  identifier: string
  cwd: string
  'manifest-path': string
}

async function removePatch(
  identifier: string,
  manifestPath: string,
): Promise<{ removed: string[]; notFound: boolean }> {
  // Read and parse manifest
  const manifestContent = await fs.readFile(manifestPath, 'utf-8')
  const manifestData = JSON.parse(manifestContent)
  const manifest = PatchManifestSchema.parse(manifestData)

  const removed: string[] = []
  let foundMatch = false

  // Check if identifier is a PURL (contains "pkg:")
  if (identifier.startsWith('pkg:')) {
    // Remove by PURL
    if (manifest.patches[identifier]) {
      removed.push(identifier)
      delete manifest.patches[identifier]
      foundMatch = true
    }
  } else {
    // Remove by UUID - search through all patches
    for (const [purl, patch] of Object.entries(manifest.patches)) {
      if (patch.uuid === identifier) {
        removed.push(purl)
        delete manifest.patches[purl]
        foundMatch = true
      }
    }
  }

  if (foundMatch) {
    // Write updated manifest
    await fs.writeFile(
      manifestPath,
      JSON.stringify(manifest, null, 2) + '\n',
      'utf-8',
    )
  }

  return { removed, notFound: !foundMatch }
}

export const removeCommand: CommandModule<{}, RemoveArgs> = {
  command: 'remove <identifier>',
  describe: 'Remove a patch from the manifest by PURL or UUID',
  builder: yargs => {
    return yargs
      .positional('identifier', {
        describe: 'Package PURL (e.g., pkg:npm/package@version) or patch UUID',
        type: 'string',
        demandOption: true,
      })
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
        console.error(`Manifest not found at ${manifestPath}`)
        process.exit(1)
      }

      const { removed, notFound } = await removePatch(
        argv.identifier,
        manifestPath,
      )

      if (notFound) {
        console.error(`No patch found matching identifier: ${argv.identifier}`)
        process.exit(1)
      }

      console.log(`Removed ${removed.length} patch(es):`)
      for (const purl of removed) {
        console.log(`  - ${purl}`)
      }

      console.log(`\nManifest updated at ${manifestPath}`)
      console.log('Tip: Run "socket-patch gc" to clean up unused blob files.')

      process.exit(0)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      console.error(`Error: ${errorMessage}`)
      process.exit(1)
    }
  },
}

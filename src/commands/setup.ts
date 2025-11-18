import * as path from 'path'
import * as readline from 'readline/promises'
import type { CommandModule } from 'yargs'
import {
  findPackageJsonFiles,
  updateMultiplePackageJsons,
  type UpdateResult,
} from '../package-json/index.js'

interface SetupArgs {
  cwd: string
  'dry-run': boolean
  yes: boolean
}

/**
 * Display a preview table of changes
 */
function displayPreview(results: UpdateResult[], cwd: string): void {
  console.log('\nPackage.json files to be updated:\n')

  const toUpdate = results.filter(r => r.status === 'updated')
  const alreadyConfigured = results.filter(
    r => r.status === 'already-configured',
  )
  const errors = results.filter(r => r.status === 'error')

  if (toUpdate.length > 0) {
    console.log('Will update:')
    for (const result of toUpdate) {
      const relativePath = path.relative(cwd, result.path)
      console.log(`  ✓ ${relativePath}`)
      if (result.oldScript) {
        console.log(`    Current:  "${result.oldScript}"`)
      } else {
        console.log(`    Current:  (no postinstall script)`)
      }
      console.log(`    New:      "${result.newScript}"`)
    }
    console.log()
  }

  if (alreadyConfigured.length > 0) {
    console.log('Already configured (will skip):')
    for (const result of alreadyConfigured) {
      const relativePath = path.relative(cwd, result.path)
      console.log(`  ⊘ ${relativePath}`)
    }
    console.log()
  }

  if (errors.length > 0) {
    console.log('Errors:')
    for (const result of errors) {
      const relativePath = path.relative(cwd, result.path)
      console.log(`  ✗ ${relativePath}: ${result.error}`)
    }
    console.log()
  }
}

/**
 * Display summary of changes made
 */
function displaySummary(results: UpdateResult[], dryRun: boolean): void {
  const updated = results.filter(r => r.status === 'updated')
  const alreadyConfigured = results.filter(
    r => r.status === 'already-configured',
  )
  const errors = results.filter(r => r.status === 'error')

  console.log('\nSummary:')
  console.log(
    `  ${updated.length} file(s) ${dryRun ? 'would be updated' : 'updated'}`,
  )
  console.log(`  ${alreadyConfigured.length} file(s) already configured`)
  if (errors.length > 0) {
    console.log(`  ${errors.length} error(s)`)
  }
}

/**
 * Prompt user for confirmation
 */
async function promptConfirmation(): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  })

  try {
    const answer = await rl.question('Proceed with these changes? (y/N): ')
    return answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes'
  } finally {
    rl.close()
  }
}

export const setupCommand: CommandModule<{}, SetupArgs> = {
  command: 'setup',
  describe: 'Configure package.json postinstall scripts to apply patches',
  builder: yargs => {
    return yargs
      .option('cwd', {
        describe: 'Working directory',
        type: 'string',
        default: process.cwd(),
      })
      .option('dry-run', {
        alias: 'd',
        describe: 'Preview changes without modifying files',
        type: 'boolean',
        default: false,
      })
      .option('yes', {
        alias: 'y',
        describe: 'Skip confirmation prompt',
        type: 'boolean',
        default: false,
      })
  },
  handler: async argv => {
    try {
      // Find all package.json files
      console.log('Searching for package.json files...')
      const packageJsonFiles = await findPackageJsonFiles(argv.cwd)

      if (packageJsonFiles.length === 0) {
        console.log('No package.json files found')
        process.exit(0)
      }

      console.log(`Found ${packageJsonFiles.length} package.json file(s)`)

      // Preview changes (dry run to see what would change)
      const previewResults = await updateMultiplePackageJsons(
        packageJsonFiles.map(p => p.path),
        true, // Always preview first
      )

      // Display preview
      displayPreview(previewResults, argv.cwd)

      const toUpdate = previewResults.filter(r => r.status === 'updated')

      if (toUpdate.length === 0) {
        console.log(
          'All package.json files are already configured with socket-patch!',
        )
        process.exit(0)
      }

      // If not dry-run, ask for confirmation (unless --yes)
      if (!argv['dry-run']) {
        if (!argv.yes) {
          const confirmed = await promptConfirmation()
          if (!confirmed) {
            console.log('Aborted')
            process.exit(0)
          }
        }

        // Apply changes
        console.log('\nApplying changes...')
        const results = await updateMultiplePackageJsons(
          packageJsonFiles.map(p => p.path),
          false,
        )

        displaySummary(results, false)

        const errors = results.filter(r => r.status === 'error')
        process.exit(errors.length > 0 ? 1 : 0)
      } else {
        // Dry run mode
        displaySummary(previewResults, true)
        process.exit(0)
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      console.error(`Error: ${errorMessage}`)
      process.exit(1)
    }
  },
}

#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { applyCommand } from './commands/apply.js'

async function main(): Promise<void> {
  await yargs(hideBin(process.argv))
    .scriptName('socket-patch')
    .usage('$0 <command> [options]')
    .command(applyCommand)
    .demandCommand(1, 'You must specify a command')
    .help()
    .alias('h', 'help')
    .version()
    .alias('v', 'version')
    .strict()
    .parse()
}

main().catch((error: Error) => {
  console.error('Error:', error.message)
  process.exit(1)
})

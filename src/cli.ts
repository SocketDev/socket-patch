#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { applyCommand } from './commands/apply.js'
import { getCommand } from './commands/get.js'
import { listCommand } from './commands/list.js'
import { removeCommand } from './commands/remove.js'
import { rollbackCommand } from './commands/rollback.js'
import { repairCommand } from './commands/repair.js'
import { scanCommand } from './commands/scan.js'
import { setupCommand } from './commands/setup.js'

async function main(): Promise<void> {
  await yargs(hideBin(process.argv))
    .scriptName('socket-patch')
    .usage('$0 <command> [options]')
    .command(getCommand)
    .command(applyCommand)
    .command(rollbackCommand)
    .command(removeCommand)
    .command(listCommand)
    .command(scanCommand)
    .command(setupCommand)
    .command(repairCommand)
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

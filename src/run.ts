import yargs from 'yargs'
import { applyCommand } from './commands/apply.js'
import { getCommand } from './commands/get.js'
import { listCommand } from './commands/list.js'
import { removeCommand } from './commands/remove.js'
import { rollbackCommand } from './commands/rollback.js'
import { repairCommand } from './commands/repair.js'
import { setupCommand } from './commands/setup.js'

/**
 * Configuration options for running socket-patch programmatically.
 */
export interface PatchOptions {
  /** Socket API URL (e.g., https://api.socket.dev). */
  apiUrl?: string
  /** Socket API token for authentication. */
  apiToken?: string
  /** Organization slug. */
  orgSlug?: string
  /** Public patch API proxy URL. */
  patchProxyUrl?: string
  /** HTTP proxy URL for all requests. */
  httpProxy?: string
  /** Enable debug logging. */
  debug?: boolean
}

/**
 * Run socket-patch programmatically with provided arguments and options.
 * Maps options to environment variables before executing yargs commands.
 *
 * @param args - Command line arguments to pass to yargs (e.g., ['get', 'CVE-2021-44228']).
 * @param options - Configuration options that override environment variables.
 * @returns Exit code (0 for success, non-zero for failure).
 */
export async function runPatch(
  args: string[],
  options?: PatchOptions
): Promise<number> {
  // Map options to environment variables.
  if (options?.apiUrl) {
    process.env.SOCKET_API_URL = options.apiUrl
  }
  if (options?.apiToken) {
    process.env.SOCKET_API_TOKEN = options.apiToken
  }
  if (options?.orgSlug) {
    process.env.SOCKET_ORG_SLUG = options.orgSlug
  }
  if (options?.patchProxyUrl) {
    process.env.SOCKET_PATCH_PROXY_URL = options.patchProxyUrl
  }
  if (options?.httpProxy) {
    process.env.SOCKET_PATCH_HTTP_PROXY = options.httpProxy
  }
  if (options?.debug) {
    process.env.SOCKET_PATCH_DEBUG = '1'
  }

  try {
    await yargs(args)
      .scriptName('socket patch')
      .usage('$0 <command> [options]')
      .command(getCommand)
      .command(applyCommand)
      .command(rollbackCommand)
      .command(removeCommand)
      .command(listCommand)
      .command(setupCommand)
      .command(repairCommand)
      .demandCommand(1, 'You must specify a command')
      .help()
      .alias('h', 'help')
      .strict()
      .parse()

    return 0
  } catch (error) {
    if (process.env.SOCKET_PATCH_DEBUG) {
      console.error('socket-patch error:', error)
    }
    return 1
  }
}

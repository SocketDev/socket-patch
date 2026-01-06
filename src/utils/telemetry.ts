/**
 * Telemetry module for socket-patch CLI.
 * Collects anonymous usage data for patch lifecycle events.
 *
 * Telemetry can be disabled via:
 * - Environment variable: SOCKET_PATCH_TELEMETRY_DISABLED=1
 * - Running in test environment: VITEST=true
 *
 * Events are sent to:
 * - Authenticated: https://api.socket.dev/v0/orgs/{org}/telemetry
 * - Public proxy: https://patches-api.socket.dev/patch/telemetry
 */

import * as https from 'node:https'
import * as http from 'node:http'
import * as os from 'node:os'
import * as crypto from 'node:crypto'

// Default public patch API URL for free tier telemetry.
const DEFAULT_PATCH_API_PROXY_URL = 'https://patches-api.socket.dev'

// Package version - updated during build.
const PACKAGE_VERSION = '1.0.0'

/**
 * Check if telemetry is disabled via environment variables.
 */
function isTelemetryDisabled(): boolean {
  return (
    process.env['SOCKET_PATCH_TELEMETRY_DISABLED'] === '1' ||
    process.env['SOCKET_PATCH_TELEMETRY_DISABLED'] === 'true' ||
    process.env['VITEST'] === 'true'
  )
}

/**
 * Check if debug mode is enabled.
 */
function isDebugEnabled(): boolean {
  return (
    process.env['SOCKET_PATCH_DEBUG'] === '1' ||
    process.env['SOCKET_PATCH_DEBUG'] === 'true'
  )
}

/**
 * Log debug messages when debug mode is enabled.
 */
function debugLog(message: string, ...args: unknown[]): void {
  if (isDebugEnabled()) {
    console.error(`[socket-patch telemetry] ${message}`, ...args)
  }
}

/**
 * Generate a unique session ID for the current CLI invocation.
 * This is shared across all telemetry events in a single CLI run.
 */
const SESSION_ID = crypto.randomUUID()

/**
 * Telemetry context describing the execution environment.
 */
export interface PatchTelemetryContext {
  version: string
  platform: string
  node_version: string
  arch: string
  command: string
}

/**
 * Error details for telemetry events.
 */
export interface PatchTelemetryError {
  type: string
  message: string | undefined
}

/**
 * Telemetry event types for patch lifecycle.
 */
export type PatchTelemetryEventType =
  | 'patch_applied'
  | 'patch_apply_failed'
  | 'patch_removed'
  | 'patch_remove_failed'
  | 'patch_rolled_back'
  | 'patch_rollback_failed'

/**
 * Telemetry event structure for patch operations.
 */
export interface PatchTelemetryEvent {
  event_sender_created_at: string
  event_type: PatchTelemetryEventType
  context: PatchTelemetryContext
  session_id: string
  metadata?: Record<string, unknown>
  error?: PatchTelemetryError
}

/**
 * Options for tracking a patch event.
 */
export interface TrackPatchEventOptions {
  /** The type of event being tracked. */
  eventType: PatchTelemetryEventType
  /** The CLI command being executed (e.g., 'apply', 'remove', 'rollback'). */
  command: string
  /** Optional metadata to include with the event. */
  metadata?: Record<string, unknown>
  /** Optional error information if the operation failed. */
  error?: Error
  /** Optional API token for authenticated telemetry endpoint. */
  apiToken?: string
  /** Optional organization slug for authenticated telemetry endpoint. */
  orgSlug?: string
}

/**
 * Build the telemetry context for the current environment.
 */
function buildTelemetryContext(command: string): PatchTelemetryContext {
  return {
    version: PACKAGE_VERSION,
    platform: process.platform,
    node_version: process.version,
    arch: os.arch(),
    command,
  }
}

/**
 * Sanitize error for telemetry.
 * Removes sensitive paths and information.
 */
function sanitizeError(error: Error): PatchTelemetryError {
  const homeDir = os.homedir()
  let message = error.message
  if (homeDir) {
    message = message.replace(new RegExp(homeDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '~')
  }
  return {
    type: error.constructor.name,
    message,
  }
}

/**
 * Build a telemetry event from the given options.
 */
function buildTelemetryEvent(options: TrackPatchEventOptions): PatchTelemetryEvent {
  const event: PatchTelemetryEvent = {
    event_sender_created_at: new Date().toISOString(),
    event_type: options.eventType,
    context: buildTelemetryContext(options.command),
    session_id: SESSION_ID,
  }

  if (options.metadata && Object.keys(options.metadata).length > 0) {
    event.metadata = options.metadata
  }

  if (options.error) {
    event.error = sanitizeError(options.error)
  }

  return event
}

/**
 * Send telemetry event to the API.
 * Returns a promise that resolves when the request completes.
 * Errors are logged but never thrown - telemetry should never block CLI operations.
 */
async function sendTelemetryEvent(
  event: PatchTelemetryEvent,
  apiToken?: string,
  orgSlug?: string,
): Promise<void> {
  // Determine the telemetry endpoint based on authentication.
  let url: string
  let useAuth = false

  if (apiToken && orgSlug) {
    // Authenticated endpoint.
    const apiUrl = process.env['SOCKET_API_URL'] || 'https://api.socket.dev'
    url = `${apiUrl}/v0/orgs/${orgSlug}/telemetry`
    useAuth = true
  } else {
    // Public proxy endpoint.
    const proxyUrl = process.env['SOCKET_PATCH_PROXY_URL'] || DEFAULT_PATCH_API_PROXY_URL
    url = `${proxyUrl}/patch/telemetry`
  }

  debugLog(`Sending telemetry to ${url}`, event)

  return new Promise(resolve => {
    const body = JSON.stringify(event)
    const urlObj = new URL(url)
    const isHttps = urlObj.protocol === 'https:'
    const httpModule = isHttps ? https : http

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body).toString(),
      'User-Agent': 'SocketPatchCLI/1.0',
    }

    if (useAuth && apiToken) {
      headers['Authorization'] = `Bearer ${apiToken}`
    }

    const requestOptions: https.RequestOptions = {
      method: 'POST',
      headers,
      timeout: 5000, // 5 second timeout.
    }

    const req = httpModule.request(urlObj, requestOptions, res => {
      // Consume response body to free resources.
      res.on('data', () => {})
      res.on('end', () => {
        if (res.statusCode === 200) {
          debugLog('Telemetry sent successfully')
        } else {
          debugLog(`Telemetry request returned status ${res.statusCode}`)
        }
        resolve()
      })
    })

    req.on('error', err => {
      debugLog(`Telemetry request failed: ${err.message}`)
      resolve()
    })

    req.on('timeout', () => {
      debugLog('Telemetry request timed out')
      req.destroy()
      resolve()
    })

    req.write(body)
    req.end()
  })
}

/**
 * Track a patch lifecycle event.
 *
 * This function is non-blocking and will never throw errors.
 * Telemetry failures are logged in debug mode but don't affect CLI operation.
 *
 * @param options - Event tracking options.
 * @returns Promise that resolves when the event is sent (or immediately if telemetry is disabled).
 *
 * @example
 * ```typescript
 * // Track successful patch application.
 * await trackPatchEvent({
 *   eventType: 'patch_applied',
 *   command: 'apply',
 *   metadata: {
 *     patches_count: 5,
 *     dry_run: false,
 *   },
 * })
 *
 * // Track failed patch application.
 * await trackPatchEvent({
 *   eventType: 'patch_apply_failed',
 *   command: 'apply',
 *   error: new Error('Failed to apply patch'),
 *   metadata: {
 *     patches_count: 0,
 *     dry_run: false,
 *   },
 * })
 * ```
 */
export async function trackPatchEvent(options: TrackPatchEventOptions): Promise<void> {
  if (isTelemetryDisabled()) {
    debugLog('Telemetry is disabled, skipping event')
    return
  }

  try {
    const event = buildTelemetryEvent(options)
    await sendTelemetryEvent(event, options.apiToken, options.orgSlug)
  } catch (err) {
    // Telemetry should never block CLI operations.
    debugLog(`Failed to track event: ${err instanceof Error ? err.message : String(err)}`)
  }
}

/**
 * Convenience function to track a successful patch application.
 */
export async function trackPatchApplied(
  patchesCount: number,
  dryRun: boolean,
  apiToken?: string,
  orgSlug?: string,
): Promise<void> {
  await trackPatchEvent({
    eventType: 'patch_applied',
    command: 'apply',
    metadata: {
      patches_count: patchesCount,
      dry_run: dryRun,
    },
    apiToken,
    orgSlug,
  })
}

/**
 * Convenience function to track a failed patch application.
 */
export async function trackPatchApplyFailed(
  error: Error,
  dryRun: boolean,
  apiToken?: string,
  orgSlug?: string,
): Promise<void> {
  await trackPatchEvent({
    eventType: 'patch_apply_failed',
    command: 'apply',
    error,
    metadata: {
      dry_run: dryRun,
    },
    apiToken,
    orgSlug,
  })
}

/**
 * Convenience function to track a successful patch removal.
 */
export async function trackPatchRemoved(
  removedCount: number,
  apiToken?: string,
  orgSlug?: string,
): Promise<void> {
  await trackPatchEvent({
    eventType: 'patch_removed',
    command: 'remove',
    metadata: {
      removed_count: removedCount,
    },
    apiToken,
    orgSlug,
  })
}

/**
 * Convenience function to track a failed patch removal.
 */
export async function trackPatchRemoveFailed(
  error: Error,
  apiToken?: string,
  orgSlug?: string,
): Promise<void> {
  await trackPatchEvent({
    eventType: 'patch_remove_failed',
    command: 'remove',
    error,
    apiToken,
    orgSlug,
  })
}

/**
 * Convenience function to track a successful patch rollback.
 */
export async function trackPatchRolledBack(
  rolledBackCount: number,
  apiToken?: string,
  orgSlug?: string,
): Promise<void> {
  await trackPatchEvent({
    eventType: 'patch_rolled_back',
    command: 'rollback',
    metadata: {
      rolled_back_count: rolledBackCount,
    },
    apiToken,
    orgSlug,
  })
}

/**
 * Convenience function to track a failed patch rollback.
 */
export async function trackPatchRollbackFailed(
  error: Error,
  apiToken?: string,
  orgSlug?: string,
): Promise<void> {
  await trackPatchEvent({
    eventType: 'patch_rollback_failed',
    command: 'rollback',
    error,
    apiToken,
    orgSlug,
  })
}

'use strict'

const fs = require('node:fs')
const path = require('node:path')

const ADDON_ENV = 'SOCKET_PATCH_NODE_ADDON_PATH'
const PROVIDER_ERROR_KINDS = new Set([
  'unauthorized',
  'forbidden',
  'rate_limited',
  'network',
  'parse',
  'not_found',
  'other',
])
const JSON_PROVIDER_METHODS = [
  'searchPatchesBatch',
  'searchPatchesByPackage',
  'fetchRegistryReferences',
  'fetchPatch',
]
const MAX_PROVIDER_MESSAGE = 2000
const REQUIRED_EXPORTS = [
  'selectHostedScanPathsJson',
  'hostedScanCandidateFiles',
  'engineVersion',
  'createHostedScanSession',
  'hostedScanSessionPushChunk',
  'hostedScanSessionEndFile',
  'hostedScanSessionMarkPresent',
  'hostedScanSessionFinish',
  'hostedScanSessionCancel',
]

class SocketPatchAddonUnavailableError extends Error {
  constructor(message, attempted, options) {
    super(message, options)
    this.name = 'SocketPatchAddonUnavailableError'
    this.code = 'addon_unavailable'
    this.attempted = attempted
  }
}

function libraryNames() {
  if (process.platform === 'win32') {
    return ['socket_patch_node.dll']
  }
  if (process.platform === 'darwin') {
    return ['libsocket_patch_node.dylib']
  }
  return ['libsocket_patch_node.so']
}

function candidatePaths() {
  const explicit = process.env[ADDON_ENV]
  if (explicit) {
    return [path.resolve(explicit)]
  }
  const candidates = [path.join(__dirname, 'socket_patch_node.node')]
  if (process.env.NODE_ENV !== 'production') {
    const targetDir = path.resolve(__dirname, '..', '..', '..', 'target')
    for (const profile of ['release', 'debug']) {
      for (const name of libraryNames()) {
        candidates.push(path.join(targetDir, profile, name))
      }
    }
  }
  return candidates
}

function loadFile(file) {
  if (path.extname(file) === '.node') {
    return require(file)
  }
  const addonModule = { exports: {} }
  process.dlopen(addonModule, file)
  return addonModule.exports
}

let cachedBinding = null

function binding() {
  if (cachedBinding) {
    return cachedBinding
  }
  const attempted = candidatePaths()
  const found = attempted.find((file) => fs.existsSync(file))
  if (!found) {
    const hint = process.env[ADDON_ENV]
      ? `${ADDON_ENV} points at a missing file`
      : `build it with \`pnpm run build:addon\` or set ${ADDON_ENV}`
    throw new SocketPatchAddonUnavailableError(
      `socket-patch-node addon not found (${hint}); tried: ${attempted.join(', ')}`,
      attempted,
    )
  }
  let loaded
  try {
    loaded = loadFile(found)
  } catch (error) {
    throw new SocketPatchAddonUnavailableError(
      `socket-patch-node addon at ${found} failed to load: ${describe(error)}`,
      attempted,
      { cause: error },
    )
  }
  const missing = REQUIRED_EXPORTS.filter((name) => loaded[name] === undefined)
  if (missing.length > 0) {
    throw new SocketPatchAddonUnavailableError(
      `socket-patch-node addon at ${found} is missing exports: ${missing.join(', ')}`,
      attempted,
    )
  }
  cachedBinding = loaded
  return loaded
}

function describe(error) {
  let text
  if (error instanceof Error) {
    text = error.message
  } else {
    try {
      text = String(error)
    } catch {
      text = 'unprintable error'
    }
  }
  return text.length > MAX_PROVIDER_MESSAGE
    ? `${text.slice(0, MAX_PROVIDER_MESSAGE)}…`
    : text
}

function engineError(code, kind, message) {
  const error = new Error(message)
  error.name = 'HostedScanError'
  error.code = code
  error.kind = kind
  return error
}

function fromNativeError(error) {
  const reason = error instanceof Error ? error.message : undefined
  if (typeof reason === 'string') {
    try {
      const parsed = JSON.parse(reason)
      if (
        parsed &&
        typeof parsed.code === 'string' &&
        typeof parsed.kind === 'string' &&
        typeof parsed.message === 'string'
      ) {
        return engineError(parsed.code, parsed.kind, parsed.message)
      }
    } catch {}
  }
  return engineError('addon_internal', 'internal', describe(error))
}

function callNative(call) {
  try {
    return call()
  } catch (error) {
    throw fromNativeError(error)
  }
}

function providerFailure(kind, message) {
  return {
    ok: false,
    error: { kind: PROVIDER_ERROR_KINDS.has(kind) ? kind : 'other', message },
  }
}

function normalizeJsonResult(result) {
  if (result === null || typeof result !== 'object' || typeof result.ok !== 'boolean') {
    return providerFailure('other', 'provider returned a malformed result')
  }
  if (result.ok) {
    return { ok: true, value: result.value === undefined ? null : result.value }
  }
  const error = result.error !== null && typeof result.error === 'object' ? result.error : {}
  return providerFailure(
    typeof error.kind === 'string' ? error.kind : 'other',
    typeof error.message === 'string' ? describe(error.message) : '',
  )
}

function serializeResult(result) {
  try {
    return JSON.stringify(result)
  } catch (error) {
    return JSON.stringify(
      providerFailure('parse', `provider result is not serializable: ${describe(error)}`),
    )
  }
}

function invokeProvider(provider, method, requestJson) {
  return Promise.resolve().then(() => {
    const request = JSON.parse(requestJson)
    const fn = provider[method]
    if (typeof fn !== 'function') {
      throw new TypeError(`provider.${method} is not a function`)
    }
    return fn.call(provider, request)
  })
}

function wrapJsonMethod(provider, method) {
  return (requestJson) =>
    invokeProvider(provider, method, requestJson)
      .then(normalizeJsonResult, (error) => providerFailure('other', describe(error)))
      .then(serializeResult)
      .catch(() => serializeResult(providerFailure('other', `provider.${method} failed`)))
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
  }
  return null
}

function flatDownloadFailure(kind, message) {
  return {
    ok: false,
    value: undefined,
    kind: PROVIDER_ERROR_KINDS.has(kind) ? kind : 'other',
    message,
  }
}

function normalizeDownloadResult(result) {
  if (result === null || typeof result !== 'object' || typeof result.ok !== 'boolean') {
    return flatDownloadFailure('other', 'provider returned a malformed result')
  }
  if (result.ok) {
    const bytes = toBuffer(result.value)
    if (!bytes) {
      return flatDownloadFailure('parse', 'downloadArtifact must resolve a Buffer')
    }
    return { ok: true, value: bytes, kind: undefined, message: undefined }
  }
  const error = result.error !== null && typeof result.error === 'object' ? result.error : {}
  return flatDownloadFailure(
    typeof error.kind === 'string' ? error.kind : 'other',
    typeof error.message === 'string' ? describe(error.message) : '',
  )
}

function wrapDownloadMethod(provider) {
  return (requestJson) =>
    invokeProvider(provider, 'downloadArtifact', requestJson)
      .then(normalizeDownloadResult, (error) => flatDownloadFailure('other', describe(error)))
      .catch(() => flatDownloadFailure('other', 'provider.downloadArtifact failed'))
}

function wrapProvider(provider) {
  if (provider === null || (typeof provider !== 'object' && typeof provider !== 'function')) {
    throw new TypeError('provider must be an object implementing PatchProvider')
  }
  const wrapped = {}
  for (const method of JSON_PROVIDER_METHODS) {
    wrapped[method] = wrapJsonMethod(provider, method)
  }
  wrapped.downloadArtifact = wrapDownloadMethod(provider)
  return wrapped
}

function requirePath(value) {
  if (typeof value !== 'string') {
    throw new TypeError('path must be a string')
  }
  return value
}

function selectHostedScanPaths(entries, options) {
  if (!Array.isArray(entries)) {
    throw new TypeError('entries must be an array of tree entries')
  }
  const native = binding()
  const optionsJson = options === undefined || options === null ? null : JSON.stringify(options)
  return JSON.parse(
    callNative(() => native.selectHostedScanPathsJson(JSON.stringify(entries), optionsJson)),
  )
}

function hostedScanCandidateFiles() {
  return binding().hostedScanCandidateFiles()
}

function engineVersion() {
  return binding().engineVersion()
}

class HostedScanSession {
  #binding
  #native

  constructor(options, provider) {
    if (options === null || typeof options !== 'object') {
      throw new TypeError('options must be a HostedScanSessionOptions object')
    }
    const native = binding()
    const wrapped = wrapProvider(provider)
    const optionsJson = JSON.stringify(options)
    this.#binding = native
    this.#native = callNative(() => native.createHostedScanSession(optionsJson, wrapped))
  }

  pushChunk(path, chunk) {
    const bytes = toBuffer(chunk)
    if (!bytes) {
      throw new TypeError('chunk must be a Buffer or Uint8Array')
    }
    callNative(() => this.#binding.hostedScanSessionPushChunk(this.#native, requirePath(path), bytes))
  }

  endFile(path) {
    callNative(() => this.#binding.hostedScanSessionEndFile(this.#native, requirePath(path)))
  }

  markPresent(path, kind) {
    if (typeof kind !== 'string') {
      throw new TypeError('kind must be a string')
    }
    callNative(() => this.#binding.hostedScanSessionMarkPresent(this.#native, requirePath(path), kind))
  }

  async finish() {
    const outcome = await callNative(() => this.#binding.hostedScanSessionFinish(this.#native))
    if (!outcome.ok) {
      throw engineError(
        outcome.errorCode ?? 'engine_internal',
        outcome.errorKind ?? 'internal',
        outcome.errorMessage ?? 'the hosted scan failed',
      )
    }
    const result = JSON.parse(outcome.resultJson)
    result.changedBinaryFiles = (outcome.binaryFiles ?? []).map((file) => ({
      path: file.path,
      content: file.content,
    }))
    return result
  }

  cancel() {
    callNative(() => this.#binding.hostedScanSessionCancel(this.#native))
  }
}

module.exports = {
  HostedScanSession,
  SocketPatchAddonUnavailableError,
  engineVersion,
  hostedScanCandidateFiles,
  selectHostedScanPaths,
}

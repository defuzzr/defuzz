import { useState, useCallback, useRef, useEffect } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'
import {
  host,
  Button,
  Badge,
  ScrollArea,
  Separator,
  EmptyState,
  Codicon,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  PALETTE_AREA
} from '@hermes/plugin-sdk'

const RAISED_FILL = 'var(--ui-bg-elevated, #1f2428)'
const MODAL_SCRIM = { position: 'fixed', inset: 0, background: 'rgba(0, 0, 0, 0.55)', display: 'grid', placeItems: 'center', zIndex: 50 }

export const DEFAULT_AUTOSAVE_DEBOUNCE_MS = 150

function normalizeToken(val, fallback, name) {
  if (typeof val === 'string' && val.trim()) {
    return val.trim()
  }
  if (fallback !== undefined) {
    return fallback
  }
  throw new Error(`${name} must be a non-empty string`)
}

/**
 * Create a standalone, framework-agnostic coalescing auto-save controller.
 *
 * @param {object} [options]
 * @param {object} [options.ctx] Desktop context owning timers and unload cleanup.
 * @param {string} [options.namespace='default'] Default namespace when not passed per call.
 * @param {number} [options.debounceMs=150] Coalescing window in milliseconds (`interval` alias supported).
 * @param {number} [options.initialSeq=0] Starting sequence counter (`seq` alias supported).
 * @param {(payload: { namespace: string, key: string, value: any, seq: number }) => Promise<any>|any} [options.onSave]
 *   Persistence callback (e.g. calling backend `safe_state_store.save_state`).
 * @param {(state: object) => void} [options.onStatusChange] Optional listener notified on state changes.
 * @param {typeof globalThis.setTimeout} [options.setTimeout] Injectable timer scheduler for deterministic tests.
 * @param {typeof globalThis.clearTimeout} [options.clearTimeout] Injectable timer clearer for deterministic tests.
 */
export function createSafeAutoSave(options = {}) {
  const defaultNamespace = normalizeToken(options.namespace, 'default', 'namespace')
  const debounceMs = Math.max(0, Number(options.debounceMs ?? options.interval ?? DEFAULT_AUTOSAVE_DEBOUNCE_MS))
  const initialSeq = Math.max(0, Number.isInteger(options.initialSeq ?? options.seq) ? (options.initialSeq ?? options.seq) : 0)
  const onSave = typeof options.onSave === 'function' ? options.onSave : null
  const onStatusChange = typeof options.onStatusChange === 'function' ? options.onStatusChange : null
  // SDK timers return cancellation functions, not browser timer IDs.
  const ctx = options.ctx
  const setTimer = ctx ? (fn, ms) => ctx.setTimeout(fn, ms) : options.setTimeout
  const clearTimer = ctx ? disposeTimer => disposeTimer() : options.clearTimeout
  if (typeof setTimer !== 'function' || typeof clearTimer !== 'function' ||
      (ctx && (typeof ctx.setTimeout !== 'function' || typeof ctx.onDispose !== 'function'))) {
    throw new Error('Auto-save requires a scoped plugin context or injected timers')
  }

  let globalSeq = initialSeq
  let disposed = false

  // Per-(namespace,key) state entry:
  // { namespace, key, value, seq, savedSeq, status, timerId, pendingPayload, inFlightPromise, error }
  const entries = new Map()

  function makeCompositeKey(namespace, key) {
    const ns = normalizeToken(namespace, defaultNamespace, 'namespace')
    const k = normalizeToken(key, undefined, 'key')
    return { ns, k, id: `${ns}::${k}` }
  }

  function snapshotEntry(entry) {
    if (!entry) return null
    return Object.freeze({
      namespace: entry.namespace,
      key: entry.key,
      value: entry.value,
      seq: entry.seq,
      savedSeq: entry.savedSeq,
      status: entry.status,
      dirty: entry.seq > entry.savedSeq,
      error: entry.error ?? null
    })
  }

  function notify(entry) {
    if (onStatusChange && !disposed) {
      onStatusChange(snapshotEntry(entry))
    }
  }

  async function commitEntry(entry) {
    if (!entry || entry.pendingPayload === null) {
      return snapshotEntry(entry)
    }
    if (entry.timerId !== null) {
      clearTimer(entry.timerId)
      entry.timerId = null
    }
    const payload = entry.pendingPayload
    entry.pendingPayload = null
    entry.status = 'saving'
    entry.error = null
    notify(entry)

    const runSave = async () => {
      try {
        let res = null
        if (onSave) {
          res = await onSave(payload)
        }
        // Monotonic guard: only advance savedSeq if this save's seq is newer
        const ackSeq =
          res && typeof res === 'object' && Number.isInteger(res.seq) && res.seq > payload.seq
            ? res.seq
            : payload.seq
        if (ackSeq > entry.savedSeq) {
          entry.savedSeq = ackSeq
        }
        // Only flip to 'saved' if no newer update arrived while in flight
        if (entry.seq <= entry.savedSeq && entry.pendingPayload === null) {
          entry.status = 'saved'
          entry.error = null
        } else if (entry.pendingPayload !== null && entry.timerId === null) {
          // Another update was staged without a timer; commit it next
          await commitEntry(entry)
          return snapshotEntry(entry)
        }
        notify(entry)
        return snapshotEntry(entry)
      } catch (err) {
        // Only mark error if no newer sequence has already superseded this one
        if (payload.seq >= entry.seq) {
          entry.status = 'error'
          entry.error = String(err?.message || err || 'Auto-save failed')
          notify(entry)
        }
        throw err
      }
    }

    const p = runSave().finally(() => {
      if (entry.inFlightPromise === p) {
        entry.inFlightPromise = null
      }
    })
    entry.inFlightPromise = p
    return p
  }

  function ensureEntry(ns, k, initialValue = undefined) {
    const id = `${ns}::${k}`
    let entry = entries.get(id)
    if (!entry) {
      entry = {
        namespace: ns,
        key: k,
        value: initialValue,
        seq: initialSeq,
        savedSeq: initialSeq,
        status: 'idle',
        timerId: null,
        pendingPayload: null,
        inFlightPromise: null,
        error: null
      }
      entries.set(id, entry)
    }
    return entry
  }

  function schedule(key, value, opts = {}) {
    if (disposed) {
      throw new Error('SafeAutoSave controller has been disposed')
    }
    const { ns, k } = makeCompositeKey(opts.namespace, key)
    const entry = ensureEntry(ns, k, value)

    const explicitSeq = opts.seq
    if (explicitSeq !== undefined) {
      if (!Number.isInteger(explicitSeq) || explicitSeq < 1) {
        throw new Error(`seq must be a positive integer, got ${explicitSeq}`)
      }
      // Reject stale updates immediately (`seq <= entry.seq`)
      if (explicitSeq <= entry.seq) {
        return snapshotEntry(entry)
      }
      globalSeq = Math.max(globalSeq, explicitSeq)
      entry.seq = explicitSeq
    } else {
      globalSeq += 1
      entry.seq = globalSeq
    }

    entry.value = value
    entry.error = null
    entry.pendingPayload = Object.freeze({
      namespace: ns,
      key: k,
      value,
      seq: entry.seq
    })
    entry.status = 'coalescing'

    if (entry.timerId !== null) {
      clearTimer(entry.timerId)
      entry.timerId = null
    }

    const effectiveDebounce = opts.debounceMs !== undefined ? Math.max(0, Number(opts.debounceMs)) : debounceMs
    if (effectiveDebounce === 0) {
      commitEntry(entry).catch(() => {})
    } else {
      entry.timerId = setTimer(() => {
        entry.timerId = null
        commitEntry(entry).catch(() => {})
      }, effectiveDebounce)
    }

    notify(entry)
    return snapshotEntry(entry)
  }

  async function flush(key, opts = {}) {
    if (key !== undefined) {
      const { ns, k } = makeCompositeKey(opts.namespace, key)
      const entry = entries.get(`${ns}::${k}`)
      if (!entry) return null
      if (entry.pendingPayload !== null) {
        return commitEntry(entry)
      }
      if (entry.inFlightPromise) {
        return entry.inFlightPromise
      }
      return snapshotEntry(entry)
    }

    const results = []
    for (const entry of entries.values()) {
      if (entry.pendingPayload !== null) {
        results.push(await commitEntry(entry))
      } else if (entry.inFlightPromise) {
        results.push(await entry.inFlightPromise)
      } else {
        results.push(snapshotEntry(entry))
      }
    }
    return results
  }

  function get(key, opts = {}) {
    const { ns, k } = makeCompositeKey(opts.namespace, key)
    return snapshotEntry(entries.get(`${ns}::${k}`))
  }

  function cancel(key, opts = {}) {
    if (key !== undefined) {
      const { ns, k } = makeCompositeKey(opts.namespace, key)
      const entry = entries.get(`${ns}::${k}`)
      if (!entry) return false
      if (entry.timerId !== null) {
        clearTimer(entry.timerId)
        entry.timerId = null
      }
      entry.pendingPayload = null
      if (entry.status === 'coalescing') {
        entry.status = entry.savedSeq > 0 ? 'saved' : 'idle'
      }
      return true
    }
    for (const entry of entries.values()) {
      if (entry.timerId !== null) {
        clearTimer(entry.timerId)
        entry.timerId = null
      }
      entry.pendingPayload = null
    }
    return true
  }

  function dispose() {
    cancel()
    disposed = true
  }

  ctx?.onDispose(dispose)

  return {
    schedule,
    flush,
    get,
    cancel,
    dispose,
    get currentSeq() {
      return globalSeq
    }
  }
}

/**
 * React hook wrapping `createSafeAutoSave` for instant optimistic UI updates
 * with coalesced background persistence and sequence-guarded status indicators.
 *
 * @param {object} [options]
 * @param {object} [options.ctx] Desktop context owning timers and unload cleanup.
 * @param {string} [options.namespace='default'] State namespace.
 * @param {string} [options.key='default'] Default state key for single-value usage.
 * @param {any} [options.initialValue=null] Initial value before edits.
 * @param {number} [options.seq=0] Initial sequence number (`initialSeq` alias supported).
 * @param {number} [options.interval=150] Debounce window in ms (`debounceMs` alias supported).
 * @param {(payload: { namespace: string, key: string, value: any, seq: number }) => Promise<any>|any} [options.onSave]
 * @param {typeof globalThis.setTimeout} [options.setTimeout]
 * @param {typeof globalThis.clearTimeout} [options.clearTimeout]
 */
export function useSafeAutoSave(options = {}) {
  const defaultNamespace = normalizeToken(options.namespace, 'default', 'namespace')
  const defaultKey = normalizeToken(options.key, 'default', 'key')
  const initialSeq = Math.max(0, Number.isInteger(options.initialSeq ?? options.seq) ? (options.initialSeq ?? options.seq) : 0)
  const debounceMs = Math.max(0, Number(options.debounceMs ?? options.interval ?? DEFAULT_AUTOSAVE_DEBOUNCE_MS))

  const [state, setState] = useState(() => {
    let ctrl = null
    const initialSnap = {
      namespace: defaultNamespace,
      key: defaultKey,
      value: options.initialValue ?? null,
      seq: initialSeq,
      savedSeq: initialSeq,
      status: initialSeq > 0 ? 'saved' : 'idle',
      dirty: false,
      error: null
    }
    ctrl = createSafeAutoSave({
      ctx: options.ctx,
      namespace: defaultNamespace,
      debounceMs,
      initialSeq,
      onSave: options.onSave,
      setTimeout: options.setTimeout,
      clearTimeout: options.clearTimeout,
      onStatusChange(snap) {
        setState(prev => ({
          ...prev,
          snapshot: snap
        }))
      }
    })
    return {
      controller: ctrl,
      snapshot: initialSnap
    }
  })

  const { controller, snapshot } = state

  const save = useCallback(
    (nextValue, saveOpts = {}) => {
      const targetKey = saveOpts.key || defaultKey
      return controller.schedule(targetKey, nextValue, saveOpts)
    },
    [controller, defaultKey]
  )

  const flush = useCallback(
    (targetKey, flushOpts = {}) => {
      return controller.flush(targetKey, flushOpts)
    },
    [controller]
  )

  const cancel = useCallback(
    (targetKey, cancelOpts = {}) => {
      return controller.cancel(targetKey, cancelOpts)
    },
    [controller]
  )

  const label =
    snapshot.status === 'coalescing' || snapshot.status === 'saving'
      ? `Coalescing Seq #${snapshot.seq}...`
      : snapshot.seq > 0
        ? `Coalesced Seq #${snapshot.seq} Saved`
        : 'Idle'

  return {
    value: snapshot.value,
    seq: snapshot.seq,
    savedSeq: snapshot.savedSeq,
    status: snapshot.status,
    dirty: snapshot.dirty,
    error: snapshot.error,
    label,
    save,
    flush,
    cancel,
    controller
  }
}

const ROUTE_PATH = '/defuzz'

export const DESTINATION_NOT_CHOSEN_TEXT = 'Destination not chosen yet. Choose a projects folder first.'

export function projectDestinationText(root, name) {
  const base = typeof root === 'string' ? root.trim() : ''
  if (!base) return DESTINATION_NOT_CHOSEN_TEXT
  const sep = base.includes('\\') && !base.includes('/') ? '\\' : '/'
  const trimmed = base.replace(/[\\/]+$/, '') || sep
  const leaf = String(name || '').replace(/^[\\/]+/, '')
  return trimmed.endsWith(sep) ? `${trimmed}${leaf}` : `${trimmed}${sep}${leaf}`
}

export const HANDOFF_SUCCESS_OUTCOME = 'completed'

const DEFAULT_REQUEST_TIMEOUT_MS = 30_000
const DEFAULT_LINT_TIMEOUT_MS = 120_000
const DEADLINE_EXCEEDED = Symbol('DEADLINE_EXCEEDED')
const LINT_TIMEOUT_EXCEEDED = Symbol('LINT_TIMEOUT_EXCEEDED')
const CONNECTION_GUARD_FAILED = Symbol('CONNECTION_GUARD_FAILED')

const DISCONNECT_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'EPIPE',
  'ENOTCONN',
  'ERR_SOCKET_CLOSED'
])

const RECOGNISED_RECEIPT_STATUSES = new Set([
  'queued',
  'started',
  'unknown',
  'terminal'
])

function formatError(err) {
  return String(err?.message || err || 'Unknown error')
}

export function parseHttpError(error) {
  const msg = String(error?.message || '')
  const match = /(?:^|[\s:])([1-5]\d\d): /.exec(msg)
  const status = typeof error?.statusCode === 'number'
    ? error.statusCode
    : typeof error?.status === 'number'
      ? error.status
      : match
        ? Number(match[1])
        : null
  const body = match ? msg.slice(match.index + match[0].length) : ''
  if (body) {
    try {
      const parsed = JSON.parse(body)
      if (typeof parsed?.detail === 'string') {
        return { status, detail: parsed.detail.trim() }
      }
    } catch {}
  }
  return { status, detail: body.trim().slice(0, 300) }
}

function isDisconnectError(err) {
  if (typeof err?.code === 'string' && DISCONNECT_CODES.has(err.code)) {
    return true
  }
  return /not connected|gateway unavailable|socket (is )?closed|connection closed/i.test(
    formatError(err)
  )
}

function isMethodNotFoundError(err) {
  if (err?.code === -32601 || err?.code === 'METHOD_NOT_FOUND') {
    return true
  }
  return /method not found|unknown method|unsupported method/i.test(formatError(err))
}

function isTimeoutError(err) {
  return err?.code === 'ETIMEDOUT' || /timeout|timed out|etimedout/i.test(formatError(err))
}

function isValidReceipt(receipt) {
  return (
    receipt !== null &&
    typeof receipt === 'object' &&
    !Array.isArray(receipt) &&
    typeof receipt.status === 'string' &&
    RECOGNISED_RECEIPT_STATUSES.has(receipt.status)
  )
}

function cloneAndFreezeData(value, seen = new Map()) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') {
      return `[Unsupported payload: ${typeof value}]`
    }
    return value
  }
  if (typeof value.then === 'function') {
    return '[Unsupported payload: Thenable]'
  }
  if (seen.has(value)) {
    return seen.get(value)
  }
  if (typeof structuredClone === 'function') {
    try {
      const cloned = structuredClone(value)
      return deepFreeze(cloned)
    } catch {
      // Fall back to JSON-safe plain data clone, dropping non-cloneable values with a note
    }
  }
  if (Array.isArray(value)) {
    const arr = []
    seen.set(value, arr)
    for (let i = 0; i < value.length; i++) {
      const item = value[i]
      if (
        item === undefined ||
        typeof item === 'function' ||
        typeof item === 'symbol' ||
        typeof item === 'bigint' ||
        (item !== null && typeof item === 'object' && typeof item.then === 'function')
      ) {
        arr.push(`[Unsupported payload: ${item === undefined ? 'undefined' : typeof item}]`)
      } else {
        arr.push(cloneAndFreezeData(item, seen))
      }
    }
    return Object.freeze(arr)
  }
  const proto = Object.getPrototypeOf(value)
  if (proto !== null && proto !== Object.prototype) {
    try {
      const jsonParsed = JSON.parse(JSON.stringify(value))
      if (jsonParsed !== undefined && typeof jsonParsed === 'object' && jsonParsed !== null) {
        return deepFreeze(jsonParsed)
      }
      if (jsonParsed !== undefined) {
        return jsonParsed
      }
    } catch {
      // Non-JSON-serializable instance
    }
    return `[Unsupported payload: ${value.constructor?.name || 'Object'}]`
  }
  const out = {}
  seen.set(value, out)
  for (const key of Object.keys(value)) {
    const prop = value[key]
    if (prop === undefined) {
      continue
    }
    if (
      typeof prop === 'function' ||
      typeof prop === 'symbol' ||
      typeof prop === 'bigint' ||
      (prop !== null && typeof prop === 'object' && typeof prop.then === 'function')
    ) {
      continue
    }
    out[key] = cloneAndFreezeData(prop, seen)
  }
  // Non-cloneable values (functions, symbols) are dropped silently, as JSON.stringify does;
  // never inject metadata keys into consumer-owned payloads.
  return Object.freeze(out)
}

function deepFreeze(value, seen = new Set()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) {
    return value
  }
  if (typeof value.then === 'function') {
    return value
  }
  seen.add(value)
  for (const key of Object.keys(value)) {
    deepFreeze(value[key], seen)
  }
  try {
    return Object.freeze(value)
  } catch {
    return value
  }
}

function mapLintResolution(val) {
  if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
    const status = typeof val.status === 'string' ? val.status.trim().toLowerCase() : null
    if (status === 'incomplete' || val.ok === false) {
      return { lint: 'incomplete', lintReport: val }
    }
    if (
      val.ok === true &&
      (status === null || status === 'complete' || status === 'completed' || status === 'clean' || status === 'findings' || status === 'ok')
    ) {
      return { lint: 'ok', lintReport: val }
    }
    return { lint: 'unknown', lintReport: val }
  }
  if (val === true) {
    return { lint: 'ok' }
  }
  return { lint: 'unknown' }
}

/**
 * Create a one-shot session hand-off coordinator for desktop template adaptation.
 *
 * Result contract (`await handoff.run(op)`):
 * - Every snapshot returned by `run()`, `handoff.latest(operationId)`, `result.lintDone`, and
 *   `result.navigationDone` is deeply cloned from detached plain JSON-like data (via `structuredClone`
 *   where available, else a JSON-safe clone of plain data; non-cloneable values such as functions are dropped, as with JSON)
 *   and frozen (`Object.freeze`) on the CLONE. Objects passed to or returned by caller callbacks
 *   (the receipt passed to `onSuccess` and any lint report returned by it) are never frozen in place.
 *   The initial settled snapshot returned by `run()` (and to double-click callers while the operation
 *   remains cached) never mutates in place after settlement.
 * - `status`: `'completed' | 'cancelled' | 'failed' | 'timed_out' | 'lost' | 'untracked' | 'unknown' | 'error'`
 *   Describes ONLY the submitted task's admission and receipt polling outcome within `maxWaitMs`.
 *   Never flipped by late navigation or by post-completion `onSuccess` lint checks.
 * - `outcome`: receipt outcome string (e.g. `'completed'`, `'cancelled'`, `'failed'`) or `null`.
 * - `session_id`: canonical runtime session ID or `null`.
 * - `stored_session_id`: persisted session ID string (or `''`).
 * - `admission_id`: prompt admission ID or `null`.
 * - `navigation`: `'opened' | 'pending' | 'skipped' | 'failed'`
 *   Reports `host.openSession` UI navigation separately from `status`. Because `host.openSession`
 *   cannot be cancelled once invoked (`apps/desktop/src/sdk/index.ts` awaits dialing before
 *   navigating), it is only called when time remains in `maxWaitMs`, and `'pending'` is a valid
 *   initial value when `run()` settles before `openSession` finishes. Late navigation updates are
 *   delivered via optional `op.onNavigation` / `deps.onNavigation` (`{ operationId, navigation, opened, session_id, stored_session_id, admission_id, open_error? }`),
 *   `handoff.latest(operationId)`, and the non-enumerable `result.navigationDone` promise (which
 *   resolves to the frozen snapshot when navigation settles as `'skipped' | 'opened' | 'failed'`) —
 *   never by mutating the settled snapshot.
 * - `opened`: boolean (`navigation === 'opened'`).
 * - `open_error` (optional): string error message when `navigation === 'failed'`.
 * - `lint`: `'ok' | 'incomplete' | 'unknown' | 'pending' | 'timed_out' | 'failed' | 'skipped'`
 *   Reports the post-completion `onSuccess` (lint re-run) outcome separately under its own bounded
 *   `lintTimeoutMs` budget (default `120_000`ms, injectable via `deps.lintTimeoutMs` or `op.lintTimeoutMs`).
 *   `run()` settles as soon as receipt `status` is known and never blocks on a slow or hung `onSuccess`,
 *   so `'pending'` is a valid initial value when `onSuccess` is still running at settlement.
 *   When `onSuccess` resolves to a lint report object, `report.ok === true` with complete status maps to
 *   `'ok'`, while `report.status === 'incomplete'` or `report.ok === false` maps to `'incomplete'` (with
 *   a frozen clone of the report attached as `lintReport`). Non-object resolutions map to `'ok'` only when
 *   explicitly `true`, else `'unknown'`. When `onSuccess` finishes or times out later, the update is
 *   delivered via optional `op.onLint` / `deps.onLint`, `handoff.latest(operationId)`, and the
 *   non-enumerable `result.lintDone` promise (snapshot at lint completion; navigation may still be pending).
 * - `lintDone` (non-enumerable Promise): snapshot at lint completion (navigation may still be pending).
 * - `navigationDone` (non-enumerable Promise): snapshot when navigation settles (`'skipped' | 'opened' | 'failed'`).
 * - `lintReport` (optional): frozen clone of the lint report object when `onSuccess` resolves to a report object.
 * - `lint_error` (optional): string error message when `lint === 'failed'` or `'timed_out'`.
 * - `error` (optional): string error message for `status` failures (or `onSuccess` failure).
 * - `result` (optional): frozen clone of the terminal receipt result payload when present (supported payload: plain JSON-like data; non-cloneable values such as functions are dropped, as with JSON).
 */
export function createHandoff(deps = {}) {
  let disposed = false
  let resolveDisposed
  const disposedPromise = new Promise(resolve => { resolveDisposed = resolve })
  const cancellationError = () => Object.assign(new Error('Handoff disposed'), { code: 'ERR_SOCKET_CLOSED', [CONNECTION_GUARD_FAILED]: true })
  const checkAlive = () => { if (disposed) throw cancellationError() }
  const untilDisposed = promise => Promise.race([promise, disposedPromise.then(() => { throw cancellationError() })])
  const dispose = () => { disposed = true; resolveDisposed() }
  const hostRef = deps.host || host
  const setTimer = deps.setTimeout || globalThis.setTimeout
  const clearTimer = deps.clearTimeout || globalThis.clearTimeout
  const now =
    typeof deps.now === 'function'
      ? deps.now
      : () => (typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : Date.now())
  const pollIntervalMs = deps.pollIntervalMs ?? 1000
  const maxPollIntervalMs = deps.maxPollIntervalMs ?? 5000
  const maxWaitMs = deps.maxWaitMs ?? 600_000
  const lintTimeoutMs = deps.lintTimeoutMs ?? DEFAULT_LINT_TIMEOUT_MS
  const requestTimeoutMs = deps.requestTimeoutMs
  const defaultRequestTimeoutMs = requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
  const defaultOnNavigation = typeof deps.onNavigation === 'function' ? deps.onNavigation : null
  const defaultOnLint = typeof deps.onLint === 'function' ? deps.onLint : null
  const maxUnknownPolls = 3

  const inFlightOps = new Map()
  // Settled results are kept until the caller releases them via release(operationId)
  // so that a duplicate click never resubmits the operation.
  const settledOps = new Map()
  // Latest immutable snapshots reflect late navigation/lint updates without mutating settledOps.
  const latestOps = new Map()
  // Generation token per operationId; bumped on every run() and invalidated on release(operationId)
  // so late callbacks from a released/superseded run never repopulate caches or overwrite a newer run.
  const opGenerations = new Map()

  function nextGeneration(operationId) {
    const nextGen = (opGenerations.get(operationId) ?? 0) + 1
    opGenerations.set(operationId, nextGen)
    return nextGen
  }

  function isCurrentGeneration(operationId, gen) {
    return opGenerations.get(operationId) === gen
  }

  function normalizeConnectionId(value) {
    if (typeof value === 'string') {
      const trimmed = value.trim()
      return trimmed ? trimmed : null
    }
    if (value && typeof value === 'object') {
      if (typeof value.connectionId === 'string') {
        const trimmed = value.connectionId.trim()
        return trimmed ? trimmed : null
      }
      if (typeof value.id === 'string') {
        const trimmed = value.id.trim()
        return trimmed ? trimmed : null
      }
    }
    return null
  }

  function readActiveConnectionId() {
    if (!hostRef) return null
    const fromFn =
      typeof hostRef.activeConnectionId === 'function'
        ? normalizeConnectionId(hostRef.activeConnectionId())
        : null
    const fromState =
      typeof hostRef.state?.connectionId?.get === 'function'
        ? normalizeConnectionId(hostRef.state.connectionId.get())
        : null
    if (fromFn !== null && fromState !== null && fromFn !== fromState) {
      return null
    }
    return fromFn ?? fromState
  }

  function extractOwnerRoute(candidate, expectedConnId, fallbackProfile) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      return null
    }
    const connId = normalizeConnectionId(candidate)
    if (!connId || (expectedConnId !== null && connId !== expectedConnId)) {
      return null
    }
    if (candidate.mode !== 'remote' || connId === 'local') {
      return null
    }
    const prof =
      typeof candidate.profile === 'string' && candidate.profile.trim()
        ? candidate.profile.trim()
        : typeof fallbackProfile === 'string' && fallbackProfile.trim()
          ? fallbackProfile.trim()
          : ''
    const targetProf =
      typeof candidate.targetProfile === 'string' && candidate.targetProfile.trim()
        ? candidate.targetProfile.trim()
        : prof
    if (!prof || !targetProf) {
      return null
    }
    return {
      ...candidate,
      connectionId: connId,
      mode: 'remote',
      profile: prof,
      targetProfile: targetProf
    }
  }

  async function execute(op, runGen) {
    const { operationId, cwd, profile, title, prompt, onSuccess } = op
    const effectiveMaxWaitMs = op.maxWaitMs ?? maxWaitMs
    const effectiveLintTimeoutMs = op.lintTimeoutMs ?? lintTimeoutMs
    const onNavigationCb =
      typeof op.onNavigation === 'function' ? op.onNavigation : defaultOnNavigation
    const onLintCb = typeof op.onLint === 'function' ? op.onLint : defaultOnLint
    const request_id = `${operationId}:create`
    const submission_id = `${operationId}:submit`

    const startMs = now()
    let sleptMs = 0
    let settled = false
    let settledFields = null

    function isGenCurrent() {
      return isCurrentGeneration(operationId, runGen)
    }

    function attachSnapshotPromises(target, lintPromise, navPromise) {
      const cloned = cloneAndFreezeData(target)
      const snap = { ...cloned }
      Object.defineProperty(snap, 'lintDone', {
        value: lintPromise,
        enumerable: false,
        configurable: false,
        writable: false
      })
      Object.defineProperty(snap, 'navigationDone', {
        value: navPromise,
        enumerable: false,
        configurable: false,
        writable: false
      })
      return Object.freeze(snap)
    }

    function earlyFailureResult(fields) {
      settled = true
      const base = {
        operationId,
        outcome: null,
        session_id: null,
        stored_session_id: '',
        admission_id: null,
        navigation: 'skipped',
        opened: false,
        lint: 'skipped',
        ...fields
      }
      settledFields = base
      let snap = null
      const donePromise = Promise.resolve().then(() =>
        isGenCurrent() ? latestOps.get(operationId) || snap : snap
      )
      snap = attachSnapshotPromises({ ...base }, donePromise, donePromise)
      if (isGenCurrent()) {
        latestOps.set(operationId, snap)
      }
      return snap
    }

    function remainingMs() {
      const elapsed = Math.max(0, now() - startMs, sleptMs)
      return Math.max(0, effectiveMaxWaitMs - elapsed)
    }

    function makeDeadlineError() {
      return Object.assign(new Error(`Receipt polling timed out after ${effectiveMaxWaitMs}ms`), {
        [DEADLINE_EXCEEDED]: true
      })
    }

    function isDeadlineError(err) {
      return Boolean(err && err[DEADLINE_EXCEEDED])
    }

    async function waitDelay(ms) {
      if (ms <= 0) return
      let timerId
      try {
        await Promise.race([new Promise(resolve => { timerId = setTimer(resolve, ms) }), disposedPromise])
      } finally { if (timerId !== undefined) clearTimer(timerId) }
      sleptMs += ms
    }

    async function awaitWithDeadline(startPromiseFn) {
      checkAlive()
      const rem = remainingMs()
      if (settled || rem <= 0) {
        throw makeDeadlineError()
      }

      let opDone = false
      let opVal
      let opErr
      let opFailed = false

      const rawPromise = startPromiseFn(rem)
      const tracked = Promise.resolve(rawPromise).then(
        v => {
          opDone = true
          opVal = v
        },
        e => {
          opDone = true
          opFailed = true
          opErr = e
        }
      )

      for (let i = 0; i < 4; i++) {
        if (opDone) break
        await Promise.resolve()
      }

      checkAlive()
      if (opDone) {
        if (settled || remainingMs() <= 0) {
          throw makeDeadlineError()
        }
        if (opFailed) {
          throw opErr
        }
        return opVal
      }

      const remAfterMicro = remainingMs()
      if (settled || remAfterMicro <= 0) {
        throw makeDeadlineError()
      }

      let timerId
      try {
        await Promise.race([
          untilDisposed(tracked),
          new Promise((_, reject) => {
            timerId = setTimer(() => {
              sleptMs = Math.max(sleptMs, effectiveMaxWaitMs)
              reject(makeDeadlineError())
            }, remAfterMicro)
          })
        ])
      } finally {
        if (timerId !== undefined) {
          clearTimer(timerId)
        }
      }

      checkAlive()
      if (settled || remainingMs() <= 0) {
        throw makeDeadlineError()
      }
      if (opFailed) {
        throw opErr
      }
      return opVal
    }

    // Pin the live gateway once per operation (`apps/desktop/src/sdk/index.ts:1521`),
    // or fall back to `host.request` (`apps/desktop/src/sdk/index.ts:1506`) while
    // pinning the initial connectionId so we never switch connections mid-operation.
    const hasGetGateway = Boolean(hostRef && typeof hostRef.getGateway === 'function')
    const gateway = hasGetGateway ? hostRef.getGateway() : null
    const hasHostRequest = !hasGetGateway && Boolean(hostRef && typeof hostRef.request === 'function')

    if (!gateway && !hasHostRequest) {
      return earlyFailureResult({
        status: 'error',
        error: 'Hermes gateway unavailable'
      })
    }

    const hasExplicitConnection = op.connection !== undefined || op.route !== undefined
    const capturedConnId = hasExplicitConnection
      ? normalizeConnectionId(op.connection !== undefined ? op.connection : op.route)
      : null
    const initialConnId = readActiveConnectionId()
    const initialProfile = hostRef.state?.profile?.get?.()

    if (
      hasExplicitConnection &&
      (capturedConnId === null || initialConnId === null || initialConnId !== capturedConnId)
    ) {
      return earlyFailureResult({
        status: 'lost',
        error: 'Hermes gateway connection does not match captured connection'
      })
    }

    const pinnedConnId = hasExplicitConnection ? capturedConnId : initialConnId

    if (!gateway && pinnedConnId === null) {
      return earlyFailureResult({
        status: 'lost',
        error: 'Hermes gateway connection identity unavailable'
      })
    }

    const capturedOwnerRoute = extractOwnerRoute(op.route ?? op.connection, pinnedConnId, profile)
    if (capturedOwnerRoute && typeof hostRef.requestProfile !== 'function') {
      return earlyFailureResult({ status: 'lost', error: 'Profile-scoped gateway unavailable' })
    }

    function readCurrentConnectionId() {
      return readActiveConnectionId()
    }
    const profileChanged = () => !capturedOwnerRoute && (
      hostRef.state?.profile?.get?.() !== initialProfile ||
      (initialProfile !== undefined && profile !== undefined && initialProfile !== profile)
    )
    const request = (method, params) =>
      awaitWithDeadline(rem => {
        if (profileChanged()) throw Object.assign(new Error('Hermes gateway profile switched mid-operation'), {
          code: 'ERR_SOCKET_CLOSED', [CONNECTION_GUARD_FAILED]: true
        })
        const rpcTimeoutMs = Math.min(defaultRequestTimeoutMs, rem)
        if (capturedOwnerRoute) {
          return hostRef.requestProfile(capturedOwnerRoute, method, params, rpcTimeoutMs)
        }
        if (gateway) {
          return gateway.request(method, params, rpcTimeoutMs)
        }
        const currentConnId = readActiveConnectionId()
        if (pinnedConnId === null || currentConnId === null || currentConnId !== pinnedConnId) {
          return Promise.reject(
            Object.assign(new Error('Hermes gateway connection switched mid-operation'), {
              code: 'ERR_SOCKET_CLOSED',
              [CONNECTION_GUARD_FAILED]: true
            })
          )
        }
        return hostRef.request(method, params, rpcTimeoutMs)
      })

    let createSnap
    try {
      createSnap = await request('session.create', {
        source: 'desktop',
        cwd,
        cwd_explicit: true,
        profile,
        title,
        hidden: false,
        request_id
      })
    } catch (err) {
      return earlyFailureResult({
        status: isDeadlineError(err) ? 'timed_out' : isDisconnectError(err) ? 'lost' : 'error',
        error: formatError(err)
      })
    }

    const session_id =
      typeof createSnap?.session_id === 'string' && createSnap.session_id ? createSnap.session_id : null
    const stored_session_id =
      typeof createSnap?.stored_session_id === 'string' ? createSnap.stored_session_id : ''

    if (!session_id) {
      return earlyFailureResult({
        status: 'error',
        stored_session_id,
        error: 'Invalid session.create response: missing session_id'
      })
    }

    // Subscribe to the canonical session before submitting the prompt
    try {
      await request('session.resume', { session_id, profile })
    } catch (err) {
      return earlyFailureResult({
        status: isDeadlineError(err) ? 'timed_out' : isDisconnectError(err) ? 'lost' : 'error',
        session_id,
        stored_session_id,
        error: formatError(err)
      })
    }

    let admission_id = null
    try {
      // Never pass unattended/yolo/finite flags; user approvals must remain enforced
      const submitRes = await request('prompt.submit', {
        session_id,
        profile,
        text: prompt,
        submission_id,
        queued: false
      })
      admission_id =
        typeof submitRes?.admission_id === 'string' && submitRes.admission_id ? submitRes.admission_id : null
    } catch (submitErr) {
      if (isDeadlineError(submitErr) || remainingMs() <= 0) {
        return earlyFailureResult({
          status: 'timed_out',
          session_id,
          stored_session_id,
          error: formatError(submitErr)
        })
      }
      if (submitErr && submitErr[CONNECTION_GUARD_FAILED]) {
        return earlyFailureResult({
          status: 'lost',
          session_id,
          stored_session_id,
          error: formatError(submitErr)
        })
      }
      // Never blindly re-send prompt.submit; recover via session.resume pending[] matching submission_id
      let resumeSnap
      try {
        resumeSnap = await request('session.resume', { session_id, profile })
      } catch (resumeErr) {
        return earlyFailureResult({
          status: isDeadlineError(resumeErr) ? 'timed_out' : 'lost',
          session_id,
          stored_session_id,
          error: formatError(resumeErr)
        })
      }
      const pending = Array.isArray(resumeSnap?.pending) ? resumeSnap.pending : []
      const matched = pending.find(
        entry =>
          entry &&
          entry.input_id === submission_id &&
          typeof entry.admission_id === 'string' &&
          entry.admission_id
      )
      if (!matched) {
        return earlyFailureResult({
          status: 'unknown',
          session_id,
          stored_session_id,
          error: formatError(submitErr)
        })
      }
      admission_id = matched.admission_id
    }

    if (!admission_id) {
      return earlyFailureResult({
        status: 'unknown',
        session_id,
        stored_session_id,
        error: 'Missing admission_id from prompt.submit'
      })
    }

    // `host.openSession` without `options.route` reads the ambient live connection
    // (`$connection.get()` / `activeGatewayConnectionId()`) and dials the active
    // gateway, while `options.route` dials `openGatewayForAgent(route.connectionId, route.profile)`
    // for explicit cross-connection routes (Hermes desktop SDK `src/sdk/index.ts`).
    // Pass the captured remote owner route when available; otherwise fail closed
    // (`status: 'lost'`, no navigation) if the active connection differs from `pinnedConnId`.
    checkAlive()
    if (profileChanged() || (!capturedOwnerRoute && readCurrentConnectionId() !== pinnedConnId)) {
      return earlyFailureResult({
        status: 'lost',
        session_id,
        stored_session_id,
        admission_id,
        error: 'Hermes gateway connection or profile switched before openSession'
      })
    }

    // `host.openSession` cannot be cancelled once started (it awaits gateway/profile
    // dialing before navigating). Only call it if time remains in `maxWaitMs`.
    // Never let a slow or late navigation flip `status` to `'timed_out'` or mutate
    // `status`/`outcome` after settlement; report navigation separately under `navigation`.
    let navigation = 'skipped'
    let opened = false
    let open_error
    let lint = 'skipped'
    let lint_error
    let lintReport
    let resolveLintDone
    const lintDonePromise = new Promise(resolve => {
      resolveLintDone = resolve
    })
    let resolveNavigationDone
    const navigationDonePromise = new Promise(resolve => {
      resolveNavigationDone = resolve
    })

    function createCurrentSnapshot(extraFields = {}) {
      const merged = { ...(settledFields || {}), ...extraFields }
      const snap = {
        operationId,
        session_id,
        stored_session_id,
        admission_id,
        navigation,
        opened,
        ...(open_error !== undefined ? { open_error } : {}),
        lint,
        ...(lintReport !== undefined ? { lintReport } : {}),
        ...(lint_error !== undefined ? { lint_error } : {}),
        ...merged,
        ...(lint === 'failed' && lint_error !== undefined && merged.error === undefined
          ? { error: lint_error }
          : {})
      }
      return attachSnapshotPromises(snap, lintDonePromise, navigationDonePromise)
    }

    function updateLatestSnapshot() {
      if (!settledFields) return null
      const snap = createCurrentSnapshot()
      if (isGenCurrent()) {
        latestOps.set(operationId, snap)
      }
      return snap
    }

    function notifyNavigation() {
      if (!disposed && typeof onNavigationCb === 'function') {
        try {
          const ret = onNavigationCb(
            cloneAndFreezeData({
              operationId,
              navigation,
              opened,
              session_id,
              stored_session_id,
              admission_id,
              ...(open_error !== undefined ? { open_error } : {})
            })
          )
          Promise.resolve(ret).catch(() => {})
        } catch {
          // Never let an observer callback throw into background navigation tracking
        }
      }
    }

    if (
      stored_session_id !== '' &&
      hostRef &&
      typeof hostRef.openSession === 'function' &&
      !settled &&
      remainingMs() > 0
    ) {
      const openOpts = capturedOwnerRoute ? { profile, route: capturedOwnerRoute } : { profile }
      navigation = 'pending'
      let navResolvedSync = false

      let openPromise
      try {
        openPromise = Promise.resolve(hostRef.openSession(stored_session_id, openOpts))
      } catch (syncOpenErr) {
        openPromise = Promise.reject(syncOpenErr)
      }

      untilDisposed(openPromise).then(
        () => {
          navResolvedSync = true
          navigation = 'opened'
          opened = true
          const snap = updateLatestSnapshot()
          notifyNavigation()
          if (snap) {
            resolveNavigationDone(snap)
          }
        },
        openErr => {
          navResolvedSync = true
          navigation = 'failed'
          opened = false
          open_error = formatError(openErr)
          const snap = updateLatestSnapshot()
          notifyNavigation()
          if (snap) {
            resolveNavigationDone(snap)
          }
        }
      )

      // Allow fast/synchronous openSession mocks to settle before polling receipts,
      // without blocking receipt polling on a timer-delayed navigation.
      for (let i = 0; i < 4; i++) {
        if (navResolvedSync) break
        await Promise.resolve()
      }
    }

    const buildResult = fields => {
      settled = true
      settledFields = { ...fields }
      const snap = createCurrentSnapshot()
      if (isGenCurrent()) {
        latestOps.set(operationId, snap)
      }
      if (lint !== 'pending') {
        resolveLintDone(snap)
      }
      if (navigation !== 'pending') {
        resolveNavigationDone(snap)
      }
      return snap
    }

    function startBoundedLint(receipt) {
      if (typeof onSuccess !== 'function') {
        lint = 'skipped'
        return
      }

      const budgetMs = Math.max(0, Number(effectiveLintTimeoutMs ?? DEFAULT_LINT_TIMEOUT_MS))
      let lintSettled = false
      let lintTimerId

      function notifyLint() {
        if (!disposed && typeof onLintCb === 'function') {
          try {
            const ret = onLintCb(
              cloneAndFreezeData({
                operationId,
                lint,
                ...(lintReport !== undefined ? { lintReport } : {}),
                ...(lint_error !== undefined ? { lint_error } : {}),
                session_id,
                stored_session_id,
                admission_id
              })
            )
            Promise.resolve(ret).catch(() => {})
          } catch {
            // Ignore observer errors
          }
        }
      }

      function applyMappedLint(val) {
        const mapped = mapLintResolution(val)
        lint = mapped.lint
        if (mapped.lintReport !== undefined) {
          lintReport = cloneAndFreezeData(mapped.lintReport)
        }
      }

      let rawLintPromise
      try {
        const ret = onSuccess(receipt)
        if (!ret || typeof ret.then !== 'function') {
          lintSettled = true
          applyMappedLint(ret)
          notifyLint()
          return
        }
        rawLintPromise = Promise.resolve(ret)
      } catch (syncErr) {
        lintSettled = true
        lint = 'failed'
        lint_error = formatError(syncErr)
        notifyLint()
        return
      }

      lint = 'pending'
      const timeoutPromise = new Promise((_, reject) => {
        lintTimerId = setTimer(() => {
          reject(
            Object.assign(new Error(`onSuccess lint timed out after ${budgetMs}ms`), {
              [LINT_TIMEOUT_EXCEEDED]: true
            })
          )
        }, budgetMs)
        lintTimerId?.unref?.()
      })

      Promise.race([untilDisposed(rawLintPromise), timeoutPromise]).then(
        val => {
          if (lintTimerId !== undefined) {
            clearTimer(lintTimerId)
          }
          if (lintSettled) {
            return
          }
          lintSettled = true
          applyMappedLint(val)
          const snap = updateLatestSnapshot()
          notifyLint()
          if (snap) {
            resolveLintDone(snap)
          }
        },
        err => {
          if (lintTimerId !== undefined) {
            clearTimer(lintTimerId)
          }
          if (lintSettled) {
            return
          }
          lintSettled = true
          const isLintTimeout = Boolean(err && err[LINT_TIMEOUT_EXCEEDED])
          lint = isLintTimeout ? 'timed_out' : 'failed'
          lint_error = formatError(err)
          const snap = updateLatestSnapshot()
          notifyLint()
          if (snap) {
            resolveLintDone(snap)
          }
        }
      )
    }

    let delay = pollIntervalMs
    let unknownCount = 0
    let lastUnknownError = null

    while (!settled && remainingMs() > 0) {
      const sleepMs = Math.min(delay, remainingMs())
      await waitDelay(sleepMs)
      delay = Math.min(maxPollIntervalMs, delay * 2)

      if (settled || remainingMs() <= 0) {
        break
      }

      let receipt
      try {
        receipt = await request('prompt.receipt', {
          session_id,
          admission_id,
          include_result: true
        })
      } catch (recErr) {
        if (isDeadlineError(recErr) || settled || remainingMs() <= 0) {
          break
        }
        if (isMethodNotFoundError(recErr)) {
          return buildResult({ status: 'untracked', outcome: null, error: formatError(recErr) })
        }
        if (isDisconnectError(recErr)) {
          return buildResult({ status: 'lost', outcome: null, error: formatError(recErr) })
        }
        if (isTimeoutError(recErr)) {
          // prompt.receipt is read-only and idempotent; retry while within maxWaitMs
          continue
        }
        lastUnknownError = formatError(recErr)
        unknownCount += 1
        if (unknownCount >= maxUnknownPolls) {
          return buildResult({ status: 'unknown', outcome: null, error: lastUnknownError })
        }
        continue
      }

      if (settled || remainingMs() <= 0) {
        break
      }

      if (!isValidReceipt(receipt)) {
        lastUnknownError = 'malformed receipt'
        unknownCount += 1
        if (unknownCount >= maxUnknownPolls) {
          return buildResult({ status: 'unknown', outcome: null, error: lastUnknownError })
        }
        continue
      }

      if (receipt.status === 'terminal') {
        const outcome = receipt.outcome ?? null
        const resultField =
          receipt.result !== undefined ? { result: cloneAndFreezeData(receipt.result) } : {}
        if (outcome === HANDOFF_SUCCESS_OUTCOME) {
          if (!settled && typeof onSuccess === 'function') {
            startBoundedLint(receipt)
            // Give fast/microtask-resolving onSuccess a brief microtask turn before building
            // the snapshot, without waiting on timers or blocking settlement.
            for (let i = 0; i < 4; i++) {
              if (lint !== 'pending') break
              await Promise.resolve()
            }
          }
          return buildResult({
            status: 'completed',
            outcome,
            ...(lint === 'failed' && lint_error !== undefined ? { error: lint_error } : {}),
            ...resultField
          })
        }
        const mappedStatus =
          outcome === 'cancelled' ? 'cancelled' : outcome === 'failed' ? 'failed' : 'unknown'
        return buildResult({
          status: mappedStatus,
          outcome,
          ...resultField
        })
      }

      if (receipt.status === 'unknown') {
        unknownCount += 1
        if (unknownCount >= maxUnknownPolls) {
          return buildResult({
            status: 'unknown',
            outcome: receipt.outcome ?? null,
            ...(lastUnknownError ? { error: lastUnknownError } : {})
          })
        }
      } else {
        unknownCount = 0
        lastUnknownError = null
      }
    }

    return buildResult({
      status: 'timed_out',
      outcome: null,
      error: `Receipt polling timed out after ${effectiveMaxWaitMs}ms`
    })
  }

  function run(op) {
    if (disposed) return Promise.reject(cancellationError())
    if (!op || typeof op.operationId !== 'string' || !op.operationId.trim()) {
      return Promise.reject(new Error('operationId must be a non-empty string'))
    }
    if (typeof op.cwd !== 'string' || !op.cwd.trim()) {
      return Promise.reject(new Error('cwd must be a non-empty string'))
    }
    if (typeof op.prompt !== 'string' || !op.prompt.trim()) {
      return Promise.reject(new Error('prompt must be a non-empty string'))
    }

    const { operationId } = op
    if (inFlightOps.has(operationId)) {
      return inFlightOps.get(operationId)
    }
    if (settledOps.has(operationId)) {
      return Promise.resolve(settledOps.get(operationId))
    }

    const runGen = nextGeneration(operationId)
    const promise = (async () => {
      try {
        const result = await execute(op, runGen)
        if (isCurrentGeneration(operationId, runGen)) {
          settledOps.set(operationId, result)
        }
        return result
      } catch (err) {
        const fallback = {
          operationId,
          status: 'error',
          outcome: null,
          session_id: null,
          stored_session_id: '',
          admission_id: null,
          navigation: 'skipped',
          opened: false,
          lint: 'skipped',
          error: formatError(err)
        }
        let frozenFallback = null
        const donePromise = Promise.resolve().then(() =>
          isCurrentGeneration(operationId, runGen)
            ? latestOps.get(operationId) || frozenFallback
            : frozenFallback
        )
        const cloned = cloneAndFreezeData(fallback)
        const snap = { ...cloned }
        Object.defineProperty(snap, 'lintDone', {
          value: donePromise,
          enumerable: false,
          configurable: false,
          writable: false
        })
        Object.defineProperty(snap, 'navigationDone', {
          value: donePromise,
          enumerable: false,
          configurable: false,
          writable: false
        })
        frozenFallback = Object.freeze(snap)
        if (isCurrentGeneration(operationId, runGen)) {
          settledOps.set(operationId, frozenFallback)
          latestOps.set(operationId, frozenFallback)
        }
        return frozenFallback
      } finally {
        if (inFlightOps.get(operationId) === promise) {
          inFlightOps.delete(operationId)
        }
      }
    })()
    inFlightOps.set(operationId, promise)
    return promise
  }

  function inFlight(operationId) {
    return inFlightOps.has(operationId)
  }

  function latest(operationId) {
    return latestOps.get(operationId) ?? settledOps.get(operationId) ?? null
  }

  // Explicit caller consent to treat a future run() with this operationId as a brand-new hand-off (a fresh prompt.submit). Until released, re-runs never resubmit. Never call it from a click handler on the same operation; use it only after the caller has shown the result and discarded it.
  function release(operationId) {
    if (inFlightOps.has(operationId)) {
      return false
    }
    const deletedLatest = latestOps.delete(operationId)
    const deletedSettled = settledOps.delete(operationId)
    const deletedSomething = deletedLatest || deletedSettled
    if (deletedSomething) {
      nextGeneration(operationId)
    }
    return deletedSomething
  }

  return { run, inFlight, latest, release, dispose }
}

function StatCard({ label, value, detail }) {
  return jsxs('div', {
    style: {
      border: '1px solid var(--ui-stroke-secondary)',
      borderRadius: '8px',
      padding: '12px 14px',
      display: 'flex',
      flexDirection: 'column',
      gap: '4px'
    },
    children: [
      jsx('div', {
        style: { fontSize: '11px', color: 'var(--ui-text-quaternary)', textTransform: 'uppercase' },
        children: label
      }),
      jsx('div', {
        style: { fontSize: '20px', fontWeight: 600, color: 'var(--ui-text-primary)' },
        children: String(value ?? 0)
      }),
      detail
        ? jsx('div', {
            style: { fontSize: '11px', color: 'var(--ui-text-secondary)' },
            children: detail
          })
        : null
    ]
  })
}

function DirTable({ title, counts }) {
  const entries = Object.entries(counts || {})
  return jsxs('div', {
    style: {
      border: '1px solid var(--ui-stroke-secondary)',
      borderRadius: '8px',
      padding: '12px 14px',
      flex: 1,
      minWidth: '240px'
    },
    children: [
      jsx('div', {
        style: { fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--ui-text-primary)' },
        children: title
      }),
      entries.length === 0
        ? jsx('div', { style: { fontSize: '12px', color: 'var(--ui-text-quaternary)' }, children: 'No entries' })
        : jsx('div', {
            style: { display: 'flex', flexDirection: 'column', gap: '6px' },
            children: entries.map(([dir, cnt]) =>
              jsxs(
                'div',
                {
                  style: {
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    fontSize: '12px',
                    fontFamily: 'var(--font-mono)'
                  },
                  children: [
                    jsx('span', { style: { color: 'var(--ui-text-secondary)' }, children: dir === '.' ? './ (root)' : `${dir}/` }),
                    jsx(Badge, { variant: 'outline', children: `${cnt} files` })
                  ]
                },
                dir
              )
            )
          })
    ]
  })
}

export async function callToolsLockApi(ctx, path, opts = {}) {
  if (!ctx || typeof ctx.rest !== 'function') {
    throw new Error('Plugin context rest unavailable')
  }
  const relPath = path.startsWith('/') ? path : `/${path}`
  return ctx.rest(relPath, opts)
}

export function createToolsLockClient(ctx) {
  const scoped = { rest: createScopedRest(ctx) }
  return {
    getLock(project) {
      return callToolsLockApi(scoped, `/tools-lock?project=${encodeURIComponent(project)}`)
    },
    initLock(project) {
      return callToolsLockApi(scoped, '/tools-lock/init', {
        method: 'POST',
        body: { project, confirm: true }
      })
    },
    acceptInstalled(project, tool, reason) {
      const trimmed = typeof reason === 'string' ? reason.trim() : ''
      if (!trimmed) {
        return Promise.reject(new Error('A non-empty reason is required to accept an installed version.'))
      }
      return callToolsLockApi(scoped, '/tools-lock/accept', {
        method: 'POST',
        body: { project, tool, reason: trimmed }
      })
    },
    setReason(project, tool, reason) {
      const trimmed = typeof reason === 'string' ? reason.trim() : ''
      if (!trimmed) {
        return Promise.reject(new Error('A non-empty reason is required.'))
      }
      return callToolsLockApi(scoped, '/tools-lock/reason', {
        method: 'POST',
        body: { project, tool, reason: trimmed }
      })
    },
    snooze(project, tool, days = 30) {
      return callToolsLockApi(scoped, '/tools-lock/snooze', {
        method: 'POST',
        body: { project, tool, days }
      })
    }
  }
}

export function ToolsLockSection({
  project,
  toolsLock,
  onAcceptPrompt,
  onSaveAccept,
  onEditReasonPrompt,
  onSaveReason,
  onSnooze30d,
  onInitLock,
  promptState,
  onChangePromptText,
  onCancelPrompt,
  busy
}) {
  const rows = Array.isArray(toolsLock?.rows) ? toolsLock.rows : []
  const summary = toolsLock?.summary || ''
  const enforce = toolsLock?.enforce || 'warn'
  const hasLock = Boolean(toolsLock?.lock)

  return jsxs('div', {
    'data-testid': 'tools-lock-section',
    style: {
      border: '1px solid var(--ui-stroke-secondary)',
      borderRadius: '8px',
      padding: '12px 14px',
      display: 'flex',
      flexDirection: 'column',
      gap: '10px'
    },
    children: [
      jsxs('div', {
        style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexWrap: 'wrap' },
        children: [
          jsxs('div', {
            children: [
              jsx('div', {
                style: { fontSize: '13px', fontWeight: 600, color: 'var(--ui-text-primary)' },
                children: `Tools (${rows.length}) · enforce = ${enforce}`
              }),
              summary
                ? jsx('div', {
                    style: { fontSize: '11px', color: 'var(--ui-text-secondary)', marginTop: '2px' },
                    children: summary
                  })
                : null
            ]
          }),
          !hasLock && project
            ? jsx(Button, {
                disabled: Boolean(busy),
                onClick: () => onInitLock && onInitLock(),
                children: 'Seed TOOLS.lock'
              })
            : null
        ]
      }),
      rows.length === 0
        ? jsx('div', {
            style: { fontSize: '12px', color: 'var(--ui-text-quaternary)' },
            children: hasLock ? 'No tools listed in TOOLS.lock.' : 'No TOOLS.lock found for this project.'
          })
        : jsx('div', {
            style: { overflowX: 'auto' },
            children: jsxs('table', {
              style: { width: '100%', borderCollapse: 'collapse', fontSize: '12px' },
              children: [
                jsx('thead', {
                  children: jsxs('tr', {
                    style: {
                      textAlign: 'left',
                      color: 'var(--ui-text-quaternary)',
                      borderBottom: '1px solid var(--ui-stroke-secondary)'
                    },
                    children: [
                      jsx('th', { style: { padding: '6px 8px' }, children: 'tool' }),
                      jsx('th', { style: { padding: '6px 8px' }, children: 'chosen' }),
                      jsx('th', { style: { padding: '6px 8px' }, children: 'installed' }),
                      jsx('th', { style: { padding: '6px 8px' }, children: 'upstream' }),
                      jsx('th', { style: { padding: '6px 8px' }, children: 'chosen on' }),
                      jsx('th', { style: { padding: '6px 8px' }, children: 'by' }),
                      jsx('th', { style: { padding: '6px 8px' }, children: 'reason' }),
                      jsx('th', { style: { padding: '6px 8px' }, children: 'actions' })
                    ]
                  })
                }),
                jsx('tbody', {
                  children: rows.map(row => {
                    const isNudge = Boolean(row.nudge)
                    const isSnoozed = Boolean(row.snoozed_until)
                    const showUpstream = Boolean(row.upstream_latest) && !isSnoozed
                    const ageMonths = Number(row.age_months || 0)
                    const isActiveAccept =
                      promptState && promptState.tool === row.tool && promptState.mode === 'accept'
                    const isActiveReason =
                      promptState && promptState.tool === row.tool && promptState.mode === 'reason'
                    const promptTrimmed = String(promptState?.text || '').trim()

                    return jsxs(
                      'tr',
                      {
                        'data-tool': row.tool,
                        'data-nudge': isNudge ? 'true' : 'false',
                        style: {
                          borderBottom: '1px solid var(--ui-stroke-secondary)',
                          background: isNudge ? 'var(--ui-bg-secondary)' : 'transparent'
                        },
                        children: [
                          jsx('td', {
                            style: { padding: '8px', fontFamily: 'var(--font-mono)', fontWeight: 600 },
                            children: row.tool
                          }),
                          jsx('td', {
                            style: { padding: '8px', fontFamily: 'var(--font-mono)' },
                            children: row.chosen || '—'
                          }),
                          jsx('td', {
                            style: {
                              padding: '8px',
                              fontFamily: 'var(--font-mono)',
                              color: row.status === 'drift' ? 'var(--ui-accent)' : 'var(--ui-text-primary)'
                            },
                            children: row.installed || '—'
                          }),
                          jsx('td', {
                            style: { padding: '8px', fontFamily: 'var(--font-mono)', color: 'var(--ui-text-quaternary)' },
                            children: showUpstream
                              ? `upstream ${row.upstream_latest}`
                              : isSnoozed
                                ? `snoozed until ${row.snoozed_until}`
                                : '—'
                          }),
                          jsxs('td', {
                            style: { padding: '8px', color: 'var(--ui-text-secondary)' },
                            children: [
                              jsx('div', { children: row.chosen_on || '—' }),
                              jsx('div', {
                                style: {
                                  fontSize: '11px',
                                  color: isNudge ? 'var(--ui-accent)' : 'var(--ui-text-quaternary)'
                                },
                                children: isNudge
                                  ? `chosen ${ageMonths} months ago · re-decide?`
                                  : `chosen ${ageMonths} months ago`
                              })
                            ]
                          }),
                          jsx('td', {
                            style: { padding: '8px' },
                            children: jsx(Badge, { variant: 'outline', children: row.by || 'human' })
                          }),
                          jsxs('td', {
                            style: { padding: '8px', color: 'var(--ui-text-secondary)', maxWidth: '300px' },
                            children: [
                              jsx('div', { children: row.reason || '' }),
                              isActiveAccept || isActiveReason
                                ? jsxs('div', {
                                    style: { display: 'flex', gap: '6px', marginTop: '6px', alignItems: 'center' },
                                    children: [
                                      jsx('input', {
                                        type: 'text',
                                        value: promptState.text || '',
                                        placeholder:
                                          isActiveAccept
                                            ? 'Why accept installed as chosen?'
                                            : 'Update reason for chosen version',
                                        onChange: e =>
                                          onChangePromptText && onChangePromptText(e?.target?.value ?? ''),
                                        style: {
                                          flex: 1,
                                          padding: '4px 6px',
                                          fontSize: '11px',
                                          borderRadius: '4px',
                                          border: '1px solid var(--ui-stroke-secondary)',
                                          background: 'transparent',
                                          color: 'var(--ui-text-primary)'
                                        }
                                      }),
                                      jsx(Button, {
                                        disabled: Boolean(busy) || !promptTrimmed,
                                        onClick: () =>
                                          isActiveAccept
                                            ? onSaveAccept && onSaveAccept(row.tool, promptTrimmed)
                                            : onSaveReason && onSaveReason(row.tool, promptTrimmed),
                                        children: isActiveAccept ? 'Confirm Accept' : 'Save Reason'
                                      }),
                                      jsx(Button, {
                                        disabled: Boolean(busy),
                                        onClick: () => onCancelPrompt && onCancelPrompt(),
                                        children: 'Cancel'
                                      })
                                    ]
                                  })
                                : null
                            ]
                          }),
                          jsxs('td', {
                            style: { padding: '8px', display: 'flex', gap: '6px', flexWrap: 'wrap' },
                            children: [
                              jsx(Button, {
                                disabled: Boolean(busy),
                                onClick: () => onAcceptPrompt && onAcceptPrompt(row.tool, row.reason || ''),
                                children: 'Accept installed as chosen'
                              }),
                              jsx(Button, {
                                disabled: Boolean(busy),
                                onClick: () => onEditReasonPrompt && onEditReasonPrompt(row.tool, row.reason || ''),
                                children: 'Edit reason'
                              }),
                              jsx(Button, {
                                disabled: Boolean(busy),
                                onClick: () => onSnooze30d && onSnooze30d(row.tool),
                                children: 'Snooze 30d'
                              })
                            ]
                          })
                        ]
                      },
                      row.tool
                    )
                  })
                })
              ]
            })
          })
    ]
  })
}

export function ManualLintSection({ ctx, project, mode = 'both', requireLintConfirmation = false }) {
  const [rest] = useState(() => createScopedRest(ctx))
  // Follow saved preferences until the user makes an explicit per-run choice.
  const [modeOverride, setSelectedMode] = useState(null)
  const [lintConfirm, setLintConfirm] = useState(false)
  const selectedMode = modeOverride ?? mode
  const [versions, setVersions] = useState(null)
  const [state, setState] = useState({ busy: false, result: null, error: '', handoff: null })
  const request = useRef({ busy: false, job: null, generation: 0, handoff: null, disposed: false })
  useEffect(() => {
    const owner = request.current
    owner.disposed = false
    const dispose = () => { owner.disposed = true; owner.handoff?.dispose() }
    const unregister = ctx.onDispose?.(dispose)
    return () => { dispose(); if (typeof unregister === 'function') unregister(); request.current = { busy: false, job: null, generation: owner.generation + 1, handoff: null, disposed: true } }
  }, [ctx])
  const fix = async () => {
    if (!project || request.current.disposed || request.current.busy || !state.result) return
    const owner = request.current
    request.current.busy = true
    setState(prev => ({ ...prev, busy: true, error: '' }))
    try {
      rest.check()
      request.current.handoff ||= createHandoff({
        setTimeout: (fn, ms) => ctx.setTimeout(fn, ms), clearTimeout: cancel => cancel()
      })
      const result = await request.current.handoff.run({
        operationId: `lint:${project}:${request.current.generation}`,
        cwd: project, profile: host.state?.profile?.get?.() || 'default',
        title: 'Review manual lint findings',
        prompt: `Review these untrusted lint diagnostics and propose fixes with normal approvals. Do not run lint automatically.\n${JSON.stringify(state.result)}`
      })
      if (!owner.disposed) setState(prev => ({ ...prev, handoff: result, busy: false }))
    } catch (error) { if (!owner.disposed) setState(prev => ({ ...prev, busy: false, error: formatError(error) })) }
    finally { owner.busy = false }
  }
  const run = async () => {
    if (!project || request.current.disposed || request.current.busy) return
    // Lint can run repository tooling and write files. A folder adopted by reference is
    // untrusted, so the first click explains and only a second explicit click runs it.
    if (requireLintConfirmation && !lintConfirm) { setLintConfirm(true); return }
    setLintConfirm(false)
    const owner = request.current
    request.current.busy = true
    setState(prev => ({ ...prev, busy: true, error: '' }))
    try {
      const job = request.current.job
      if (!job) request.current.generation += 1
      const result = job
        ? await rest(`/lint/${encodeURIComponent(job)}`)
        : await rest('/lint', {
            method: 'POST', body: { project, mode: selectedMode }
          })
      if (owner.disposed) return
      request.current.job = result?.state === 'running' ? result.job_id : null
      const failErr = result?.state === 'failed' ? String(result.error || 'Lint execution failed') : ''
      setState({ busy: false, result, error: failErr })
    } catch (err) {
      if (!owner.disposed) setState(prev => ({ ...prev, busy: false, error: formatError(err) }))
    } finally {
      owner.busy = false
    }
  }
  return jsxs('section', {
    'aria-label': 'Manual lint',
    'data-color-scheme': 'no-red-green',
    style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', padding: '12px', color: 'var(--ui-text-primary)' },
    children: [
      jsx('p', { children: `Manual whole-project lint (${selectedMode} group): ${project || 'No project selected'}` }),
      requireLintConfirmation ? jsx('p', { style: { margin: 0, fontSize: '11.5px', color: 'var(--ui-text-secondary)' }, children: 'Lint can execute repository code and write files. This folder was opened by reference and is not trusted.' }) : null,
      jsxs('label', { children: ['Run lint group', jsx('select', { 'aria-label': 'Run lint group', value: selectedMode,
        disabled: state.busy || state.result?.state === 'running', onChange: e => setSelectedMode(e.target.value),
        children: ['pre', 'post', 'both'].map(value => jsx('option', { value, children: value.toUpperCase() }, value)) })] }),
      jsx(Button, { disabled: !project || state.busy, onClick: run, children: state.busy ? 'Lint request pending…' : state.result?.state === 'running' ? 'Check lint status' : requireLintConfirmation && lintConfirm ? 'Confirm and run lint' : 'Run lint' }),
      requireLintConfirmation && lintConfirm && !state.busy ? jsx('p', { 'data-testid': 'manual-lint-confirm', role: 'status', style: { margin: 0 }, children: 'Lint can execute repository code and write files. Confirm to run lint on this existing project.' }) : null,
      jsx('div', { role: 'status', children: state.error || (state.busy ? 'Lint request pending…' : '') }),
      jsx('h4', { children: 'Tool versions / setup status' }),
      jsx(Button, { children: 'Refresh tool versions', disabled: state.busy, onClick: async () => {
        if (request.current.disposed || request.current.busy) return
        const owner = request.current
        owner.busy = true
        setState(prev => ({ ...prev, busy: true, error: '' }))
        try { const result = await rest('/tools/status'); if (!owner.disposed) setVersions(result) }
        catch (error) { if (!owner.disposed) setState(prev => ({ ...prev, error: formatError(error) })) }
        finally { owner.busy = false; if (!owner.disposed) setState(prev => ({ ...prev, busy: false })) }
      } }),
      versions ? outputView(versions) : jsx('p', { children: 'Tool versions not loaded. Refresh to read manifest versions and installation state; no tools are installed by this action. Settings shows the installed versions under Tools on this computer, separately from manifest versions and TOOLS.lock.' }),
      state.result ? jsx('pre', { style: { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }, children: JSON.stringify(state.result, null, 2) }) : null,
      jsx('ul', { 'aria-label': 'Lint findings', children: (state.result?.result?.findings || state.result?.findings || []).map((finding, index) => jsx('li', { style: { borderLeft: '3px solid var(--ui-accent)', borderBottom: '1px solid var(--ui-stroke-secondary)', padding: '8px 12px', marginBottom: '8px', borderRadius: '4px' }, children: `${finding.file || ''}:${finding.line || ''} ${finding.tool || ''} ${finding.rule || ''} — ${finding.message || ''}` }, index)) }),
      jsx(Button, { children: 'Fix with Hermes', disabled: state.busy || !state.result || state.result.state === 'running', onClick: fix }),
      jsx('p', { children: 'Fixes open a normal visible session with approvals. Run lint again manually when ready.' }),
      state.handoff ? jsx('pre', { children: JSON.stringify(state.handoff, null, 2) }) : null
    ]
  })
}

export function AdoptBeforeAfterPage({ ctx }) {
  const [toolsClient] = useState(() => createToolsLockClient(ctx))
  const [state, setState] = useState({
    folderLabel: '',
    projectPath: '',
    report: null,
    rules: null,
    agentsMd: '',
    placeLog: [],
    toolsLock: null,
    toolsPrompt: null,
    toolsBusy: false,
    error: ''
  })

  const refreshToolsLock = useCallback(
    async projectPath => {
      if (!projectPath) return null
      try {
        const client = toolsClient
        const data = await client.getLock(projectPath)
        setState(prev => ({ ...prev, toolsLock: data }))
        return data
      } catch {
        return null
      }
    },
    [ctx]
  )

  const loadFolder = useCallback(async () => {
    try {
      const picked = await ctx.files.requestFolder()
      if (!picked || !picked.ok || !picked.folder) {
        return
      }
      const folder = picked.folder
      const folderId = typeof folder === 'string' ? folder : folder.id
      const reportRes = await ctx.files.readText(folderId, '.adopt/report.json')
      if (!reportRes || !reportRes.ok) {
        const errDetail =
          reportRes && reportRes.error && reportRes.error !== 'not-found'
            ? reportRes.message || reportRes.error
            : 'Selected folder does not contain .adopt/report.json yet. Run hermes defuzz run <copy> first.'
        setState(prev => ({
          ...prev,
          error: errDetail
        }))
        return
      }
      const report = JSON.parse(reportRes.text)
      const rulesRes = await ctx.files.readText(folderId, '.adopt/rules.json')
      const rules = rulesRes && rulesRes.ok ? JSON.parse(rulesRes.text) : null
      const agentsRes = await ctx.files.readText(folderId, 'AGENTS.md')
      const agentsMd = agentsRes && agentsRes.ok ? agentsRes.text : ''
      const logRes = await ctx.files.readText(folderId, '.adopt/place-log.json')
      const placeLog = logRes && logRes.ok ? JSON.parse(logRes.text) : []
      // Only the folder grant supplies an execution target; report metadata is untrusted.
      const projectPath = typeof folder === 'object' && typeof folder.path === 'string' ? folder.path : ''
      let toolsLock = null
      if (projectPath) {
        try {
          toolsLock = await toolsClient.getLock(projectPath)
        } catch {
          toolsLock = null
        }
      }

      setState({
        folderLabel: report.copy_root || folder.name || 'Adopted Copy',
        projectPath,
        report,
        rules,
        agentsMd,
        placeLog: Array.isArray(placeLog) ? placeLog : [],
        toolsLock,
        toolsPrompt: null,
        toolsBusy: false,
        error: ''
      })
    } catch (err) {
      setState(prev => ({ ...prev, error: String(err?.message || err) }))
    }
  }, [ctx])

  const handleAcceptPrompt = useCallback((tool, initialReason) => {
    setState(prev => ({
      ...prev,
      toolsPrompt: { tool, mode: 'accept', text: initialReason || '' }
    }))
  }, [])

  const handleEditReasonPrompt = useCallback((tool, initialReason) => {
    setState(prev => ({
      ...prev,
      toolsPrompt: { tool, mode: 'reason', text: initialReason || '' }
    }))
  }, [])

  const handleSaveAccept = useCallback(
    async (tool, reasonText) => {
      const trimmed = String(reasonText || '').trim()
      if (!trimmed || !state.projectPath) return
      setState(prev => ({ ...prev, toolsBusy: true, error: '' }))
      try {
        const client = toolsClient
        await client.acceptInstalled(state.projectPath, tool, trimmed)
        const updated = await client.getLock(state.projectPath)
        setState(prev => ({
          ...prev,
          toolsLock: updated,
          toolsPrompt: null,
          toolsBusy: false
        }))
      } catch (err) {
        setState(prev => ({
          ...prev,
          toolsBusy: false,
          error: String(err?.message || err)
        }))
      }
    },
    [ctx, state.projectPath]
  )

  const handleSaveReason = useCallback(
    async (tool, reasonText) => {
      const trimmed = String(reasonText || '').trim()
      if (!trimmed || !state.projectPath) return
      setState(prev => ({ ...prev, toolsBusy: true, error: '' }))
      try {
        const client = toolsClient
        await client.setReason(state.projectPath, tool, trimmed)
        const updated = await client.getLock(state.projectPath)
        setState(prev => ({
          ...prev,
          toolsLock: updated,
          toolsPrompt: null,
          toolsBusy: false
        }))
      } catch (err) {
        setState(prev => ({
          ...prev,
          toolsBusy: false,
          error: String(err?.message || err)
        }))
      }
    },
    [ctx, state.projectPath]
  )

  const handleSnooze30d = useCallback(
    async tool => {
      if (!state.projectPath) return
      setState(prev => ({ ...prev, toolsBusy: true, error: '' }))
      try {
        const client = toolsClient
        await client.snooze(state.projectPath, tool, 30)
        const updated = await client.getLock(state.projectPath)
        setState(prev => ({
          ...prev,
          toolsLock: updated,
          toolsBusy: false
        }))
      } catch (err) {
        setState(prev => ({
          ...prev,
          toolsBusy: false,
          error: String(err?.message || err)
        }))
      }
    },
    [ctx, state.projectPath]
  )

  const handleInitLock = useCallback(async () => {
    if (!state.projectPath) return
    setState(prev => ({ ...prev, toolsBusy: true, error: '' }))
    try {
      const client = toolsClient
      await client.initLock(state.projectPath)
      const updated = await client.getLock(state.projectPath)
      setState(prev => ({
        ...prev,
        toolsLock: updated,
        toolsBusy: false
      }))
    } catch (err) {
      setState(prev => ({
        ...prev,
        toolsBusy: false,
        error: String(err?.message || err)
      }))
    }
  }, [ctx, state.projectPath])

  const { report, rules, agentsMd, placeLog, toolsLock, toolsPrompt, toolsBusy, projectPath, error, folderLabel } = state

  return jsx(ScrollArea, {
    style: { height: '100%', width: '100%' },
    children: jsxs('div', {
      'data-testid': 'adopt-inspector-page',
      'data-color-scheme': 'no-red-green',
      style: {
        padding: '24px',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
        maxWidth: '1100px'
      },
      children: [
        jsxs('div', {
          style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', padding: '14px', border: '1px solid var(--ui-stroke-secondary)', borderLeft: '3px solid var(--ui-accent)', borderRadius: '10px', background: 'var(--ui-bg-secondary)' },
          children: [
            jsxs('div', {
              children: [
                jsx('h2', {
                  style: { fontSize: '18px', fontWeight: 600, color: 'var(--ui-text-primary)', margin: 0 },
                  children: 'Project Defuzz — Before / After Inspector'
                }),
                jsx('p', {
                  style: { fontSize: '12px', color: 'var(--ui-text-secondary)', margin: '4px 0 0 0' },
                  children: folderLabel || 'Inspect a copy-only adopted workspace (.adopt/report.json)'
                })
              ]
            }),
            jsxs(Button, {
              onClick: loadFolder,
              children: [
                jsx(Codicon, { name: 'folder-opened' }),
                jsx('span', { style: { marginLeft: '6px' }, children: 'Open Adopted Copy' })
              ]
            })
          ]
        }),
        error
          ? jsx('div', {
              style: {
                padding: '10px 12px',
                border: '1px solid var(--ui-stroke-secondary)',
                borderRadius: '6px',
                fontSize: '12px',
                color: 'var(--ui-accent)'
              },
              children: error
            })
          : null,
        !report
          ? jsx(EmptyState, {
              title: 'No adopted project copy loaded',
              description: 'Click "Open Adopted Copy" and select a copy folder containing .adopt/report.json.'
            })
          : jsxs('div', {
              style: { display: 'flex', flexDirection: 'column', gap: '20px' },
              children: [
                jsxs('div', {
                  style: {
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
                    gap: '12px'
                  },
                  children: [
                    jsx(StatCard, {
                      label: 'Verified Files',
                      value: report.counts?.total_files_verified,
                      detail: 'SHA-256 matched'
                    }),
                    jsx(StatCard, {
                      label: 'Moved',
                      value: report.counts?.moved,
                      detail: 'Organized by folder rules'
                    }),
                    jsx(StatCard, {
                      label: 'Archived',
                      value: (report.counts?.archived || 0) + (report.counts?.runtime_dirs_archived || 0),
                      detail: 'Preserved in _archive/ (0 deleted)'
                    }),
                    jsx(StatCard, {
                      label: 'Secrets Locked',
                      value: report.counts?.secrets_locked_to_ignore,
                      detail: 'git_policy = ignore before commit'
                    }),
                    jsx(StatCard, {
                      label: 'Baseline Commit',
                      value: (report.baseline_commit_sha || 'n/a').slice(0, 10),
                      detail: `${report.agents_md_lines || 0} lines in AGENTS.md`
                    })
                  ]
                }),
                jsxs('div', {
                  style: { display: 'flex', gap: '16px', flexWrap: 'wrap' },
                  children: [
                    jsx(DirTable, {
                      title: 'Before (Top-Level File Distribution)',
                      counts: report.before_dir_counts
                    }),
                    jsx(DirTable, {
                      title: 'After (Adopted Copy Distribution)',
                      counts: report.after_dir_counts
                    })
                  ]
                }),
                jsx(Separator, {}),
                jsx(ManualLintSection, { ctx, project: projectPath }, projectPath),
                jsx(ToolsLockSection, {
                  project: projectPath,
                  toolsLock,
                  onAcceptPrompt: handleAcceptPrompt,
                  onSaveAccept: handleSaveAccept,
                  onEditReasonPrompt: handleEditReasonPrompt,
                  onSaveReason: handleSaveReason,
                  onSnooze30d: handleSnooze30d,
                  onInitLock: handleInitLock,
                  promptState: toolsPrompt,
                  onChangePromptText: text =>
                    setState(prev =>
                      prev.toolsPrompt ? { ...prev, toolsPrompt: { ...prev.toolsPrompt, text } } : prev
                    ),
                  onCancelPrompt: () => setState(prev => ({ ...prev, toolsPrompt: null })),
                  busy: toolsBusy
                }),
                jsx(Separator, {}),
                jsxs('div', {
                  style: { display: 'flex', gap: '16px', flexWrap: 'wrap' },
                  children: [
                    jsxs('div', {
                      style: {
                        border: '1px solid var(--ui-stroke-secondary)',
                        borderRadius: '8px',
                        padding: '12px 14px',
                        flex: 1,
                        minWidth: '300px'
                      },
                      children: [
                        jsx('div', {
                          style: { fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--ui-text-primary)' },
                          children: 'AGENTS.md (Purpose · Layout · Conventions · Build & test)'
                        }),
                        jsx('pre', {
                          style: {
                            fontSize: '11px',
                            fontFamily: 'var(--font-mono)',
                            color: 'var(--ui-text-secondary)',
                            whiteSpace: 'pre-wrap',
                            margin: 0
                          },
                          children: agentsMd || '(empty)'
                        })
                      ]
                    }),
                    jsxs('div', {
                      style: {
                        border: '1px solid var(--ui-stroke-secondary)',
                        borderRadius: '8px',
                        padding: '12px 14px',
                        flex: 1,
                        minWidth: '300px'
                      },
                      children: [
                        jsx('div', {
                          style: { fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--ui-text-primary)' },
                          children: `Active Placement Rules (${(rules?.placement_rules || []).length}) & Recent Placements (${placeLog.length})`
                        }),
                        jsx('div', {
                          style: { display: 'flex', flexDirection: 'column', gap: '6px' },
                          children: (rules?.placement_rules || []).map(r =>
                            jsxs(
                              'div',
                              {
                                style: {
                                  fontSize: '12px',
                                  fontFamily: 'var(--font-mono)',
                                  color: 'var(--ui-text-secondary)'
                                },
                                children: [
                                  jsx('strong', { children: `${r.kind}: ` }),
                                  jsx('span', { children: `${(r.match_ext || []).join(', ')} -> ${r.dest_dir}/` })
                                ]
                              },
                              r.kind
                            )
                          )
                        })
                      ]
                    })
                  ]
                })
              ]
            })
      ]
    })
  })
}

export function createScopedRest(ctx) {
  const scope = () => JSON.stringify([host.activeConnectionId?.() ?? host.state?.connectionId?.get?.() ?? null, host.state?.profile?.get?.() ?? null])
  const owner = scope()
  const check = () => {
    if (scope() !== owner) throw new Error('Connection or profile changed. Reopen the workspace before continuing.')
  }
  const rest = async (path, options) => {
    check()
    const result = await ctx.rest(path, options)
    check()
    return result
  }
  rest.check = check
  return rest
}

function stableUiValue(value) {
  if (Array.isArray(value)) return value.map(stableUiValue)
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableUiValue(value[key])]))
  return value
}

// Live diagnostics and setup/lock actions use scoped requests and reject disposed lifetimes.
export function createLiveModel(ctx, changed = () => {}) {
  const rest = createScopedRest(ctx)
  let state = { busy: false, error: '', project: '', tools: null, setup: null, lock: null, lockFile: null, resourceErrors: {} }
  let disposed = false, lifetime = 0
  const emit = patch => { if (!disposed) { state = { ...state, ...patch }; changed(state) } }
  const current = owner => !disposed && owner === lifetime
  const dispose = () => { disposed = true; lifetime += 1 }
  ctx.onDispose?.(dispose)
  return {
    get: () => state,
    dispose,
    mount: () => { if (disposed) { disposed = false; emit({ busy: false }) } },
    async loadPro(project = '') {
      if (disposed || state.busy) return
      const owner = lifetime
      emit({ busy: true, error: '', project, tools: null, setup: null, lock: null, lockFile: null, resourceErrors: {} })
      const resources = [['tools', '/tools/status'], ['setup', '/setup/status']]
      if (project) resources.push(['lock', `/tools-lock?project=${encodeURIComponent(project)}`], ['lockFile', `/workspace/file?project=${encodeURIComponent(project)}&path=TOOLS.lock`])
      for (const [key, path] of resources) {
        if (!current(owner)) break
        try { const value = await rest(path); if (current(owner)) emit({ [key]: value }) }
        catch (error) { if (current(owner)) emit({ resourceErrors: { ...state.resourceErrors, [key]: formatError(error) } }) }
      }
      if (current(owner)) emit({ busy: false, proLoaded: true })
    },
    async setup(cancel = false) {
      if (disposed || state.busy || (!cancel && (!state.tools?.plan || state.tools?.lazy_installs_allowed !== true))) return
      const owner = lifetime
      emit({ busy: true, error: '' })
      try {
        await rest(cancel ? '/setup/cancel' : '/setup', { method: 'POST', body: cancel ? {} : { confirm: true } })
        if (!current(owner)) return
        const setup = await rest('/setup/status')
        if (current(owner)) emit({ setup })
      } catch (error) { if (current(owner)) emit({ error: formatError(error) }) }
      finally { if (current(owner)) emit({ busy: false }) }
    },
    async trustLock(project) {
      const hash = state.lock?.trust?.tools_lock_hash
      if (disposed || state.busy || !hash || project !== state.project) return
      const owner = lifetime
      emit({ busy: true, error: '' })
      try {
        await rest('/tools-lock/trust', { method: 'POST', body: { project, expected_hash: hash, confirm: true } })
        if (!current(owner)) return
        const lock = await rest(`/tools-lock?project=${encodeURIComponent(project)}`)
        if (current(owner)) emit({ lock })
      } catch (error) { if (current(owner)) emit({ error: formatError(error) }) }
      finally { if (current(owner)) emit({ busy: false }) }
    }
  }
}

// The New Project pick-list as sent by the server (`catalog` of /scaffold/match).
// Anything malformed is dropped; a missing catalog is an empty list, never a local one.
const catalogKey = entry => `${entry.kind}:${entry.id}`
function readCatalog(raw) {
  const src = raw && typeof raw === 'object' ? raw : {}
  const entries = (Array.isArray(src.entries) ? src.entries : [])
    .filter(e => e && typeof e === 'object' && typeof e.kind === 'string' && e.kind && typeof e.id === 'string' && e.id)
    .map(e => ({ kind: e.kind, id: e.id, title: auditSafe(typeof e.title === 'string' && e.title ? e.title : e.id),
      line: typeof e.line === 'string' ? auditSafe(e.line) : '', group: typeof e.group === 'string' ? e.group : '',
      group_title: typeof e.group_title === 'string' ? auditSafe(e.group_title) : '',
      ...(e.coming_soon === true ? { coming_soon: true, selectable: false } : {}) }))
  const suggested = Array.isArray(src.suggested) ? src.suggested.filter(k => typeof k === 'string') : []
  return { entries, suggested, notice: typeof src.notice === 'string' ? src.notice : '' }
}

// Request limits for creating a project. The host's default is 30 s, but the server's accept
// step runs the new project's own check under its own 60 s deadline (scaffolder.accept
// timeout_s=60.0; kit_scaffold.accept_kit and the kit apply in a kit propose use the same 60 s),
// and the Python template's check alone takes about 35 s. 75 s lets the server's own answer
// (success or its timeout) arrive first.
export const SCAFFOLD_ACCEPT_TIMEOUT_MS = 75000
// Template propose only stages files (well under a second when measured).
export const SCAFFOLD_PROPOSE_TIMEOUT_MS = 15000
export const CREATE_PROGRESS_TEXT = 'Creating the project and running its first check. This can take about a minute.'
export const CREATE_STILL_RUNNING_TEXT = 'The project is still being created. It will appear in the project list when it is ready.'
export const CREATE_BUSY_TEXT = 'This project is still being created. Wait a moment, then check the project list.'
export const CREATE_CONSUMED_TEXT = 'That request is no longer available. Choose the project type again.'
export const CREATE_NAME_TAKEN_TEXT = 'A project with this name already exists. Choose another name or open the existing one.'
// A newer server answers a long accept with 202 {status: 'running', ...}; the page then asks
// GET /scaffold/accept/<id> every 1.5 s (each with its own short limit) for at most 15 minutes.
export const SCAFFOLD_POLL_INTERVAL_MS = 1500
export const SCAFFOLD_POLL_TIMEOUT_MS = 10000
export const SCAFFOLD_POLL_LIMIT_MS = 15 * 60 * 1000
// Failed polls in a row before the page says the project is still being created.
const SCAFFOLD_POLL_QUIET_AFTER = 5
// How a polled accept ended without a finished answer: 'cancelled', 'detached' (the dialog
// closed or the page went away), 'too-long' (the overall limit).
const acceptStop = kind => Object.assign(new Error(kind), { acceptStop: kind })
// A finished-with-failure poll as the error a finished POST would have thrown: the same
// "<status>: {detail}" message, with the body only when the detail is not plain text.
const acceptFailure = reply => {
  const status = Number.isInteger(reply.http_status) && reply.http_status >= 400 && reply.http_status <= 599 ? reply.http_status : 500
  const detail = reply.detail ?? 'The project could not be created.'
  const error = new Error(`${status}: ${JSON.stringify({ detail })}`)
  return typeof detail === 'string' ? error : Object.assign(error, { body: { detail } })
}
const cancelTimer = handle => { if (typeof handle === 'function') handle(); else if (handle != null) clearTimeout(handle) }
export const CREATE_CANCELLED_TEXT = 'Creation was cancelled. Nothing was created.'
export const CREATE_TOO_LATE_TEXT = 'It is too late to cancel: the project is being finished.'
export const CREATE_TOO_LONG_TEXT = 'This is taking much longer than expected. Check the project list before you try again.'
export const CREATE_CLOSED_RUNNING_TEXT = 'Closing the window did not stop the project. It is still being created and will appear in the project list when it is ready.'
// Elapsed seconds as plain words. Whole minutes only, so the live region changes at most once a minute.
export const createElapsedText = seconds => {
  const minutes = typeof seconds === 'number' && Number.isFinite(seconds) && seconds >= 60 ? Math.floor(seconds / 60) : 0
  return minutes === 0 ? 'less than a minute' : minutes === 1 ? '1 minute' : `${minutes} minutes`
}
// The progress sentence while a polled job runs: the server's step phrase (escaped) and the
// time so far; after several failed polls in a row, the still-being-created sentence instead.
export const acceptJobText = job => {
  const step = typeof job?.step === 'string' && job.step.trim() ? auditSafe(job.step.trim()) : 'Creating the project'
  const main = job?.fails >= SCAFFOLD_POLL_QUIET_AFTER ? CREATE_STILL_RUNNING_TEXT : `${step} (${createElapsedText(job?.elapsed_s)} so far).`
  return job?.tooLate ? `${main} ${CREATE_TOO_LATE_TEXT}` : main
}
// What a failed create request means. 'no-answer': no HTTP answer at all (timeout, dropped
// connection), so the server may still be creating the project. The other kinds are the
// server's own answers to a retry after a lost answer.
export function scaffoldErrorKind(error) {
  const { status, detail } = parseHttpError(error)
  const raw = error?.body?.detail ?? error?.data?.detail ?? error?.detail
  const text = typeof raw === 'string' ? raw : raw == null ? detail : ''
  if (status == null && error?.body == null && error?.data == null && error?.detail == null &&
    !/Connection or profile changed/.test(formatError(error))) return 'no-answer'
  if (status === 409 && /^Proposal is busy/.test(text)) return 'busy'
  if (status === 404 && /^Unknown or consumed proposal_id/.test(text)) return 'consumed'
  if (status === 400 && /^Destination already exists/.test(text)) return 'name-taken'
  return ''
}

// Shared request model: no requests during render, no ambient timers, no automatic lint.
export function createWorkspaceModel(ctx, changed = () => {}, initialScreen = 'main') {
  const rest = createScopedRest(ctx)
  let state = { busy: false, error: '', screen: initialScreen, projects: [], unavailableProjects: [], selected: '',
    forgetting: '', forgetNotice: '',
    idea: '', name: '', answers: { building: 'service', layout: 'single', languages: [], engine: '' },
    matches: [], matchFailed: false, template: null, options: {},
    catalog: null, selectedKitId: '', kitPreview: null, kitPreviewError: '',
    existingList: { status: 'idle', projects: [], coverage: '', error: '' },
    existingOpenBusy: false, existingOpenError: '', existingOpenNotice: '',
    projectTree: { project: '', status: 'idle', files: [], coverage: '', truncated: false, omitted: 0, error: '' },
    proposal: null, output: null, settings: { rules: [
      { id: 'ruff-format', label: 'Ruff formatting', mode: 'pre', enabled: true },
      { id: 'ruff', label: 'Ruff analysis', mode: 'both', enabled: true },
      { id: 'shellcheck', label: 'ShellCheck', mode: 'post', enabled: true }
    ] }, seq: 0, loaded: false, settingsSaveState: 'not loaded' }
  let settingsTimer = null
  let disposed = false
  let revision = 0
  let lifetime = 0
  let previewToken = 0
  let matchToken = 0
  let kitPreviewToken = 0
  let projectTreeToken = 0
  let existingListToken = 0
  // Project-list reads are serialized: a verified reload after forget must never be swallowed
  // because a Refresh was in flight, and overlapping reads must publish in start order.
  let listToken = 0
  let listTail = Promise.resolve()
  let listInFlight = null
  let listBusy = 0
  let listPendingReads = 0
  let activeProposalId = null
  let acceptJob = null // the accept job being polled after a 202: { pid, finish, ... }
  let mounted = false
  const emit = patch => { state = { ...state, ...patch }; if (!disposed) changed(state) }
  const discardAbandoned = async pid => {
    const ownerLifetime = lifetime
    try {
      await rest('/scaffold/discard', { method: 'POST', body: { proposal_id: pid } })
    } catch (error) {
      if (!disposed && ownerLifetime === lifetime) {
        const details = error?.body?.detail || error?.data?.detail || error?.detail || error?.body || error?.data || formatError(error)
        emit({ proposal: null, error: formatError(error), output: details })
      }
    }
  }
  const dispose = () => {
    // A running accept job is the server's now: stop asking about it, never discard it.
    const job = acceptJob
    if (job) { acceptJob = null; activeProposalId = null; state = { ...state, proposal: null, accepting: false } }
    if (!state.partial && (activeProposalId || state.proposal?.proposal_id)) {
      const pid = activeProposalId || state.proposal.proposal_id
      activeProposalId = null
      state = { ...state, proposal: null }
      rest('/scaffold/discard', { method: 'POST', body: { proposal_id: pid } }).catch(() => {})
    }
    disposed = true; mounted = false; lifetime += 1; previewToken += 1; matchToken += 1; kitPreviewToken += 1; settingsTimer?.(); settingsTimer = null
    job?.finish(acceptStop('detached'))
  }
  ctx.onDispose?.(dispose)
  const request = async (path, body, apply, { onError, ...options } = {}, send = rest) => {
    if (state.busy || disposed) return
    const ownerLifetime = lifetime
    const current = () => !disposed && ownerLifetime === lifetime
    emit({ busy: true, error: '' })
    try {
      const result = await send(path, body === undefined ? { ...options } : { method: 'POST', body, ...options })
      if (current()) apply(result)
      return result
    } catch (error) {
      if (onError && current() && onError(error)) return undefined
      const details = error?.body?.detail || error?.data?.detail || error?.detail || error?.body || error?.data || formatError(error)
      const isPartial = state.partial || (Array.isArray(details?.created_dirs) && details.created_dirs.length > 0)
      if (isPartial) activeProposalId = null
      if (current()) emit({ error: formatError(error), output: details, partial: isPartial })
    } finally { if (current()) emit({ busy: false }) }
  }
  const invalidate = patch => {
    if (state.busy || state.partial) return
    revision += 1
    // After a lost accept answer the server may still be using the proposal: forget it, do not discard it.
    const pid = state.acceptLost ? null : activeProposalId
    activeProposalId = null
    if (patch && Object.hasOwn(patch, 'idea') && patch.idea !== state.idea) matchToken += 1
    const answersChanged = patch && Object.hasOwn(patch, 'answers') && JSON.stringify(patch.answers) !== JSON.stringify(state.answers)
    emit({ ...patch, proposal: null, template: null, options: {}, output: null, error: '', acceptLost: '', acceptNote: '', ...(answersChanged ? { matches: [], matchFailed: false } : {}) })
    if (pid) return discardAbandoned(pid)
  }
  const cleanKitAnswers = raw => {
    const src = raw && typeof raw === 'object' ? raw : {}
    const out = { building: src.building || 'other' }
    for (const [k, v] of Object.entries(src)) {
      if (k !== 'layout' && k !== 'languages' && (k !== 'engine' || Boolean(v))) {
        out[k] = v
      }
    }
    return out
  }
  const clearKit = () => {
    if (state.busy || state.partial) return
    kitPreviewToken += 1
    const pid = activeProposalId
    activeProposalId = null
    emit({ selectedKitId: '', kitPreview: null, kitPreviewError: '', proposal: null, output: null, error: '' })
    if (pid) return discardAbandoned(pid)
  }
  const selectKit = kitId => {
    if (state.busy || state.partial || disposed) return undefined
    const cleanId = typeof kitId === 'string' ? kitId.trim() : ''
    if (!cleanId) return clearKit()
    if (state.catalog?.entries.some(e => e.kind === 'kit' && e.id === cleanId && e.coming_soon)) return undefined
    const ownerLifetime = lifetime
    const token = ++kitPreviewToken
    const pid = activeProposalId
    activeProposalId = null
    emit({ selectedKitId: cleanId, kitPreview: null, kitPreviewError: '', answers: cleanKitAnswers(state.answers), template: null, options: {}, proposal: null, output: null, error: '' })
    const discardPromise = pid ? discardAbandoned(pid) : undefined
    return (async () => {
      if (discardPromise) await discardPromise
      try {
        const result = await rest(`/scaffold/kits/${encodeURIComponent(cleanId)}`)
        if (!disposed && ownerLifetime === lifetime && token === kitPreviewToken && state.selectedKitId === cleanId) {
          if (result && (result.error || result.ok === false || (typeof result.status === 'number' && result.status >= 400) || (!result.kit && !Array.isArray(result.tree) && result.detail))) {
            const rawMsg = result.detail || result.error || result.notice || 'Could not show the folders for this workspace.'
            const oneLine = String(rawMsg).split(/\r?\n/)[0].trim() || 'Could not show the folders for this workspace.'
            emit({ kitPreview: null, kitPreviewError: oneLine })
          } else {
            emit({ kitPreview: result || null, kitPreviewError: '' })
          }
        }
        return result
      } catch (error) {
        if (!disposed && ownerLifetime === lifetime && token === kitPreviewToken && state.selectedKitId === cleanId) {
          const rawMsg = error?.body?.detail || error?.data?.detail || error?.detail || error?.body?.error || formatError(error) || 'Could not show the folders for this workspace.'
          const oneLine = String(typeof rawMsg === 'string' ? rawMsg : formatError(error)).split(/\r?\n/)[0].trim() || 'Could not show the folders for this workspace.'
          emit({ kitPreview: null, kitPreviewError: oneLine })
        }
      }
    })()
  }
  const saveSettings = async () => {
    settingsTimer?.(); settingsTimer = null
    if (disposed || !state.loaded) return
    if (state.busy) { scheduleSettings(); return }
    const owner = lifetime, seq = state.seq + 1, value = state.settings
    emit({ busy: true, settingsSaveState: 'saving', error: '' })
    try {
      const result = await rest('/ui-state', { method: 'POST', body: { key: 'settings', value, seq } })
      if (disposed || owner !== lifetime) return
      if (result.seq !== seq || (result.value && JSON.stringify(stableUiValue(result.value)) !== JSON.stringify(stableUiValue(value)))) throw new Error('Settings changed elsewhere. Load saved settings before saving again.')
      const readback = await rest('/ui-state?key=settings')
      if (disposed || owner !== lifetime) return
      if (readback?.seq !== seq || JSON.stringify(stableUiValue(readback.value)) !== JSON.stringify(stableUiValue(value))) throw new Error('Settings readback did not match. Load saved settings before saving again.')
      emit({ seq, settingsSaveState: 'saved' })
    } catch (error) { if (!disposed && owner === lifetime) emit({ error: formatError(error), settingsSaveState: 'error' }) }
    finally { if (!disposed && owner === lifetime) emit({ busy: false }) }
  }
  // The accept request (Create's second step). An old server answers when it is finished; a
  // newer one may answer 202 {status: 'running'} and the page then polls until a final answer,
  // which goes through exactly the same success and failure handling as a finished POST.
  const requestVia = send => (path, body, apply, options) => request(path, body, apply, options, send)
  const startAndPoll = async (path, options) => {
    const ownerLifetime = lifetime
    const first = await rest(path, options)
    if (first?.status !== 'running' || disposed || ownerLifetime !== lifetime) return first
    return pollAccept(options.body.proposal_id, first)
  }
  const acceptRequest = onError => requestVia(startAndPoll)('/scaffold/accept', { proposal_id: state.proposal.proposal_id, confirm: true }, output => {
    const accepted = output.ok !== false && (output.ok === true || output.state === 'accepted' || output.status === 'created')
    const partial = !accepted && Array.isArray(output.created_dirs) && output.created_dirs.length > 0
    if (partial) activeProposalId = null
    emit({ output, partial: state.partial || partial })
    if (accepted) {
      activeProposalId = null
      emit({ proposal: null, template: null, options: {}, selectedKitId: '', kitPreview: null, kitPreviewError: '' })
    } else if (!partial) {
      emit({ error: output.error || output.check?.stderr || output.check?.stdout || 'The project could not be created.' })
    }
  }, { timeoutMs: SCAFFOLD_ACCEPT_TIMEOUT_MS, onError })
  // Polls GET /scaffold/accept/<id> until a final answer. Resolves with the finished body;
  // rejects with the failure as a POST would have thrown it, or with an acceptStop marker.
  // A dropped, timed-out or odd poll means "still working": polling goes on.
  const pollAccept = (pid, first) => new Promise((resolve, reject) => {
    const schedule = typeof ctx.setTimeout === 'function' ? ctx.setTimeout : setTimeout
    const pollPath = `/scaffold/accept/${encodeURIComponent(pid)}`
    const job = { pid, timer: null, deadline: null, fails: 0, done: false }
    const show = patch => { if (!job.done) emit({ acceptJob: { ...state.acceptJob, ...patch } }) }
    job.show = show
    job.finish = (value, ok = false) => {
      if (job.done) return
      job.done = true
      cancelTimer(job.timer); cancelTimer(job.deadline); job.timer = job.deadline = null
      if (acceptJob === job) acceptJob = null
      emit({ acceptJob: null })
      if (ok) resolve(value); else reject(value)
    }
    const step = reply => ({ step: reply.step, elapsed_s: reply.elapsed_s })
    const handle = reply => {
      const status = reply && typeof reply === 'object' ? reply.status : undefined
      if (status === 'running') { job.fails = 0; show({ ...step(reply), fails: 0 }); return true }
      if (status === 'done') { job.finish(reply.result && typeof reply.result === 'object' ? reply.result : {}, true); return true }
      if (status === 'failed') {
        if (reply.partial === true) emit({ partial: true })
        job.finish(acceptFailure(reply)); return true
      }
      if (status === 'cancelled') { job.finish(acceptStop('cancelled')); return true }
      return false
    }
    const tick = async () => {
      job.timer = null
      if (job.done) return
      let reply
      try { reply = await rest(pollPath, { timeoutMs: SCAFFOLD_POLL_TIMEOUT_MS }) } catch (error) {
        // The server no longer knows the proposal: the same as a consumed POST.
        if (!job.done && scaffoldErrorKind(error) === 'consumed') job.finish(error)
        reply = null
      }
      if (job.done) return
      if (!handle(reply)) { job.fails += 1; show({ fails: job.fails }) }
      if (!job.done) job.timer = schedule(tick, SCAFFOLD_POLL_INTERVAL_MS)
    }
    acceptJob = job
    emit({ acceptJob: { ...step(first), fails: 0, cancelling: false, tooLate: false } })
    job.deadline = schedule(() => job.finish(acceptStop('too-long')), SCAFFOLD_POLL_LIMIT_MS)
    job.timer = schedule(tick, SCAFFOLD_POLL_INTERVAL_MS)
  })
  const scheduleSettings = () => {
    settingsTimer?.()
    if (state.loaded && typeof ctx.setTimeout === 'function') settingsTimer = ctx.setTimeout(saveSettings, 300)
  }
  const applyNormalizedLists = (normalized, result, { preservePreview = false } = {}) => {
    if (!preservePreview) previewToken += 1
    const stillSelected = normalized.projects.some(p => p.path === state.selected && p.registered === true)
    emit({
      projects: normalized.projects,
      unavailableProjects: normalized.unavailableProjects,
      projectsLoaded: true,
      coverage: result?.coverage || 'could_not_verify',
      selected: stillSelected ? state.selected : '',
      ...(stillSelected && preservePreview ? {} : { preview: null, previewPath: '' })
    })
    return normalized
  }
  // Reads are serialized and de-duplicated. `force` is for the verified reload after a registry
  // mutation: it waits for any Refresh already in flight and then performs its own read, so a
  // concurrent Refresh can never make the confirmation read be skipped. The newest read wins
  // for the visible list; every read also returns its own normalized payload so a caller can
  // verify the mutation against the read it actually made, even if a later read supersedes it.
  const fetchProjects = ({ force = false, preservePreview = false } = {}) => {
    if (disposed) return Promise.resolve(undefined)
    const ownerLifetime = lifetime
    if (!force && listInFlight) return Promise.resolve(undefined)
    const token = ++listToken
    listBusy += 1
    emit({ busy: true, error: '' })
    const execute = async () => {
      if (disposed || ownerLifetime !== lifetime) return undefined
      try {
        const result = await rest('/workspace/projects')
        if (disposed || ownerLifetime !== lifetime) return undefined
        const normalized = normalizeProjectLists(result && typeof result === 'object' ? result : {})
        if (token === listToken) applyNormalizedLists(normalized, result, { preservePreview })
        return {
          projects: normalized.projects,
          unavailableProjects: normalized.unavailableProjects,
          coverage: result?.coverage || 'could_not_verify'
        }
      } catch (error) {
        if (!disposed && ownerLifetime === lifetime && token === listToken) {
          emit({ error: formatError(error) })
        }
        return undefined
      }
    }
    const idle = listPendingReads === 0
    listPendingReads += 1
    const job = idle ? execute() : listTail.then(execute)
    let settled
    settled = job.finally(() => {
      listBusy -= 1
      listPendingReads -= 1
      if (listBusy === 0 && !disposed && ownerLifetime === lifetime) emit({ busy: false })
      if (listInFlight === settled) listInFlight = null
    })
    listTail = settled.then(() => undefined, () => undefined)
    if (!force) listInFlight = settled
    return settled
  }
  const loadProjects = () => fetchProjects()
  const exactRegistration = value => typeof value === 'string' && value ? value : ''
  // Forget removes one exact registry record only. It never touches the folder, so the
  // confirmation says so and success is claimed only after a fresh verified list proves that
  // this exact registration is gone.
  const forget = async registrationPath => {
    const exactPath = exactRegistration(registrationPath)
    if (!exactPath || state.forgetting || disposed) return undefined
    const ownerLifetime = lifetime
    const current = () => !disposed && ownerLifetime === lifetime
    emit({ forgetting: exactPath, error: '', forgetNotice: '' })
    try {
      const result = await rest('/workspace/projects/forget', { method: 'POST', body: { path: exactPath } })
      if (!current()) return undefined
      const rejected = Boolean(result && (result.ok === false || result.status === 'error' || result.error))
      const rejectedMessage = rejected
        ? String(result.error || result.detail || 'The registry did not remove this project.')
        : ''
      const verified = await fetchProjects({ force: true, preservePreview: true })
      if (!current()) return result
      if (rejected) {
        emit({ error: rejectedMessage })
        return result
      }
      if (!verified) {
        emit({ forgetNotice: 'Could not verify removal: the project list could not be reloaded. Nothing was removed and nothing is claimed; Refresh projects to check.' })
        return result
      }
      if (verified.coverage !== 'verified') {
        emit({ forgetNotice: `Could not verify removal: registry coverage is ${verified.coverage || 'unknown'}. Nothing is claimed as removed; Refresh projects to check.` })
        return result
      }
      if (result && result.removed === false) {
        emit({ forgetNotice: 'The registry reported no matching registration; nothing was removed. Refresh projects to check.' })
        return result
      }
      // Verify against the exact read this call made, not mutable state a newer read may own.
      const verifiedPaths = new Set([...verified.projects, ...verified.unavailableProjects]
        .map(record => record.registrationPath)
        .filter(Boolean))
      if (verifiedPaths.has(exactPath)) {
        emit({ forgetNotice: 'The registry still lists this registration; nothing was removed. Refresh projects to confirm.' })
        return result
      }
      emit({ forgetNotice: 'Removed from Defuzz only; files untouched.' })
      return result
    } catch (error) {
      if (current()) emit({ error: formatError(error) })
      return undefined
    } finally {
      if (current()) emit({ forgetting: '' })
    }
  }
  const forgetMissing = async () => {
    if (state.forgetting || disposed) return undefined
    const targets = (state.unavailableProjects || [])
      .filter(p => p.folder_status === 'missing' && p.registrationPath)
      .map(p => p.registrationPath)
    if (!targets.length) return undefined
    const ownerLifetime = lifetime
    const current = () => !disposed && ownerLifetime === lifetime
    const errors = []
    emit({ forgetting: targets[0], error: '', forgetNotice: '' })
    for (const path of targets) {
      if (!current()) return undefined
      emit({ forgetting: path })
      try {
        const result = await rest('/workspace/projects/forget', { method: 'POST', body: { path } })
        if (!current()) return undefined
        if (result && (result.ok === false || result.status === 'error' || result.error)) {
          errors.push(String(result.error || result.detail || `Could not forget ${path}`))
        } else if (result && result.removed === false) {
          errors.push(`Registry reported no removal for ${path}`)
        }
      } catch (error) {
        errors.push(formatError(error))
      }
    }
    if (!current()) return undefined
    const verified = await fetchProjects({ force: true, preservePreview: true })
    if (!current()) return undefined
    if (errors.length) emit({ error: errors.join('; ') })
    if (!verified) {
      emit({ forgetting: '', forgetNotice: `Could not verify removal of ${targets.length} missing project${targets.length === 1 ? '' : 's'}; nothing is claimed as removed. Refresh projects to check.` })
      return { status: 'unverified', removed: 0, failed: targets.length, errors }
    }
    const present = new Set([...verified.projects, ...verified.unavailableProjects]
      .map(record => record.registrationPath)
      .filter(Boolean))
    const confirmed = targets.filter(path => !present.has(path))
    const unconfirmed = targets.filter(path => present.has(path))
    if (verified.coverage !== 'verified') {
      emit({ forgetting: '', forgetNotice: `Could not verify removal: registry coverage is ${verified.coverage || 'unknown'}. Nothing is claimed as removed.` })
      return { status: 'unverified', removed: 0, failed: targets.length, errors }
    }
    const parts = [confirmed.length
      ? `${confirmed.length} missing project${confirmed.length === 1 ? '' : 's'} removed from Defuzz only; files untouched.`
      : 'No missing projects were confirmed removed; files untouched.']
    if (unconfirmed.length) parts.push(`${unconfirmed.length} still listed or unverified: ${unconfirmed.join(', ')}.`)
    emit({ forgetting: '', forgetNotice: parts.join(' ') })
    return {
      status: unconfirmed.length || errors.length ? 'partial' : 'forgotten',
      removed: confirmed.length,
      failed: unconfirmed.length + errors.length,
      errors
    }
  }
  const isExistingTemplate = project => project?.template_id === 'existing'
  // Reads the bounded, read-only file list for one already-selected existing registration.
  // A reply is published only if the same selection is still current; a profile/lifetime
  // change or a different selection discards it. An error is shown as an error, never
  // replaced with invented rows.
  const loadProjectTree = async projectPath => {
    const cleanPath = typeof projectPath === 'string' ? projectPath : ''
    if (disposed || !cleanPath) return undefined
    const ownerLifetime = lifetime
    const token = ++projectTreeToken
    const isCurrent = () => !disposed && ownerLifetime === lifetime && token === projectTreeToken && state.selected === cleanPath
    emit({ projectTree: { project: cleanPath, status: 'loading', files: [], coverage: '', truncated: false, omitted: 0, error: '' } })
    try {
      const result = await rest(`/workspace/tree?project=${encodeURIComponent(cleanPath)}`)
      if (!isCurrent()) return undefined
      const files = Array.isArray(result?.files) ? result.files.filter(entry => typeof entry === 'string' && entry.trim()) : null
      if (!files) {
        emit({ projectTree: { project: cleanPath, status: 'error', files: [], coverage: '', truncated: false, omitted: 0, error: 'The file list response could not be read.' } })
        return result
      }
      const omitted = Number.isFinite(result?.omitted) && result.omitted > 0 ? Math.floor(result.omitted) : 0
      emit({ projectTree: {
        project: cleanPath,
        status: 'ready',
        files,
        coverage: typeof result?.coverage === 'string' ? result.coverage : '',
        truncated: result?.truncated === true,
        omitted,
        error: ''
      } })
      return result
    } catch (error) {
      if (isCurrent()) {
        const details = error?.body?.detail || error?.data?.detail || formatError(error)
        emit({ projectTree: { project: cleanPath, status: 'error', files: [], coverage: '', truncated: false, omitted: 0, error: String(details) } })
      }
      return undefined
    }
  }
  // Selection is local and explicit: only a verified registered project can be selected, and
  // only an existing (adopted-by-reference) project asks the backend for its real file list.
  const selectProject = selected => {
    if (state.busy || disposed || !state.projects.some(project => project.path === selected && project.registered === true)) return false
    previewToken += 1
    projectTreeToken += 1
    const project = state.projects.find(entry => entry.path === selected) || null
    const existing = isExistingTemplate(project)
    emit({
      selected,
      preview: null,
      previewPath: '',
      projectTree: existing
        ? { project: selected, status: 'loading', files: [], coverage: '', truncated: false, omitted: 0, error: '' }
        : { project: '', status: 'idle', files: [], coverage: '', truncated: false, omitted: 0, error: '' }
    })
    if (existing) loadProjectTree(selected)
    return true
  }
  // The existing-project list is read only when the person explicitly opens the dialog.
  // There is no mount-time scan and no background refresh.
  const listExistingProjects = async () => {
    if (disposed) return undefined
    const ownerLifetime = lifetime
    const token = ++existingListToken
    const current = () => !disposed && ownerLifetime === lifetime && token === existingListToken
    emit({ existingList: { status: 'loading', projects: [], coverage: '', error: '' } })
    try {
      const result = await rest('/workspace/available-projects')
      if (!current()) return undefined
      const coverage = result?.coverage === 'verified' ? 'verified' : 'could_not_verify'
      if (coverage !== 'verified') {
        emit({ existingList: { status: 'error', projects: [], coverage, error: String(result?.error || 'Hermes projects could not be verified.') } })
        return result
      }
      const projects = (Array.isArray(result?.projects) ? result.projects : []).map(project => {
        const path = typeof project?.primary_path === 'string' && project.primary_path
          ? project.primary_path
          : typeof project?.path === 'string' ? project.path : ''
        const name = typeof project?.name === 'string' && project.name.trim() ? project.name : path
        return {
          id: typeof project?.id === 'string' ? project.id : '',
          name,
          path,
          folders: Array.isArray(project?.folders) ? project.folders : []
        }
      }).filter(project => project.path)
      emit({ existingList: { status: 'ready', projects, coverage, error: '' } })
      return result
    } catch (error) {
      if (current()) {
        const details = error?.body?.detail || error?.data?.detail || formatError(error)
        emit({ existingList: { status: 'error', projects: [], coverage: 'could_not_verify', error: String(details) } })
      }
      return undefined
    }
  }
  // Registers a reference to an existing folder. Success is claimed only after a forced,
  // verified project-list read shows the canonical folder; otherwise nothing is selected.
  const openExistingProject = async ({ path, hermes_project_id } = {}) => {
    if (disposed || state.existingOpenBusy) return { ok: false }
    const cleanPath = typeof path === 'string' ? path.trim() : ''
    const projectId = typeof hermes_project_id === 'string' && hermes_project_id.trim() ? hermes_project_id.trim() : ''
    if (!cleanPath) {
      emit({ existingOpenError: 'Choose a project or type the full folder path on the backend machine.' })
      return { ok: false }
    }
    const ownerLifetime = lifetime
    const current = () => !disposed && ownerLifetime === lifetime
    emit({ existingOpenBusy: true, existingOpenError: '', existingOpenNotice: '' })
    try {
      const body = projectId ? { path: cleanPath, hermes_project_id: projectId } : { path: cleanPath }
      const result = await rest('/workspace/projects/open', { method: 'POST', body })
      if (!current()) return { ok: false }
      const openedPath = typeof result?.project?.path === 'string' && result.project.path ? result.project.path : ''
      if (result?.status !== 'opened' || !openedPath) {
        emit({ existingOpenBusy: false, existingOpenError: 'The backend did not confirm that the folder was opened. Nothing was selected.' })
        return { ok: false }
      }
      const verified = await fetchProjects({ force: true, preservePreview: true })
      if (!current()) return { ok: false }
      if (!verified) {
        emit({ existingOpenBusy: false, existingOpenError: 'The reference could not be verified because the project list could not be reloaded. Nothing was selected; Refresh projects to check.' })
        return { ok: false }
      }
      if (verified.coverage !== 'verified') {
        emit({ existingOpenBusy: false, existingOpenError: `The reference could not be verified: registry coverage is ${verified.coverage || 'unknown'}. Nothing was selected.` })
        return { ok: false }
      }
      const record = verified.projects.find(project => project.path === openedPath && project.registered === true)
      if (!record) {
        emit({ existingOpenBusy: false, existingOpenError: 'The backend reported the project opened, but the verified active-profile list does not show it. Nothing was selected; Refresh projects to check.' })
        return { ok: false }
      }
      emit({ existingOpenBusy: false, existingOpenNotice: `Opened ${record.name || openedPath} as a reference. No files were copied, changed, or trusted.` })
      selectProject(record.path)
      return { ok: true, path: record.path }
    } catch (error) {
      if (!current()) return { ok: false }
      const details = error?.body?.detail || error?.data?.detail || formatError(error)
      emit({ existingOpenBusy: false, existingOpenError: String(details) })
      return { ok: false }
    }
  }
  return {
    dispose,
    mount: () => { mounted = true; if (disposed) { disposed = false; emit({ busy: false }) } },
    isMounted: () => mounted,
    get: () => state,
    edit: patch => invalidate(patch),
    screen: screen => emit({ screen }),
    select: selectProject,
    loadTree: () => loadProjectTree(state.selected),
    listExistingProjects,
    openExistingProject,
    preview: path => {
      const cleanPath = typeof path === 'string' ? path.trim() : ''
      if (state.busy || disposed || !state.selected || !cleanPath) return undefined
      const ownerLifetime = lifetime
      const targetProject = state.selected
      const token = ++previewToken
      emit({ preview: null, previewPath: cleanPath, error: '' })
      return (async () => {
        try {
          const result = await rest(`/workspace/file?project=${encodeURIComponent(targetProject)}&path=${encodeURIComponent(cleanPath)}`)
          if (!disposed && ownerLifetime === lifetime && token === previewToken && state.selected === targetProject) {
            const normalized = result && typeof result === 'object' ? { ...result, path: result.path || cleanPath } : { content: String(result ?? ''), path: cleanPath }
            emit({ preview: normalized, previewPath: normalized.path })
          }
          return result
        } catch (error) {
          if (!disposed && ownerLifetime === lifetime && token === previewToken) {
            emit({ error: formatError(error), preview: null })
          }
        }
      })()
    },
    load: loadProjects,
    forget,
    forgetMissing,
    // Loads the pick-list. The request carries only the typed idea, so the "(suggested)"
    // marks never depend on the chosen row. `heldAnswers` are the answers the page keeps
    // for Create (they are stored, never sent here).
    match: async heldAnswers => {
      if (disposed) return
      const ownerLifetime = lifetime
      const token = ++matchToken
      const current = () => !disposed && ownerLifetime === lifetime && token === matchToken
      const answers = heldAnswers && typeof heldAnswers === 'object' ? heldAnswers : state.answers
      emit({ error: '', answers })
      try {
        const body = { prompt: state.idea, answers: {} }
        const result = await rest('/scaffold/match', { method: 'POST', body })
        if (!current()) return
        if (result && (result.error || result.ok === false)) {
          const msg = String(result.error || 'The list of project types could not be loaded.')
          const discardPromise = state.selectedKitId ? clearKit() : undefined
          emit({ matches: [], catalog: null, matchFailed: true, error: msg })
          if (discardPromise) await discardPromise
          return result
        }
        const catalog = readCatalog(result?.catalog)
        const list = result ? [...(Array.isArray(result.matches) ? result.matches : []), ...(Array.isArray(result.closest) ? result.closest : [])] : []
        const selectedStillListed = catalog.entries.some(e => e.kind === 'kit' && e.id === state.selectedKitId && !e.coming_soon)
        const discardPromise = state.selectedKitId && !selectedStillListed ? clearKit() : undefined
        emit({ matches: list, catalog, matchFailed: false })
        if (discardPromise) await discardPromise
        return result
      } catch (error) {
        const msg = formatError(error)
        if (current()) {
          const discardPromise = state.selectedKitId ? clearKit() : undefined
          emit({ matches: [], catalog: null, matchFailed: true, error: msg })
          if (discardPromise) await discardPromise
        }
      }
    },
    selectKit,
    clearKit,
    cleanKitAnswers,
    // The chosen template's options (with the defaults remembered from earlier projects).
    // A separate request: empty idea, the template's answers. Its reply is never used for
    // the list or its marks, and it changes no model state.
    templateOptions: async (templateId, answers) => {
      if (disposed || !templateId) return null
      const ownerLifetime = lifetime
      try {
        const result = await rest('/scaffold/match', { method: 'POST', body: { prompt: '', answers: answers && typeof answers === 'object' ? answers : {} } })
        if (disposed || ownerLifetime !== lifetime || !result || result.error || result.ok === false) return null
        const found = [...(Array.isArray(result.matches) ? result.matches : []), ...(Array.isArray(result.closest) ? result.closest : [])]
          .find(m => m && (m.template_id || m.id) === templateId)
        return found?.options && typeof found.options === 'object' ? found.options : null
      } catch { return null }
    },
    choose: template => {
      if (state.busy || state.partial) return
      matchToken += 1
      kitPreviewToken += 1
      const pid = activeProposalId
      activeProposalId = null
      const declared = template?.options && typeof template.options === 'object' ? template.options : {}
      const defaults = {}
      for (const [key, spec] of Object.entries(declared)) {
        if (spec && typeof spec === 'object' && typeof spec.default === 'string') {
          defaults[key] = spec.default
        } else if (Array.isArray(spec?.choices) && typeof spec.choices[0] === 'string') {
          defaults[key] = spec.choices[0]
        }
      }
      emit({ template, options: defaults, selectedKitId: '', kitPreview: null, kitPreviewError: '', proposal: null, output: null, error: '' })
      if (pid) return discardAbandoned(pid)
    },
    option: (key, value) => {
      if (state.busy || state.partial) return
      const declared = state.template?.options && typeof state.template.options === 'object' ? state.template.options : {}
      if (!Object.hasOwn(declared, key)) return
      const choices = Array.isArray(declared[key]?.choices) ? declared[key].choices : null
      if (choices && !choices.includes(value)) return
      const pid = activeProposalId
      activeProposalId = null
      emit({ options: { ...state.options, [key]: value }, proposal: null, output: null, error: '' })
      if (pid) return discardAbandoned(pid)
    },
    propose: () => {
      if (state.selectedKitId) {
        if (!state.name.trim() || state.proposal || state.partial || state.busy || disposed) return
        const kitAnswers = cleanKitAnswers(state.answers)
        const ownerLifetime = lifetime
        const current = () => !disposed && ownerLifetime === lifetime
        emit({ busy: true, error: '' })
        return (async () => {
          try {
            // A kit propose runs the kit's apply step (bounded at 60 s by the bridge), so it gets the long limit.
            const proposal = await rest('/scaffold/propose', { method: 'POST', body: { kit_id: state.selectedKitId, name: state.name, answers: kitAnswers }, timeoutMs: SCAFFOLD_ACCEPT_TIMEOUT_MS })
            if (current()) {
              activeProposalId = proposal?.proposal_id || null
              emit({ proposal, output: null, partial: false })
            }
            return proposal
          } catch (error) {
            const { status, detail } = parseHttpError(error)
            const details = detail || error?.body || error?.data || formatError(error)
            const isPartial = state.partial || (Array.isArray(details?.created_dirs) && details.created_dirs.length > 0)
            if (isPartial) activeProposalId = null
            if (scaffoldErrorKind(error) === 'name-taken') {
              if (current()) emit({ error: CREATE_NAME_TAKEN_TEXT, output: null })
              return undefined
            }
            const msg = status === 503
              ? (detail
                  ? (detail.startsWith('Project kits are unavailable') ? detail : `Project kits are unavailable: ${detail}`)
                  : 'Project kits are unavailable')
              : formatError(error)
            if (current()) emit({ error: msg, output: details, partial: isPartial })
          } finally { if (current()) emit({ busy: false }) }
        })()
      }
      if (!state.template || !state.name.trim() || state.proposal || state.partial) return
      const declared = state.template?.options && typeof state.template.options === 'object' ? state.template.options : {}
      const validOptions = {}
      for (const [key, spec] of Object.entries(declared)) {
        const candidate = state.options?.[key] ?? spec?.default
        const choices = Array.isArray(spec?.choices) ? spec.choices : null
        if (typeof candidate === 'string' && (!choices || choices.includes(candidate))) {
          validOptions[key] = candidate
        }
      }
      return request('/scaffold/propose', { template_id: state.template.template_id || state.template.id,
        name: state.name, answers: state.answers, options: validOptions, remember_options: true },
      proposal => {
        activeProposalId = proposal?.proposal_id || null
        emit({ proposal, output: null, partial: false })
      }, {
        timeoutMs: SCAFFOLD_PROPOSE_TIMEOUT_MS,
        onError: error => {
          if (scaffoldErrorKind(error) !== 'name-taken') return false
          emit({ error: CREATE_NAME_TAKEN_TEXT, output: null })
          return true
        }
      })
    },
    accept: async () => {
      if (!state.proposal?.proposal_id || state.partial || state.busy || disposed) return
      // `acceptLost` records an accept whose outcome is unknown ('no-answer') or whose proposal
      // the server no longer has ('consumed'); the page then checks the project list.
      const onError = error => {
        const stop = error?.acceptStop
        if (stop === 'cancelled') emit({ error: '', output: null, acceptNote: CREATE_CANCELLED_TEXT, acceptEnd: stop })
        else if (stop === 'detached') { activeProposalId = null; emit({ error: '', output: null, proposal: null, acceptEnd: stop }) }
        else if (stop === 'too-long') emit({ error: '', output: null, acceptLost: stop, acceptEnd: stop })
        if (stop) return true
        const kind = scaffoldErrorKind(error)
        if (kind === 'no-answer' || kind === 'consumed') emit({ error: '', output: null, acceptLost: kind })
        else if (kind === 'busy') emit({ error: CREATE_BUSY_TEXT, output: null })
        return kind === 'no-answer' || kind === 'consumed' || kind === 'busy'
      }
      emit({ accepting: true, acceptLost: '', acceptNote: '', acceptEnd: '' })
      try {
        return await acceptRequest(onError)
      } finally { if (!disposed) emit({ accepting: false }) }
    },
    // Cancel while a polled job runs: the server stops it before the project is moved into
    // place, or answers that it is too late (polling goes on either way until a final state).
    cancelAccept: async () => {
      const job = acceptJob
      if (!job || job.done || state.acceptJob?.cancelling || state.acceptJob?.tooLate) return undefined
      job.show({ cancelling: true })
      try {
        const reply = await rest('/scaffold/cancel', { method: 'POST', body: { proposal_id: job.pid }, timeoutMs: SCAFFOLD_POLL_TIMEOUT_MS })
        if (reply?.status === 'cancelled') job.finish(acceptStop('cancelled'))
        else job.show({ cancelling: false, tooLate: reply?.cancel === 'too_late' })
        return reply
      } catch { job.show({ cancelling: false }) }
    },
    // The dialog closed while a polled job runs: stop polling and forget the proposal (the
    // server finishes the job; nothing is cancelled or discarded). False when no job runs.
    detachAccept: () => {
      if (!acceptJob) return false
      acceptJob.finish(acceptStop('detached'))
      return true
    },
    // Ends a lost accept: the project turned up in the list (created) or cannot (error text).
    settleLostAccept: ({ created = false, error = '' } = {}) => {
      activeProposalId = null
      emit({ acceptLost: '', proposal: null, error, output: null,
        ...(created ? { template: null, options: {}, selectedKitId: '', kitPreview: null, kitPreviewError: '' } : {}) })
    },
    discard: async () => {
      if (state.partial || state.busy || disposed) return
      const pid = activeProposalId || state.proposal?.proposal_id
      if (!pid) return
      activeProposalId = null
      const ownerLifetime = lifetime
      const current = () => !disposed && ownerLifetime === lifetime
      emit({ busy: true, error: '', proposal: null })
      try {
        const output = await rest('/scaffold/discard', { method: 'POST', body: { proposal_id: pid } })
        if (current()) emit({ proposal: null, output })
        return output
      } catch (error) {
        const details = error?.body?.detail || error?.data?.detail || error?.detail || error?.body || error?.data || formatError(error)
        if (current()) emit({ proposal: null, error: formatError(error), output: details })
      } finally {
        if (current()) emit({ busy: false })
      }
    },
    loadSettings: () => {
      settingsTimer?.(); settingsTimer = null
      return request('/ui-state?key=settings', undefined,
        result => emit({ settings: result.value || state.settings, seq: result.seq || 0, loaded: true, settingsSaveState: 'saved' }))
    },
    settings: settings => {
      if (!state.busy && !disposed) { emit({ settings, settingsSaveState: state.loaded ? 'pending' : 'not loaded' }); scheduleSettings() }
    },
    saveSettings
  }
}

const panelStyle = { padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px', minWidth: 0 }
const outputView = value => jsx('pre', { style: { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }, children: typeof value === 'string' ? value : JSON.stringify(value, null, 2) })
// Read-only audit view, built from the /audit/summary `summary` object (its sections, in the
// backend's order) plus the /audit/report findings of checks that summary does not cover.
// No section names live here: an unknown section gets the same generic layout. Every value
// from the server is passed as a text child (never HTML).
const AUDIT_ROWS_PER_LIST = 15 // same cap as audit_summary.WARNINGS_PER_SECTION; the rest is a count
const AUDIT_CLASS_LABELS = { warning: 'Warning', review_suggested: 'Review suggested', info: 'For information' }
const AUDIT_CLASS_ORDER = Object.keys(AUDIT_CLASS_LABELS)
const AUDIT_NO_SENTENCE = 'No fixed sentence was stored for this item.'
// Same characters and escapes as audit_summary.safe_text: C0 controls, DEL, C1 controls, bidi
// embeddings/overrides/isolates and U+2028/U+2029 become `\x1b` / `\u202e`; newline, carriage
// return and tab become a space in sentences and an escape in paths. Idempotent.
const AUDIT_UNSAFE_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u2028\u2029]/g
const AUDIT_BREAK_RE = /[\n\r\t]/g
const auditEscape = ch => {
  const code = ch.charCodeAt(0)
  return code <= 0xff ? `\\x${code.toString(16).padStart(2, '0')}` : `\\u${code.toString(16).padStart(4, '0')}`
}
export const auditSafe = (value, path = false) => {
  if (value == null) return ''
  const text = (typeof value === 'string' ? value : String(value)).replace(AUDIT_UNSAFE_RE, auditEscape)
  return text.replace(AUDIT_BREAK_RE, path ? auditEscape : ' ')
}
// For JSON blocks: JSON.stringify already escapes line breaks inside strings; this escapes the rest.
const auditSafeBlock = value => (typeof value === 'string' ? value : JSON.stringify(value, null, 2) ?? '').replace(AUDIT_UNSAFE_RE, auditEscape)
// Plain phrases for reason codes, the same table as audit_summary._REASON_PHRASES.
const AUDIT_REASON_PHRASES = {
  not_in_report: 'not part of this report',
  not_run: 'not run this time',
  unexpected_shape: 'the report section had an unexpected shape',
  bounded_quick_audit_not_collected: 'not included in a quick audit',
  not_included: 'not included this time',
  could_not_verify: 'could not be verified',
  no_reason: 'the audit did not say why',
  ledger_absent: 'no skill change history file exists yet',
  usage_file_missing: 'no record of skill use exists yet, so use counts are not known',
  missing: 'the file or folder it reads was not found',
  empty: 'the file it reads is empty',
  empty_home: 'the Hermes home is empty',
  missing_home: 'the Hermes home folder was not found',
  missing_profile_root: 'the profile folder was not found',
  profile_missing: 'the profile folder was not found',
  profile_unreadable: 'the profile folder could not be read',
  unreadable: 'the file it reads could not be read',
  not_directory: 'the Hermes home is not a folder',
  invalid_home_root: 'the Hermes home is not a folder',
  invalid_profile_root: 'the profile folder is not a folder',
  managed_overlay: 'some settings are managed outside this home',
  time_budget: 'the audit time limit was reached',
  snapshot_shape: 'some memory backup folders had an unusual layout',
  input_unknown: 'a setting the check needs could not be read',
  no_projects: 'there are no projects to compare with',
  default_profile_never_archived: 'the default profile is never offered for archiving',
  active_profile_never_archived: 'the active profile is never offered for archiving',
  within_active_threshold: 'the profile was used recently',
  not_present: 'nothing of this kind is in this home',
  findings_unverified: 'some of its results could not be verified',
  unverified: 'the check was not run or did not finish',
  // Outward-sweep codes (scope.regions.*.reason_details).
  skipped_folders: 'dependency, cache and Git object folders were skipped and not checked',
  entry_limit_exceeded: 'some folders were not fully checked because the entry limit was reached',
  total_byte_limit_exceeded: 'some folders were not fully checked because the size limit was reached',
  // Limits and read problems named by the sections.
  truncated: 'some files or folders were skipped and not checked',
  entry_budget: 'a folder had more entries than the audit limit',
  max_entries: 'a folder had more entries than the audit limit',
  max_blob_entries: 'a folder had more entries than the audit limit',
  depth_budget: 'folders nested deeper than the audit limit were not checked',
  walk_truncated: 'the walk through the home stopped at an audit limit',
  file_bytes: 'a file was larger than the size limit',
  max_file_bytes: 'a file was larger than the size limit',
  total_bytes_cap: 'the total amount the check may read was reached',
  scandir_error: 'a folder could not be listed',
  subpath_unreadable: 'part of the home could not be listed',
  unreadable_subdir: 'a folder could not be read',
  config_unreadable: 'config.yaml could not be read',
  duplicate_config_key: 'config.yaml sets the same setting twice',
  skills_tree_unreadable: 'the skills folder could not be read',
  external_skill_dirs: 'the skill folders named in config.yaml could not all be checked',
  enabled_plugins: 'the list of turned-on plugins could not be read',
  pet_enabled: 'the pet setting could not be read',
  root_missing: 'the Hermes home folder was not found',
  // Parts of the text sent with every request (context_load) that could not be measured.
  identity_soul: 'the SOUL.md persona could not be measured',
  core_guidance: 'the built-in guidance could not be measured',
  enabled_memory_files: 'the memory files could not be measured',
  auto_loaded_skill_bodies: 'the auto-loaded skills could not be measured',
  skills_index_text: 'the skill list could not be measured',
  external_memory_provider: 'an external memory provider is set up and was not measured',
  project_context: 'the context files of a project could not be fully read',
  // Checks known from their findings.
  dynamic_contributions_unverified: 'plugin text, tool lists and other runtime parts cannot be measured from files',
  memory_unreadable: 'a memory file could not be read',
  soul_unreadable: 'the SOUL.md file could not be read',
  store_unreadable: 'a memory store could not be read',
  entry_age_unverified: 'memory entries carry no dates, so their age is not known',
  inspection_failed: 'a file or folder could not be inspected'
}
export const auditReasonPhrase = reason => typeof reason !== 'string' || !reason ? 'unknown'
  : Object.hasOwn(AUDIT_REASON_PHRASES, reason) ? AUDIT_REASON_PHRASES[reason] : auditSafe(reason).replace(/_/g, ' ')
const auditWords = value => typeof value === 'string' && value ? auditSafe(value).replace(/_/g, ' ') : 'unknown'
const auditNum = value => typeof value === 'number' && Number.isFinite(value) ? value : null
const auditText = value => auditSafe(value)
// Python's f'{n:,}' and f'{n:,.2f}' (audit_summary._int_text).
const auditInt = value => Number.isInteger(value)
  ? value.toLocaleString('en-US')
  : value.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
// audit_summary._evidence_text: bytes as a size, a 0..1 share or rate as a percent, else a number.
const auditEvidence = (key, value) => {
  const label = key.replace(/_/g, ' ')
  if (key.includes('bytes')) return `${label} ${auditBytes(value)}`
  if ((key.includes('share') || key.includes('rate')) && !Number.isInteger(value) && value >= 0 && value <= 1) return `${label} ${Math.round(value * 100)}%`
  return `${label} ${auditInt(value)}`
}
const auditUnitValue = (value, unit) => unit === 'bytes' ? auditBytes(value)
  : unit === 'characters' ? `${auditNum(value) === null ? auditText(value) : auditInt(value)} characters`
    : `${auditNum(value) === null ? auditText(value) : auditInt(value)} ${auditWords(unit)}`
const auditTitleCase = text => text ? text[0].toUpperCase() + text.slice(1) : text
const auditPlural = (n, word, plural) => `${n} ${n === 1 ? word : (plural || `${word}s`)}`
const auditRulePrefix = id => typeof id === 'string' && id.includes('.') ? id.split('.')[0] : null
const auditCoverageLabel = coverage => coverage === 'could_not_verify' ? 'Could not verify'
  : typeof coverage === 'string' && coverage && coverage !== 'verified' && coverage !== 'not_applicable' ? 'Only partly checked' : ''
const auditBytes = value => {
  let size = auditNum(value)
  if (size === null) return 'not known'
  size = Math.trunc(size)
  if (Math.abs(size) < 1024) return size === 1 ? '1 byte' : `${auditInt(size)} bytes`
  for (const unit of ['KB', 'MB', 'GB', 'TB']) {
    size /= 1024
    if (Math.abs(size) < 1024 || unit === 'TB') return `${size.toLocaleString('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 })} ${unit}`
  }
  return `${value} bytes`
}
const auditLabelOf = cls => AUDIT_CLASS_LABELS[cls] || auditWords(cls)
const auditClassRank = cls => { const i = AUDIT_CLASS_ORDER.indexOf(cls); return i < 0 ? AUDIT_CLASS_ORDER.length : i }

function auditGroups(byClass, coverageOf) {
  return Object.entries(byClass)
    .filter(([, rows]) => Array.isArray(rows) && rows.length)
    .sort(([a], [b]) => auditClassRank(a) - auditClassRank(b))
    .map(([cls, rows]) => {
      const items = rows.filter(r => r && typeof r === 'object').map(row => {
        const count = auditNum(row.count) ?? 1
        const evidence = (Array.isArray(row.evidence) ? row.evidence : [])
          .filter(pair => Array.isArray(pair) && pair.length === 2 && auditNum(pair[1]) !== null)
          .map(([key, value]) => auditEvidence(auditText(key), value))
        const coverage = auditCoverageLabel(coverageOf(row.rule_id))
        const sentence = typeof row.sentence === 'string' && row.sentence.trim() ? auditText(row.sentence) : AUDIT_NO_SENTENCE
        return { count, text: `${coverage ? `${coverage}: ` : ''}${sentence}${count > 1 ? ` (${auditInt(count)} times)` : ''}${evidence.length ? ` [${evidence.join(', ')}]` : ''}` }
      })
      const shown = items.slice(0, AUDIT_ROWS_PER_LIST)
      const hidden = items.slice(AUDIT_ROWS_PER_LIST).reduce((sum, item) => sum + item.count, 0)
      return { label: auditLabelOf(cls), rows: shown.map(item => item.text), hidden }
    })
}

export function auditViewModel(payload, run) {
  const summary = payload && typeof payload === 'object' ? payload.summary : null
  if (!summary || typeof summary !== 'object' || !Array.isArray(summary.sections)) return null
  const report = run && typeof run === 'object' ? (run.report && typeof run.report === 'object' ? run.report : run) : {}
  const findings = Array.isArray(report.findings) ? report.findings.filter(f => f && typeof f === 'object') : []
  const coverages = new Map()
  for (const f of findings) {
    if (typeof f.id !== 'string' || typeof f.coverage !== 'string') continue
    if (!coverages.has(f.id)) coverages.set(f.id, new Set())
    coverages.get(f.id).add(f.coverage)
  }
  const coverageOf = id => {
    const seen = coverages.get(id)
    if (!seen) return ''
    return seen.has('could_not_verify') ? 'could_not_verify' : [...seen].find(c => c !== 'verified' && c !== 'not_applicable') || ''
  }
  const sectionKeys = new Set()
  const sections = summary.sections.filter(s => s && typeof s === 'object').map(sec => {
    const key = auditText(sec.section)
    sectionKeys.add(key)
    const reason = typeof sec.reason === 'string' && sec.reason ? sec.reason : null
    const stored = Object.prototype.hasOwnProperty.call(report, key) && report[key] && typeof report[key] === 'object' ? report[key] : null
    let status
    if (sec.measured === true) {
      status = sec.partial ? `Partly measured: some parts could not be checked${reason ? ` (${auditReasonPhrase(reason)})` : ''}.` : 'Measured.'
    } else if (reason === 'not_present') {
      status = 'Not present in this home.'
    } else {
      status = `Not measured (${auditReasonPhrase(reason || stored?.status || 'not_in_report')})${stored?.coverage === 'could_not_verify' ? '; it could not be verified' : ''}.`
    }
    const numbers = sec.numbers && typeof sec.numbers === 'object' ? Object.entries(sec.numbers)
      .filter(([, v]) => ['string', 'number', 'boolean'].includes(typeof v)).map(([k, v]) => `${auditWords(k)}: ${auditText(v)}`) : []
    const headline = typeof sec.headline === 'string' && sec.headline ? [auditText(sec.headline)] : sec.measured === true ? numbers : []
    const groups = auditGroups(sec.findings && typeof sec.findings === 'object' ? sec.findings : {}, coverageOf)
    return { key, title: auditText(sec.title) || auditTitleCase(auditWords(key)), status, headline, groups, measured: sec.measured === true }
  })
  // Checks with findings in the report that the summary has no section for (for example
  // profile_context, memory, template_drift): shown generically, in report order.
  const others = new Map()
  for (const f of findings) {
    const prefix = auditRulePrefix(f.id)
    if (prefix === null || sectionKeys.has(prefix)) continue
    if (!others.has(prefix)) others.set(prefix, [])
    others.get(prefix).push(f)
  }
  for (const [key, rows] of others) {
    const byClass = {}
    for (const f of rows) {
      const cls = typeof f.classification === 'string' && f.classification ? f.classification : 'unclassified'
      const sentence = typeof f.consequence === 'string' && f.consequence.trim() ? f.consequence
        : typeof f.detail === 'string' && f.detail.trim() ? f.detail : AUDIT_NO_SENTENCE
      const list = byClass[cls] || (byClass[cls] = [])
      const same = list.find(r => r.rule_id === f.id && r.sentence === sentence)
      if (same) same.count += 1
      else list.push({ rule_id: f.id, sentence, count: 1, evidence: [] })
    }
    const unverified = rows.some(f => f.coverage === 'could_not_verify')
    sections.push({ key, title: `Other check: ${auditTitleCase(auditWords(key))}`, headline: [], measured: false, fromReport: true,
      status: unverified ? 'Could not verify.' : 'Listed from the full report.',
      groups: auditGroups(byClass, coverageOf) })
  }
  const counts = summary.counts && typeof summary.counts === 'object' ? summary.counts : {}
  const notMeasured = (Array.isArray(summary.not_measured) ? summary.not_measured : []).filter(m => m && typeof m === 'object')
  return {
    measuredOn: typeof summary.measured_on === 'string' ? auditText(summary.measured_on) : '',
    countsLine: `Findings: ${auditPlural(auditNum(counts.warning) ?? 0, 'warning')}, ${auditNum(counts.review_suggested) ?? 0} review suggested, ${auditNum(counts.info) ?? 0} for information.`,
    otherLine: auditNum(summary.other_findings) ? `${summary.other_findings} of these come from other audit checks; they are listed after the summary sections.` : '',
    notMeasuredLine: notMeasured.filter(m => m.reason !== 'not_present').length
      ? `Not measured this time: ${notMeasured.filter(m => m.reason !== 'not_present').map(m => `${auditText(m.title)} (${auditReasonPhrase(m.reason)})`).join(', ')}.`
      : notMeasured.length ? '' : 'Every section was measured.',
    absentLine: notMeasured.some(m => m.reason === 'not_present') ? `Not present in this home: ${notMeasured.filter(m => m.reason === 'not_present').map(m => auditText(m.title)).join(', ')}.` : '',
    biggest: (Array.isArray(summary.biggest_items) ? summary.biggest_items : []).filter(b => b && typeof b === 'object').slice(0, 3)
      .map(b => `${auditText(b.label)}: ${auditUnitValue(b.value, b.unit)}${b.path ? ` (${auditSafe(b.path, true)})` : ''}`),
    scopeNotes: (Array.isArray(summary.scope_notes) ? summary.scope_notes : []).filter(s => typeof s === 'string').map(auditText),
    nextSteps: (Array.isArray(summary.next_steps) ? summary.next_steps : []).filter(s => typeof s === 'string').slice(0, 3).map(auditText),
    sections
  }
}

export const auditSummaryView = model => jsxs('div', { 'data-testid': 'audit-sections', 'aria-label': 'Audit summary', style: { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', display: 'flex', flexDirection: 'column', gap: '8px' }, children: [
  jsx('h3', { style: { margin: 0, fontSize: '14px' }, children: 'Defuzz audit summary' }),
  model.measuredOn ? jsx('p', { style: { margin: 0 }, children: `Measured on ${model.measuredOn} (UTC).` }) : null,
  jsx('p', { style: { margin: 0 }, children: model.countsLine }),
  model.otherLine ? jsx('p', { style: { margin: 0 }, children: model.otherLine }) : null,
  model.notMeasuredLine ? jsx('p', { style: { margin: 0 }, children: model.notMeasuredLine }) : null,
  model.absentLine ? jsx('p', { style: { margin: 0 }, children: model.absentLine }) : null,
  ...(model.scopeNotes || []).map((note, i) => jsx('p', { style: { margin: 0 }, children: note }, `scope-${i}`)),
  model.biggest.length ? jsxs('div', { children: [jsx('h4', { style: { margin: 0 }, children: 'Biggest items' }),
    jsx('ol', { style: { margin: 0 }, children: model.biggest.map((line, i) => jsx('li', { children: line }, i)) })] }) : null,
  ...model.sections.map((sec, index) => jsxs('section', { role: 'region', 'aria-labelledby': `audit-section-${index}`, 'data-audit-section': sec.key, style: { borderTop: '1px solid var(--ui-stroke-secondary)', paddingTop: '6px' }, children: [
    jsx('h4', { id: `audit-section-${index}`, style: { margin: 0 }, children: sec.title }),
    jsx('p', { 'data-testid': 'audit-section-status', style: { margin: 0 }, children: sec.status }),
    ...sec.headline.map((line, i) => jsx('p', { style: { margin: 0 }, children: line }, `h${i}`)),
    sec.measured && !sec.groups.length ? jsx('p', { style: { margin: 0 }, children: 'No findings in this section.' }) : null,
    ...sec.groups.map(group => jsxs('div', { children: [
      jsx('p', { style: { margin: 0, fontWeight: 600 }, children: `${group.label}:` }),
      jsx('ul', { style: { margin: 0 }, children: group.rows.map((row, i) => jsx('li', { 'data-testid': 'audit-finding', children: row }, i)) }),
      group.hidden ? jsx('p', { style: { margin: 0 }, children: `${auditInt(group.hidden)} more. Choose “Show raw report” to see all.` }) : null
    ] }, group.label))
  ] }, `${index}-${sec.key}`)),
  model.nextSteps.length ? jsxs('div', { children: [jsx('h4', { style: { margin: 0 }, children: 'Small next steps' }),
    jsx('ol', { style: { margin: 0 }, children: model.nextSteps.map((step, i) => jsx('li', { children: step }, i)) })] }) : null
] })

const action = (label, onClick, disabled = false) => jsx(Button, { children: label, onClick, disabled })
const field = (label, value, onChange, disabled = false, extraProps = {}) => jsxs('label', { children: [label,
  jsx('input', { 'aria-label': label, value, disabled, onChange: e => onChange(e.target.value), ...extraProps })] })

// Settings section: what ProView used to show, in plain words. Nothing loads on render.
// Setup needs the disclosed plan, then a review step, then a confirmation; trust needs the lock read
// for this project, then a review step that shows the hash, then a confirmation. Each confirmation
// closes after use, so every setup or trust asks again.
export function ComputerToolsSection({ model, state, project, projectState }) {
  const card = background => ({ ...panelStyle, padding: '14px', border: '1px solid var(--ui-stroke-secondary)', borderLeft: '3px solid var(--ui-accent)', borderRadius: '10px', background })
  const [confirmTrust, setConfirmTrust] = useState(false)
  const [confirmSetup, setConfirmSetup] = useState(false)
  const [openTool, setOpenTool] = useState('')
  const toolRefs = useRef({})
  const toolItems = Array.isArray(state.tools?.items) ? state.tools.items : []
  const closeTool = name => {
    setOpenTool('')
    const opener = toolRefs.current?.[name]
    if (opener && typeof opener.focus === 'function') opener.focus()
  }
  const toolStatusLine = item => String(item.status || 'could_not_verify')
  return jsxs('section', { 'aria-label': 'Tools on this computer', 'data-testid': 'settings-computer-tools', 'data-color-scheme': 'no-red-green', style: panelStyle, children: [
    jsx('h2', { style: { margin: 0, fontSize: '15px' }, children: 'Tools on this computer' }),
    jsx('p', { children: 'Nothing is checked, installed or trusted until you press a button here.' }),
    action('Check tools now', () => model.loadPro(project), state.busy),
    jsx('p', { role: 'status', children: state.busy ? 'Checking tools…' : state.proLoaded ? 'Tool status loaded. Press Check tools now to check again.' : 'Not checked yet.' }),
    state.error ? jsx('p', { role: 'alert', children: state.error }) : null,
    ...Object.entries(state.resourceErrors || {}).map(([key, error]) => jsx('p', { role: 'alert', children: `${key}: ${error}` }, key)),
    jsxs('section', { style: card('var(--ui-bg-secondary)'), children: [
    jsx('h3', { children: 'Lint tools, expected versions and setup plan' }),
    jsx('p', { children: 'Expectations come from the plugin manifest; installed versions and paths come from /tools/status. An expected version does not prove a tool is installed. Selecting a pill only reveals its details; it never installs or runs anything.' }),
    !state.tools ? jsx('p', { children: 'Tools not checked yet' }) : (toolItems.length ? jsx('div', {
      role: 'group',
      'aria-label': 'Tool status pills',
      'data-testid': 'tool-status-grid',
      style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '8px', alignItems: 'start' },
      children: toolItems.map(item => {
      const name = String(item.name || 'unknown')
      const isOpen = openTool === name
      const popupId = `tool-status-popup-${name.replace(/[^a-zA-Z0-9_-]+/g, '-')}`
      return jsx('div', {
        key: name,
        style: { position: 'relative', minWidth: 0 },
        onKeyDown: e => {
          if (e?.key !== 'Escape' || !isOpen) return
          e.preventDefault?.()
          closeTool(name)
        },
        children: [
          jsx(Button, {
            className: 'tool-pill',
            'data-testid': 'tool-pill',
            'data-tool': name,
            'aria-expanded': isOpen,
            'aria-controls': popupId,
            title: `${name} — expected ${item.expected_version ?? item.version ?? 'unknown'}, installed ${item.installed_version ?? 'unknown'}`,
            ref: node => { if (toolRefs.current) toolRefs.current[name] = node },
            onClick: () => setOpenTool(current => current === name ? '' : name),
            style: { width: '100%', minWidth: 0, justifyContent: 'center', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' },
            children: name
          }),
          isOpen ? jsx('div', {
            id: popupId,
            role: 'dialog',
            'aria-label': `Tool status ${name}`,
            'data-testid': 'tool-status-popup',
            'data-tool': name,
            style: { position: 'absolute', bottom: 'calc(100% + 6px)', left: 0, right: 0, zIndex: 20, background: RAISED_FILL, color: 'var(--ui-text-primary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', padding: '8px 10px', fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '3px' },
            children: [
              jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' }, children: [
                jsx('strong', { style: { flex: 1, overflowWrap: 'anywhere' }, children: name }),
                jsx(Button, {
                  'data-testid': 'close-tool-status',
                  'aria-label': `Close tool status ${name}`,
                  onClick: () => closeTool(name),
                  children: '×'
                })
              ] }),
              jsx('span', { children: `Expected version: ${item.expected_version ?? item.version ?? 'unknown'}` }),
              jsx('span', { children: `Installed version: ${item.installed_version ?? 'unknown'}` }),
              jsx('span', { style: { overflowWrap: 'anywhere' }, children: `Executable: ${item.executable_path ?? 'unknown'}` }),
              jsx('span', { children: `Status: ${toolStatusLine(item)}` }),
              item.error ? jsx('span', { role: 'alert', style: { overflowWrap: 'anywhere' }, children: `Error: ${item.error}` }) : null
            ]
          }) : null
        ]
      })
    })}) : jsx('p', { children: 'No tool rows returned; absence is not a pass.' })),
    state.tools?.plan ? jsx('details', { 'data-testid': 'tool-setup-plan', style: { marginTop: '6px' }, children: [
      jsx('summary', { style: { cursor: 'pointer' }, children: 'Setup plan and total size (review before confirming)' }),
      outputView(state.tools.plan)
    ] }) : null
    ] }),
    jsxs('section', { style: card('var(--ui-bg-secondary)'), children: [
    jsx('h3', { children: 'Installed tool versions' }),
    jsx('p', { children: 'Installed versions and executable paths are shown in each tool pill above. They come from /tools/status, separately from the selected project and TOOLS.lock. An expected version does not prove a tool is installed; a missing answer means unknown.' })
    ] }),
    jsxs('section', { style: card('var(--ui-bg-secondary)'), children: [
    jsx('h3', { children: 'Setup status' }), outputView(state.setup || 'Setup not checked yet'),
    jsx('p', { children: 'Tools are downloaded only after you read the plan above and confirm. Opening this page never installs or runs anything.' }),
    action('Review setup confirmation', () => setConfirmSetup(true), state.busy || !state.tools?.plan || state.tools?.lazy_installs_allowed !== true || state.setup?.state === 'running'),
    // data-glass-raised has no effect here: Hermes remaps unused variables; opacity comes from --ui-bg-elevated.
    confirmSetup ? jsxs('div', { role: 'group', 'aria-label': 'Confirm tool setup', 'data-glass-raised': true, style: card(RAISED_FILL), children: [
      jsx('p', { children: 'Download and install the disclosed tools into the user-space cache? Review plan and total size above before proceeding.' }),
      action('Confirm download and setup', async () => { await model.setup(); setConfirmSetup(false) }, state.busy),
      action('Cancel setup confirmation', () => setConfirmSetup(false))
    ] }) : null,
    action('Cancel running setup', () => model.setup(true), state.busy || state.setup?.state !== 'running'),
    ] }),
    jsxs('section', { style: card('var(--ui-bg-secondary)'), children: [
    jsx('h3', { children: 'TOOLS.lock trust and hash' }),
    !project ? jsx('p', { children: 'Choose a project on the main page to see its TOOLS.lock.' }) : outputView(state.lock || 'Lock not checked yet'),
    action('Review trust confirmation', () => setConfirmTrust(true), state.busy || !state.lock?.trust?.tools_lock_hash || state.project !== project),
    confirmTrust ? jsxs('div', { role: 'group', 'aria-label': 'Confirm lock trust', 'data-glass-raised': true, style: card(RAISED_FILL), children: [
      jsx('p', { children: 'Trust only after reviewing the lock bytes and hash below. Trust is provenance, not a safety guarantee.' }),
      outputView(state.lock?.trust?.tools_lock_hash),
      action('Trust displayed hash', async () => { await model.trustLock(project); setConfirmTrust(false) }, state.busy),
      action('Cancel trust', () => setConfirmTrust(false))
    ] }) : null,
    ] }),
    jsxs('section', { style: card('var(--ui-bg-secondary)'), children: [
    jsx('h3', { children: 'TOOLS.lock contents (read only, nothing is run)' }),
    outputView(state.lockFile?.content || state.lockFile || 'Lock bytes not loaded; missing or unreadable is not a pass.'),
    jsx('p', { children: 'This only reads the file. It does not run any tool and does not prove the tools are correct. To run a read-only audit, use AUDIT Full ▶ or Quick ▶ at the bottom of the main page.' }),
    ] }),
    jsxs('section', { style: card('var(--ui-bg-secondary)'), children: [
    jsx('h3', { children: 'Saved project list (raw data)' }), outputView(projectState || []),
    ] })
  ] })
}

export const V10_TEMPLATES = [
  {
    id: 'ts-node-golden',
    badge: 'TS',
    label: 'TypeScript · Node',
    kind: 'service',
    layout: 'mono',
    language: 'typescript',
    previewTree: ['packages/foundation/', 'packages/domain/', 'packages/adapters/http-hono/', 'packages/adapters/http-node/', 'packages/apps/', 'tools/xtask/', 'AGENTS.md', 'package.json', '.env.example']
  },
  {
    id: 'rust-golden',
    badge: 'R',
    label: 'Rust',
    kind: 'app',
    layout: 'mono',
    language: 'rust',
    previewTree: ['crates/foundation/', 'crates/domain/', 'crates/adapters/', 'crates/apps/', 'xtask/', 'AGENTS.md', 'Cargo.toml', 'rust-toolchain.toml']
  },
  {
    id: 'python-golden',
    badge: 'Py',
    label: 'Python',
    kind: 'service',
    layout: 'mono',
    language: 'python',
    previewTree: ['packages/foundation/', 'packages/domain/', 'packages/adapters/', 'packages/apps/', 'tools/xtask/', 'AGENTS.md', 'pyproject.toml', 'uv.lock']
  },
  {
    id: 'go-golden',
    badge: 'Go',
    label: 'Go',
    kind: 'service',
    layout: 'mono',
    language: 'go',
    previewTree: ['foundation/', 'domain/', 'adapters/', 'apps/cli/', 'xtask/', 'AGENTS.md', 'go.mod', '.golangci.yml']
  },
  {
    id: 'cpp-golden',
    badge: 'C++',
    label: 'C++20 · CMake',
    kind: 'tool',
    layout: 'mono',
    language: 'cpp',
    previewTree: ['foundation/', 'domain/', 'adapters/', 'cli/', 'cmake/', 'AGENTS.md', 'CMakeLists.txt', '.clang-format', '.clang-tidy']
  },
  {
    id: 'dotnet-golden',
    badge: 'C#',
    label: '.NET · C# (csharpier)',
    kind: 'service',
    layout: 'mono',
    language: 'csharp',
    tools: ['csharpier', 'dotnet-format'],
    previewTree: ['src/Foundation/', 'src/Domain/', 'src/Adapters/', 'src/Cli/', 'xtask/', 'AGENTS.md', 'Directory.Build.props', 'Directory.Build.targets', 'global.json']
  },
  {
    id: 'web-golden',
    badge: 'Web',
    label: 'Static website · Vite + TypeScript',
    summary: 'Static-first website: Vite and TypeScript, no framework, design tokens as CSS custom properties, accessible pages, and one check command (pnpm xtask ci).',
    kind: 'app',
    layout: 'mono',
    language: 'typescript',
    previewTree: ['design/tokens/', 'public/', 'src/pages/', 'src/components/', 'src/styles/', 'src/assets/', 'src/lib/', 'tests/unit/', 'tests/e2e/', 'scripts/', 'docs/', 'tools/xtask/', 'AGENTS.md', 'package.json', 'vite.config.ts']
  }
]

// Details the page holds for a template row the person chose. A template the server
// lists but this page does not know is still creatable; it just has no preview tree.
const templateSpecFor = (id, entry) => V10_TEMPLATES.find(t => t.id === id) || { id, label: entry?.title || id, previewTree: [] }
const templateAnswers = spec => (spec?.language
  ? { building: spec.kind || 'service', layout: spec.layout || 'mono', languages: [spec.language] }
  : {})
const fallbackTemplateOptions = id => (id === 'ts-node-golden'
  ? { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'], choiceLabels: { hono: 'Hono', node_http: 'Node HTTP' } } }
  : id === 'python-golden'
    ? { http_adapter: { label: 'HTTP adapter', default: 'fastapi', choices: ['fastapi', 'stdlib_http'], choiceLabels: { fastapi: 'FastAPI', stdlib_http: 'Python standard library' } } }
    : {})
// Unique per row: the position in the list makes two ids that sanitise alike distinct.
const choiceDomId = (prefix, index, id) => `${prefix}-${index}-${String(id).replace(/[^A-Za-z0-9_-]/g, '_')}`
const mutedText = { fontSize: '11px', color: 'var(--ui-text-secondary)' }
const LIST_SLOW_MS = 4000
const ACCEPT_RECHECK_MS = 5000

export const V10_AUDIT_SCRIPTS = [
  {
    id: 'profile_context', idx: '01', stage: 0, cat: 'context', catLabel: 'Hermes & memory',
    title: 'Hermes context', module: 'audit/vendor/profile_context.py',
    summary: 'Checks active Hermes profile for shadowed skills, truncated instructions and memory-state drift.',
    desc: 'Inspects the captured Hermes profile snapshot that wraps this project so hidden skill overrides or truncated system instructions cannot silently alter agent behavior.',
    reads: ['Active profile config', 'Skill manifests', 'AGENTS.md / instruction buffers', 'Memory state index'],
    checks: ['Shadowed skill names', 'Truncated prompt/instruction files', 'Profile vs. disk memory drift'],
    never: ['Never invokes skills', 'Never mutates Hermes profile', 'Never makes model/API calls'],
    sample: '[VERIFIED] profile_context · 0 shadowed skills across 14 loaded\n[DRIFT]    AGENTS.md instruction buffer near cap (3,910 / 4,096 B)'
  },
  {
    id: 'memory', idx: '02', stage: 1, cat: 'context', catLabel: 'Hermes & memory',
    title: 'Memory references', module: 'audit/vendor/memory.py',
    summary: 'Finds stale file paths, duplicate entries and cross-project memory leakage.',
    desc: 'Scans memory entries linked to the active profile to verify referenced files still exist and ensure another project’s private context is not bleeding into this workspace.',
    reads: ['Profile memory store', 'Referenced workspace paths', 'Cross-project pointer entries'],
    checks: ['Dead / deleted file pointers', 'Duplicate memory keys', 'Cross-project context exposure'],
    never: ['Never deletes memory entries', 'Never writes to MEMORY.md'],
    sample: '[VERIFIED] memory · 18 entries checked, 0 duplicate keys\n[FINDING]  memory.py:42 · Stale path ref -> packages/legacy-auth/src'
  },
  {
    id: 'executable_inventory', idx: '03', stage: 2, cat: 'code', catLabel: 'Project & code',
    title: 'Execution inventory', module: 'audit/vendor/executable_inventory.py',
    summary: 'Inventories plugin, MCP and hook declarations without launching them.',
    desc: 'Catalogs every executable surface declared by the project or profile (hooks, MCP servers, package scripts). Dynamic registrations that cannot be statically resolved are flagged as unverified.',
    reads: ['package.json scripts', 'MCP server declarations', 'Hook config manifests', 'Plugin entrypoints'],
    checks: ['Declared lifecycle hooks', 'External MCP command strings', 'Unresolvable dynamic registrations'],
    never: ['Never spawns MCP servers', 'Never executes lifecycle hooks'],
    sample: '[INVENTORY] 2 package scripts (check, test) · 0 postinstall hooks\n[UNVERIFIED] 1 dynamic plugin loader in tools/xtask (static limit)'
  },
  {
    id: 'template_drift', idx: '04', stage: 2, cat: 'code', catLabel: 'Project & code',
    title: 'Template drift', module: 'audit/vendor/template_drift.py',
    summary: 'Compares project files against template provenance, locked files and placeholder rules.',
    desc: 'Diffs the captured workspace against its recorded template baseline (ts-node-golden) to spot modified locked files, leftover scaffolding placeholders, or missing required structure.',
    reads: ['Template provenance manifest', 'Locked file hashes', 'Workspace file tree'],
    checks: ['Modified locked template files', 'Unreplaced template placeholders', 'Missing golden-layout packages'],
    never: ['Never overwrites drifted files', 'Never runs git checkout/reset'],
    sample: '[VERIFIED] template_drift · Matches baseline ts-node-golden\n[VERIFIED] 0 unreplaced placeholder tokens found'
  },
  {
    id: 'static_code', idx: '05', stage: 2, cat: 'code', catLabel: 'Project & code',
    title: 'Static code policy', module: 'audit/vendor/static_code.py',
    summary: 'Checks source imports for layer boundary violations and lint/type suppressions.',
    desc: 'Parses supported source files to enforce architectural dependency rules (e.g. foundation must not import adapters) and inventories inline suppression comments like @ts-ignore.',
    reads: ['packages/**/src/*.ts', 'tsconfig.base.json', 'Import / export AST edges'],
    checks: ['Upward layer imports (foundation -> apps)', 'Inline rule suppressions (@ts-ignore)', 'Unsupported language disclosure'],
    never: ['Never compiles or bundles code', 'Never executes TypeScript/Node'],
    sample: '[VERIFIED] static_code · 12 TS files parsed · 0 layer violations\n[FINDING]  packages/adapters/http-hono/src/index.ts · 0 suppressions'
  },
  {
    id: 'tool_guard', idx: '06', stage: 2, cat: 'outward', catLabel: 'Locks & outward',
    title: 'Tool declarations', module: 'tool_guard.py · static_lock_summary',
    summary: 'Reads TOOLS.lock provenance statically without launching any binaries.',
    desc: 'Inspects TOOLS.lock to verify pinned tool versions and checksum provenance match policy—strictly by reading the lockfile, without invoking the underlying CLI binaries.',
    reads: ['TOOLS.lock', 'Pinned binary digests', 'Toolchain policy manifest'],
    checks: ['Missing TOOLS.lock pins', 'Unpinned or mismatched tool hashes', 'Declared vs. policy version drift'],
    never: ['Never runs tool --version', 'Never downloads or updates binaries'],
    sample: '[VERIFIED] tool_guard · TOOLS.lock parsed statically\n[VERIFIED] biome, oxlint, tsc provenance pins present'
  },
  {
    id: 'outward', idx: '07', stage: 3, cat: 'outward', catLabel: 'Locks & outward',
    title: 'Outward references', module: 'audit/outward.py',
    summary: 'Traces symlinks, Git remotes/worktrees and shared startup files outside the repo.',
    desc: 'In Full mode, follows evidenced outward pointers (Git worktrees, symlinks, shared startup/profile files) within resource budgets. Quick mode uses bounded active-profile capture plus selected-project checks, skips this outward collector, and records uncollected scope as COULD NOT VERIFY (never clean).',
    reads: ['.git config & worktree links', 'Symlink targets', 'Bounded shared startup files'],
    checks: ['Symlinks escaping project root', 'Shared parent config dependencies', 'Cross-profile file links'],
    never: ['Never fetches Git remotes', 'Never scans arbitrary home folders'],
    sample: '[VERIFIED] outward · 0 symlinks escaping workspace root\n[INFO]     Quick skips outward collection; bounded profile and project checks remain'
  }
]

export const V10_LINT_CHECK_GROUPS = {
  typescript: [
    { id: 'biome', title: 'Formatting & style', tool: 'Biome', execRisk: true, execLabel: '⚠ Can exec repo code', summary: 'Formatting and supported TS/JS diagnostics.', detail: 'Runs configured Biome checks against matching project files and returns structured rule + line locations.', inputs: ['biome.json', 'packages/**/*.{ts,js,json}'], cmd: 'linter.py -> biome check --reporter=json packages/', warning: 'Tool manifest marks Biome as capable of executing repository code/plugins. Review biome.json and isolation before running.' },
    { id: 'oxlint', title: 'Code diagnostics', tool: 'Oxlint', execRisk: true, execLabel: '⚠ Can exec repo code', summary: 'Fast JavaScript and TypeScript lint rules.', detail: 'Runs Oxlint across matching JS/TS source files and collects structured rule diagnostics.', inputs: ['.oxlintrc.json', 'packages/**/*.ts'], cmd: 'linter.py -> oxlint --format=json packages/', warning: 'Current manifest marks Oxlint as capable of executing repository code. Manual execution does not imply sandboxing.' }
  ],
  python: [
    { id: 'ruff', title: 'Python diagnostics', tool: 'Ruff', execRisk: false, execLabel: '✓ Static file check', summary: 'Python lint rules and source diagnostics.', detail: 'Checks matching Python files with Ruff and reports file locations, messages and rule IDs without executing repo code.', inputs: ['pyproject.toml', 'ruff.toml', '**/*.py'], cmd: 'linter.py -> ruff check --output-format=json .', warning: 'Manifest marks Ruff as not executing repository code. It still reads project files and configuration.' },
    { id: 'ruff-format', title: 'Formatting', tool: 'Ruff format', execRisk: false, execLabel: '✓ Static file check', summary: 'Verify Python formatting in check-only mode.', detail: 'Runs Ruff formatter in --check mode; any suggested formatting diffs remain separate from this manual check.', inputs: ['pyproject.toml', '**/*.py'], cmd: 'linter.py -> ruff format --check .', warning: 'Manifest marks ruff format as not executing repository code. Check-only mode does not modify files.' }
  ],
  rust: [
    { id: 'rustfmt', title: 'Formatting', tool: 'rustfmt', execRisk: false, execLabel: '✓ Static file check', summary: 'Check Rust source formatting.', detail: 'Checks matching Rust source files against rustfmt.toml without modifying files on disk.', inputs: ['rustfmt.toml', 'src/**/*.rs'], cmd: 'linter.py -> rustfmt --check src/lib.rs', warning: 'Manifest marks rustfmt as not executing repository code.' },
    { id: 'clippy', title: 'Rust diagnostics', tool: 'Clippy', execRisk: true, execLabel: '⚠ Runs build.rs / macros', summary: 'Compiler-backed Rust analysis and lints.', detail: 'Runs cargo clippy analysis and collects structured compiler and lint diagnostics.', inputs: ['Cargo.toml', 'build.rs', 'src/**/*.rs'], cmd: 'linter.py -> cargo clippy --message-format=json', warning: 'Clippy compiles proc-macros and can execute build.rs scripts inside the repository. Verify trust and sandbox before running.' }
  ],
  go: [
    { id: 'gofmt', title: 'Go formatting', tool: 'gofmt', execRisk: false, execLabel: '✓ Static file check', summary: 'Verify standard Go source formatting.', detail: 'Checks matching Go files with gofmt -e -l without modifying files on disk.', inputs: ['go.mod', '**/*.go'], cmd: 'linter.py -> gofmt -e -l .', warning: 'Manifest marks gofmt as not executing repository code.' },
    { id: 'golangci-lint', title: 'Go diagnostics', tool: 'golangci-lint', execRisk: true, execLabel: '⚠ Can exec repo code', summary: 'Go static analysis and linter suite.', detail: 'Runs golangci-lint and collects structured JSON findings.', inputs: ['go.mod', '.golangci.yml', '**/*.go'], cmd: 'linter.py -> golangci-lint run --output.json.path stdout ./...', warning: 'golangci-lint type-checks and may invoke Go build/module tooling.' }
  ],
  cpp: [
    { id: 'clang-format', title: 'C/C++ formatting', tool: 'clang-format', execRisk: false, execLabel: '✓ Static file check', summary: 'Dry-run C/C++ formatting check.', detail: 'Checks matching C/C++ headers and sources with clang-format --dry-run -Werror.', inputs: ['.clang-format', 'CMakeLists.txt', '**/*.{cpp,hpp,h}'], cmd: 'linter.py -> clang-format --dry-run -Werror', warning: 'Manifest marks clang-format as not executing repository code.' },
    { id: 'clang-tidy', title: 'C/C++ diagnostics', tool: 'clang-tidy', execRisk: false, execLabel: '✓ Static AST check', summary: 'Compile-commands-backed C++ static analysis.', detail: 'Runs clang-tidy against compile_commands.json and C++ source files.', inputs: ['.clang-tidy', 'compile_commands.json', '**/*.cpp'], cmd: 'linter.py -> clang-tidy -p build', warning: 'Requires compile_commands.json in root, build/, or out/.' }
  ],
  csharp: [
    { id: 'csharpier', title: 'C# formatting', tool: 'csharpier', execRisk: false, execLabel: '✓ Static file check', summary: 'Verify C# formatting with CSharpier.', detail: 'Runs csharpier check across C# files without modifying files on disk.', inputs: ['Directory.Build.props', '**/*.cs'], cmd: 'linter.py -> csharpier check .', warning: 'Manifest marks csharpier as not executing repository code.' },
    { id: 'dotnet-format', title: '.NET analyzer check', tool: 'dotnet-format', execRisk: true, execLabel: '⚠ Can exec MSBuild targets', summary: 'Verify .NET formatting and analyzer rules.', detail: 'Runs dotnet format --verify-no-changes --no-restore across the solution.', inputs: ['*.sln', '**/*.csproj', '**/*.cs'], cmd: 'linter.py -> dotnet format --verify-no-changes --no-restore', warning: 'dotnet format evaluates MSBuild project files; review project targets before running.' }
  ]
}

export const V10_PIPELINE_STAGES = {
  auditor: [
    { title: 'Profile context', sub: 'Context checks · 01', leadScript: 0 },
    { title: 'Memory', sub: 'References · 02', leadScript: 1 },
    { title: 'Code & tools', sub: 'Static checks · 03–06', leadScript: 2 },
    { title: 'Outward scope', sub: 'References · 07', leadScript: 6 }
  ],
  lint: [
    { title: 'Select checks', sub: 'Manual checkboxes', toolSlot: 0 },
    { title: 'Probe binaries', sub: 'PATH & config check', toolSlot: 0 },
    { title: 'Spawn CLI linters', sub: 'Runs external binary', toolSlot: 1 },
    { title: 'Line diagnostics', sub: 'File, line & rule ID', toolSlot: 1 }
  ]
}

const PROJECT_META_KEYS = ['template_id', 'template', 'language', 'languages', 'stack']

function projectMetaText(project) {
  const parts = []
  for (const key of PROJECT_META_KEYS) {
    const value = project?.[key]
    if (typeof value === 'string') parts.push(value)
    else if (Array.isArray(value)) parts.push(...value.filter(item => typeof item === 'string'))
  }
  return parts.join(' ').toLowerCase()
}

// Template/language badges come from metadata only. Names and paths are user data:
// a folder called "copy" or "py-copy" must never be mistaken for a Python project.
export function projectBadgeFor(project) {
  const meta = projectMetaText(project)
  if (meta.includes('web-golden')) return { badge: 'Web', template: 'web-golden' }
  if (/(^|[^a-z0-9])(rust|cargo)([^a-z0-9]|$)|\.rs($|[^a-z0-9])/.test(meta)) return { badge: 'R', template: 'rust-golden' }
  if (/(^|[^a-z0-9])(python|py|uv)([^a-z0-9]|$)/.test(meta)) return { badge: 'Py', template: 'python-golden' }
  if (/(^|[^a-z0-9])(go|golang)([^a-z0-9]|$)/.test(meta)) return { badge: 'Go', template: 'go-golden' }
  if (/(^|[^a-z0-9])(cpp|c\+\+|cmake)([^a-z0-9]|$)/.test(meta)) return { badge: 'C++', template: 'cpp-golden' }
  if (/(^|[^a-z0-9])(dotnet|csharp|c#)([^a-z0-9]|$)/.test(meta)) return { badge: 'C#', template: 'dotnet-golden' }
  // TypeScript is a positive claim: require an explicit TS/template marker. Unknown metadata
  // (including adopted projects and name/path tokens like "py") stays unknown.
  if (meta.includes('ts-node-golden') || /(^|[^a-z0-9])(ts|typescript|node|javascript|js)([^a-z0-9]|$)/.test(meta)) {
    return { badge: 'TS', template: 'ts-node-golden' }
  }
  return { badge: '?', template: 'unknown' }
}

const FOLDER_STATUS_ORDER = ['present', 'missing', 'not_directory', 'unavailable']

function normalizeProjectRecord(project, fallbackStatus) {
  // The registry's exact stored string: used to key management rows and as the POST body for
  // forget. Never trim it or substitute the canonical path, or a duplicate alias cannot be
  // targeted exactly.
  const registrationPath = typeof project?.raw_path === 'string' && project.raw_path
    ? project.raw_path
    : typeof project?.path === 'string' && project.path
      ? project.path
      : typeof project?.canonical_path === 'string' && project.canonical_path ? project.canonical_path : ''
  // The canonical folder: used for selection and read actions. Two stored registrations may
  // point at one folder, so the strip de-dupes on this value.
  const path = typeof project?.canonical_path === 'string' && project.canonical_path
    ? project.canonical_path
    : typeof project?.path === 'string' && project.path
      ? project.path
      : registrationPath
  const trimmed = path.replace(/[\\/]+$/, '')
  const name = typeof project?.name === 'string' && project.name
    ? project.name
    : trimmed ? trimmed.split(/[\\/]/).pop() : 'Unnamed project'
  const declared = typeof project?.folder_status === 'string' ? project.folder_status : ''
  return { ...project, name, path, canonicalPath: path, registrationPath, folder_status: declared || fallbackStatus }
}

// `projects` are the records whose directory exists; `unavailable_projects` keep the rest.
// Missing folders are not projects any more, so they never join the current strip or count.
function normalizeProjectLists(result) {
  const currentRecords = Array.isArray(result?.projects) ? result.projects : []
  const unavailableRecords = Array.isArray(result?.unavailable_projects) ? result.unavailable_projects : []
  const coverage = result?.coverage === 'verified' ? 'verified' : 'could_not_verify'
  const projects = currentRecords.map(record => {
    const project = normalizeProjectRecord(record, 'present')
    const registered = project.registered === true || (project.registered !== false && coverage === 'verified')
    return {
      ...project,
      folder_status: 'present',
      registered,
      registrationStatus: registered ? 'registered' : project.registered === false ? 'not registered' : 'could_not_verify'
    }
  })
  const unavailableProjects = unavailableRecords.map(record => {
    const project = normalizeProjectRecord(record, 'unavailable')
    return {
      ...project,
      registered: false,
      folder_status: FOLDER_STATUS_ORDER.includes(project.folder_status) && project.folder_status !== 'present'
        ? project.folder_status
        : 'unavailable'
    }
  })
  return { projects, unavailableProjects }
}

export function buildTreeFromPaths(paths = []) {
  const root = []
  for (const rawPath of paths) {
    if (!rawPath || typeof rawPath !== 'string') continue
    const parts = rawPath.split('/').filter(Boolean)
    let currentList = root
    let currentPrefix = ''
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i]
      currentPrefix = currentPrefix ? `${currentPrefix}/${part}` : part
      const isLast = i === parts.length - 1
      if (isLast) {
        if (!currentList.some(n => !n.children && n.path === currentPrefix)) {
          currentList.push({ name: part, path: currentPrefix })
        }
      } else {
        let folder = currentList.find(n => n.children && n.name === part)
        if (!folder) {
          folder = { name: part, path: currentPrefix, children: [] }
          currentList.push(folder)
        }
        currentList = folder.children
      }
    }
  }
  return root
}

export function renderSafeMarkdown(text = '') {
  const renderInline = (str, keyPrefix) => {
    const tokens = String(str).split(/(`[^`]+`|\*\*[^*]+\*\*)/g)
    return tokens.filter(Boolean).map((tok, idx) => {
      if (tok.startsWith('`') && tok.endsWith('`') && tok.length >= 2) {
        return jsx('code', { children: tok.slice(1, -1) }, `${keyPrefix}-c-${idx}`)
      }
      if (tok.startsWith('**') && tok.endsWith('**') && tok.length >= 4) {
        return jsx('strong', { children: tok.slice(2, -2) }, `${keyPrefix}-b-${idx}`)
      }
      return tok
    })
  }
  const elements = []
  let listItems = []
  let paragraphLines = []
  let fenceLines = null
  const flushParagraph = () => {
    if (paragraphLines.length) {
      const joined = paragraphLines.join(' ')
      elements.push(jsx('p', { children: renderInline(joined, `p-${elements.length}`) }, `p-${elements.length}`))
      paragraphLines = []
    }
  }
  const flushList = () => {
    if (listItems.length) {
      elements.push(jsx('ul', {
        children: listItems.map((item, i) => jsx('li', { children: renderInline(item, `li-${elements.length}-${i}`) }, `li-${i}`))
      }, `ul-${elements.length}`))
      listItems = []
    }
  }
  for (const line of String(text).split('\n')) {
    if (line.startsWith('```')) {
      flushParagraph()
      flushList()
      if (fenceLines !== null) {
        elements.push(jsx('pre', { children: jsx('code', { children: fenceLines.join('\n') }) }, `pre-${elements.length}`))
        fenceLines = null
      } else {
        fenceLines = []
      }
      continue
    }
    if (fenceLines !== null) {
      fenceLines.push(line)
      continue
    }
    if (!line.trim()) {
      flushParagraph()
      flushList()
      continue
    }
    const heading = line.match(/^(#{1,3})\s+(.*)/)
    if (heading) {
      flushParagraph()
      flushList()
      const tag = `h${heading[1].length}`
      elements.push(jsx(tag, { children: heading[2] }, `${tag}-${elements.length}`))
      continue
    }
    if (line.startsWith('- ')) {
      flushParagraph()
      listItems.push(line.slice(2))
      continue
    }
    flushList()
    paragraphLines.push(line)
  }
  flushParagraph()
  flushList()
  if (fenceLines !== null) {
    elements.push(jsx('pre', { children: fenceLines.join('\n') }, `pre-${elements.length}`))
  }
  return jsx('article', { className: 'markdown-view', 'data-testid': 'markdown-preview', style: { lineHeight: 1.65, padding: '8px 14px', color: 'var(--ui-text-primary)' }, children: elements })
}

// Defuzz's own preferences about the defuzz-componentize companion (GET/PUT /componentize/settings).
const COMPANION_KEYS = ['enabled_on_adopt', 'run_survey_on_new', 'cli_path_override']
const COMPANION_SOURCES = { hermes: 'hermes componentize', path: 'componentize on PATH', override: 'the saved path' }

function companionErrorText(error, fallback) {
  const body = error?.body && typeof error.body === 'object' ? error.body : null
  if (typeof body?.error === 'string' && body.error.trim()) return body.error.trim()
  const msg = String(error?.message || '')
  const match = /(?:^|[\s:])([1-5]\d\d): /.exec(msg)
  if (match) {
    try {
      const parsed = JSON.parse(msg.slice(match.index + match[0].length))
      const text = typeof parsed?.error === 'string' ? parsed.error : typeof parsed?.detail === 'string' ? parsed.detail : ''
      if (text.trim()) return text.trim()
    } catch {}
  }
  return msg.split(/\r?\n/)[0].trim() || fallback
}

function readCompanionPrefs(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  if (Object.keys(raw).some(key => !COMPANION_KEYS.includes(key))) return null
  const value = { enabled_on_adopt: raw.enabled_on_adopt, run_survey_on_new: raw.run_survey_on_new, cli_path_override: raw.cli_path_override ?? null }
  if (typeof value.enabled_on_adopt !== 'boolean' || typeof value.run_survey_on_new !== 'boolean') return null
  if (value.cli_path_override !== null && typeof value.cli_path_override !== 'string') return null
  return value
}

const companionDraftOf = saved => ({ enabled_on_adopt: saved.enabled_on_adopt, run_survey_on_new: saved.run_survey_on_new, cli_path_override: saved.cli_path_override ?? '' })

// Nothing is sent until save(); rest is a createScopedRest() so a profile/connection switch refuses the PUT.
export function createCompanionPrefsModel(rest, changed = () => {}) {
  let state = { phase: 'idle', saved: null, draft: null, dirty: false, saveState: '', error: '', loadError: '', commandLine: '', checking: false }
  let token = 0, disposed = false
  const isDirty = (draft, saved) => Boolean(draft && saved) && JSON.stringify(draft) !== JSON.stringify(companionDraftOf(saved))
  const emit = patch => {
    if (disposed) return
    state = { ...state, ...patch }
    state = { ...state, dirty: isDirty(state.draft, state.saved) }
    changed(state)
  }
  return {
    get: () => state,
    dispose: () => { disposed = true; token += 1 },
    async load() {
      if (disposed || state.saveState === 'saving') return
      const mine = ++token
      emit({ phase: 'loading', loadError: '', error: '', saveState: '' })
      try {
        const raw = await rest('/componentize/settings')
        if (mine !== token) return
        if (raw && typeof raw.error === 'string') throw new Error(raw.error)
        const saved = readCompanionPrefs(raw)
        if (!saved) throw new Error('The saved preferences have an unexpected shape.')
        emit({ phase: 'ready', saved, draft: companionDraftOf(saved) })
      } catch (error) {
        if (mine === token) emit({ phase: 'load-error', loadError: companionErrorText(error, 'Preferences unavailable') })
      }
    },
    edit(patch) {
      if (state.phase !== 'ready' || state.saveState === 'saving') return
      const next = { ...state.draft }
      for (const key of COMPANION_KEYS) {
        if (!Object.hasOwn(patch || {}, key)) continue
        next[key] = key === 'cli_path_override' ? String(patch[key] ?? '') : Boolean(patch[key])
      }
      emit({ draft: next, saveState: state.saveState === 'saved' ? '' : state.saveState })
    },
    revert() {
      if (state.phase !== 'ready' || state.saveState === 'saving') return
      emit({ draft: companionDraftOf(state.saved), error: '', saveState: '' })
    },
    async save() {
      if (disposed || state.phase !== 'ready' || state.saveState === 'saving') return
      const draft = state.draft
      const body = {
        enabled_on_adopt: draft.enabled_on_adopt === true,
        run_survey_on_new: draft.run_survey_on_new === true,
        cli_path_override: draft.cli_path_override.trim() === '' ? null : draft.cli_path_override
      }
      const mine = ++token
      emit({ saveState: 'saving', error: '' })
      try {
        const raw = await rest('/componentize/settings', { method: 'PUT', body })
        if (mine !== token) return
        if (raw && typeof raw.error === 'string') throw new Error(raw.error)
        const saved = readCompanionPrefs(raw)
        if (!saved) throw new Error('The save was not confirmed. Reload the page before saving again.')
        const stillSame = JSON.stringify(state.draft) === JSON.stringify(draft)
        emit({ saved, draft: stillSame ? companionDraftOf(saved) : state.draft, saveState: 'saved', commandLine: '' })
      } catch (error) {
        if (mine === token) emit({ saveState: 'error', error: companionErrorText(error, 'Save failed') })
      }
    },
    async checkCommand() {
      if (disposed || state.checking) return
      emit({ checking: true, commandLine: 'Looking for the command…' })
      try {
        const raw = await rest('/componentize/status')
        if (raw && typeof raw.error === 'string') throw new Error(raw.error)
        const line = raw?.detected === true
          ? `Command found (${COMPANION_SOURCES[raw.source] || 'unknown source'}${typeof raw.version === 'string' && raw.version ? `, version ${raw.version}` : ''}).`
          : 'Command not found. Kits and surveys are skipped until it is installed.'
        emit({ checking: false, commandLine: line })
      } catch (error) {
        emit({ checking: false, commandLine: `Could not check: ${companionErrorText(error, 'status unavailable')}` })
      }
    }
  }
}

export function CompanionPrefsSection({ ctx, rest, kitsUnavailable = false }) {
  const [, setTick] = useState(0)
  const [model] = useState(() => createCompanionPrefsModel(rest || createScopedRest(ctx), () => setTick(n => n + 1)))
  useEffect(() => {
    model.load()
    const unregister = ctx?.onDispose?.(() => model.dispose())
    return () => { model.dispose(); if (typeof unregister === 'function') unregister() }
  }, [model])
  const s = model.get()
  const ready = s.phase === 'ready'
  const saving = s.saveState === 'saving'
  const locked = !ready || saving
  const statusText = s.phase === 'loading' || s.phase === 'idle' ? 'Loading preferences…'
    : s.phase === 'load-error' ? 'Preferences not loaded.'
    : saving ? 'Saving…'
    : s.saveState === 'error' ? 'Not saved.'
    : s.dirty ? 'Unsaved changes. Nothing is saved until you press Save.'
    : s.saveState === 'saved' ? 'Saved.'
    : 'No unsaved changes.'
  const errorId = s.saveState === 'error' && s.error ? 'companion-prefs-error' : ''
  const described = help => [help, errorId].filter(Boolean).join(' ')
  const draft = s.draft || { enabled_on_adopt: false, run_survey_on_new: false, cli_path_override: '' }
  const row = { display: 'flex', alignItems: 'flex-start', gap: '8px' }
  const helpStyle = { ...mutedText, margin: '2px 0 0' }
  return jsxs('section', { id: 'companion-prefs', 'aria-labelledby': 'companion-prefs-title', style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '10px' }, children: [
    jsx('h2', { id: 'companion-prefs-title', style: { margin: 0, fontSize: '15px' }, children: 'Project kits (companion plugin)' }),
    jsx('p', { style: { ...mutedText, margin: 0 }, children: 'Defuzz\u2019s own preferences for the defuzz-componentize plugin. They apply to the active profile.' }),
    kitsUnavailable ? jsx('p', { id: 'companion-kits-missing', style: { ...mutedText, margin: 0 }, children: 'Kits need the defuzz-componentize plugin.' }) : null,
    s.phase === 'load-error' ? jsxs('div', { role: 'alert', style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }, children: [
      jsx('p', { id: 'companion-prefs-load-error', style: { margin: 0, overflowWrap: 'anywhere' }, children: `These preferences could not be loaded: ${s.loadError}` }),
      jsx(Button, { id: 'companion-prefs-retry', onClick: () => model.load(), children: 'Try again' })
    ] }) : null,
    jsxs('div', { style: row, children: [
      jsx('input', { id: 'companion-enabled-on-adopt', type: 'checkbox', checked: draft.enabled_on_adopt, disabled: locked, 'aria-describedby': described('companion-enabled-on-adopt-help'), onChange: e => model.edit({ enabled_on_adopt: Boolean(e?.target?.checked) }) }),
      jsxs('div', { children: [
        jsx('label', { htmlFor: 'companion-enabled-on-adopt', children: 'Use the companion plugin when adopting a project' }),
        jsx('p', { id: 'companion-enabled-on-adopt-help', style: helpStyle, children: 'After Defuzz adopts a project, it runs the companion\u2019s survey on the adopted copy: it writes .adopt/componentize-survey.json and one line in AGENTS.md. Nothing is split. Skipped if the command is not found.' })
      ] })
    ] }),
    jsxs('div', { style: row, children: [
      jsx('input', { id: 'companion-run-survey-on-new', type: 'checkbox', checked: draft.run_survey_on_new, disabled: locked, 'aria-describedby': described('companion-run-survey-on-new-help'), onChange: e => model.edit({ run_survey_on_new: Boolean(e?.target?.checked) }) }),
      jsxs('div', { children: [
        jsx('label', { htmlFor: 'companion-run-survey-on-new', children: 'Run the companion\'s survey when a project is created' }),
        jsx('p', { id: 'companion-run-survey-on-new-help', style: helpStyle, children: 'After a new project is created, Defuzz runs the same survey and records it in its own commit. If it fails or the command is not found, the project is still created.' })
      ] })
    ] }),
    jsxs('div', { style: { display: 'flex', flexDirection: 'column', gap: '4px' }, children: [
      jsx('label', { htmlFor: 'companion-cli-path', children: 'Path to the componentize command (optional)' }),
      jsx('input', { id: 'companion-cli-path', type: 'text', value: draft.cli_path_override, disabled: locked, spellCheck: false, 'aria-describedby': described('companion-cli-path-help'), onChange: e => model.edit({ cli_path_override: e?.target?.value ?? '' }), style: { padding: '6px 8px', background: 'var(--ui-bg-secondary)', color: 'var(--ui-text-primary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', fontFamily: 'var(--font-mono)' } }),
      jsx('p', { id: 'companion-cli-path-help', style: helpStyle, children: 'Leave empty to find it automatically (hermes componentize, then componentize on PATH). This page does not check that the file exists.' })
    ] }),
    errorId ? jsx('p', { id: errorId, role: 'alert', style: { margin: 0, overflowWrap: 'anywhere' }, children: s.error }) : null,
    jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }, children: [
      jsx(Button, { id: 'companion-prefs-save', className: 'primary', disabled: locked || !s.dirty, onClick: () => model.save(), children: 'Save' }),
      jsx(Button, { id: 'companion-prefs-revert', disabled: locked || !s.dirty, onClick: () => model.revert(), children: 'Revert' }),
      jsx(Button, { id: 'companion-prefs-check', disabled: s.checking, onClick: () => model.checkCommand(), children: 'Check for the command' }),
      jsx('span', { id: 'companion-prefs-status', role: 'status', style: mutedText, children: statusText })
    ] }),
    s.commandLine ? jsx('p', { id: 'companion-prefs-command', role: 'status', style: { ...mutedText, margin: 0 }, children: s.checking ? s.commandLine : `${s.commandLine} This check uses the saved path, not unsaved changes.` }) : null
  ] })
}

export function SettingsView({ ctx, model, state, project = '', auditMode = 'full', scopedRest = null, live = null, liveState = null, projectState = null }) {
  const [tab, setTab] = useState('auditor')
  const [guideOpen, setGuideOpen] = useState(false)
  const [pipeStep, setPipeStep] = useState(0)
  const [scriptFilter, setScriptFilter] = useState('all')
  const [scriptIdx, setScriptIdx] = useState(0)
  const [lintLang, setLintLang] = useState('typescript')
  const [selectedToolId, setSelectedToolId] = useState('biome')
  const [playing, setPlaying] = useState(false)
  const [notice, setNotice] = useState('Auditor · Click any script or open Interactive guide (preview only)')
  const [dirtyToolEdits, setDirtyToolEdits] = useState({})
  const timerDisposeRef = useRef(null)
  const playStepRef = useRef(0)

  const stopDryRun = () => {
    if (timerDisposeRef.current) {
      timerDisposeRef.current()
      timerDisposeRef.current = null
    }
    setPlaying(false)
  }

  useEffect(() => {
    const unregister = ctx?.onDispose?.(() => {
      if (timerDisposeRef.current) {
        timerDisposeRef.current()
        timerDisposeRef.current = null
      }
    })
    return () => {
      if (timerDisposeRef.current) {
        timerDisposeRef.current()
        timerDisposeRef.current = null
      }
      if (typeof unregister === 'function') unregister()
    }
  }, [ctx])

  const projectName = project || state?.selected || 'No project selected'
  const prevContextRef = useRef({ projectName, auditMode })
  if (prevContextRef.current.projectName !== projectName || prevContextRef.current.auditMode !== auditMode) {
    prevContextRef.current = { projectName, auditMode }
    if (timerDisposeRef.current) {
      timerDisposeRef.current()
      timerDisposeRef.current = null
    }
  }

  const liveRules = (model?.get?.()?.settings || state?.settings)?.rules || []
  const isToolEnabled = toolId => {
    if (Object.hasOwn(dirtyToolEdits, toolId)) return dirtyToolEdits[toolId] !== false
    const matchingRule = liveRules.find(r => r.id === toolId)
    if (matchingRule) return matchingRule.enabled !== false
    return true
  }

  const mergeToolRules = (existingRules, updates) => {
    let nextRules = Array.isArray(existingRules) ? [...existingRules] : []
    for (const { id, label, enabled } of updates) {
      if (nextRules.some(r => r.id === id)) {
        nextRules = nextRules.map(r => r.id === id ? { ...r, enabled } : r)
      } else {
        nextRules.push({ id, label, mode: 'both', enabled })
      }
    }
    return nextRules
  }

  const setToolEnabled = (toolItem, enabled) => {
    if (state?.busy) return
    stopDryRun()
    setDirtyToolEdits(prev => ({ ...prev, [toolItem.id]: enabled }))
    if (model && typeof model.settings === 'function') {
      const currentSettings = model.get?.()?.settings || state?.settings || { rules: [] }
      const nextRules = mergeToolRules(currentSettings.rules, [{ id: toolItem.id, label: toolItem.title || toolItem.tool, enabled }])
      model.settings({ ...currentSettings, rules: nextRules })
    }
    setNotice(`Selection updated — saving does not execute ${toolItem.tool}.`)
  }

  const toggleLanguageChecks = enabled => {
    if (state?.busy) return
    stopDryRun()
    const tools = V10_LINT_CHECK_GROUPS[lintLang] || V10_LINT_CHECK_GROUPS.typescript
    const patch = {}
    const updates = []
    for (const t of tools) {
      patch[t.id] = enabled
      updates.push({ id: t.id, label: t.title || t.tool, enabled })
    }
    setDirtyToolEdits(prev => ({ ...prev, ...patch }))
    if (model && typeof model.settings === 'function') {
      const currentSettings = model.get?.()?.settings || state?.settings || { rules: [] }
      const nextRules = mergeToolRules(currentSettings.rules, updates)
      model.settings({ ...currentSettings, rules: nextRules })
    }
    setNotice('Selection updated — saving checkboxes only updates preferences.')
  }

  const saveLintChecks = async () => {
    if (state?.busy || !model) return
    stopDryRun()
    if (!model.get?.()?.loaded && typeof model.loadSettings === 'function') {
      await model.loadSettings()
    }
    const afterLoad = model.get?.() || state
    if (!afterLoad?.loaded || afterLoad?.error) {
      setNotice(`Failed to load settings: ${afterLoad?.error || 'Settings unavailable'}`)
      return
    }
    const allToolsById = new Map(Object.values(V10_LINT_CHECK_GROUPS).flat().map(t => [t.id, t]))
    const updates = Object.entries(dirtyToolEdits).map(([id, enabled]) => {
      const meta = allToolsById.get(id)
      return { id, label: meta?.title || meta?.tool || id, enabled }
    })
    if (updates.length > 0) {
      const currentSettings = afterLoad.settings || { rules: [] }
      const nextRules = mergeToolRules(currentSettings.rules, updates)
      model.settings?.({ ...currentSettings, rules: nextRules })
    }
    if (typeof model.saveSettings === 'function') {
      await model.saveSettings()
    }
    const afterSave = model.get?.() || state
    if (afterSave?.error || afterSave?.settingsSaveState !== 'saved') {
      setNotice(`Failed to save settings: ${afterSave?.error || 'Settings save failed'}`)
      return
    }
    setDirtyToolEdits({})
    setNotice('Lint tool preferences saved.')
  }

  const visibleScripts = scriptFilter === 'all' ? V10_AUDIT_SCRIPTS : V10_AUDIT_SCRIPTS.filter(s => s.cat === scriptFilter)
  const activeScript = V10_AUDIT_SCRIPTS[scriptIdx] || V10_AUDIT_SCRIPTS[0]
  const activeTools = V10_LINT_CHECK_GROUPS[lintLang] || V10_LINT_CHECK_GROUPS.typescript
  const activeTool = activeTools.find(t => t.id === selectedToolId) || activeTools[0]
  const stages = V10_PIPELINE_STAGES[tab] || V10_PIPELINE_STAGES.auditor

  const selectScript = (idx, fromAutoplay = false) => {
    if (!fromAutoplay) stopDryRun()
    const normalized = ((idx % V10_AUDIT_SCRIPTS.length) + V10_AUDIT_SCRIPTS.length) % V10_AUDIT_SCRIPTS.length
    const nextScript = V10_AUDIT_SCRIPTS[normalized]
    setScriptIdx(normalized)
    setPipeStep(nextScript.stage)
    if (!fromAutoplay) setNotice(`Inspecting script ${nextScript.idx}/07: ${nextScript.module} (Read-only static module · synced with Stage ${nextScript.stage + 1})`)
  }

  const selectStage = (idx, fromAutoplay = false) => {
    if (!fromAutoplay) stopDryRun()
    const normalized = ((idx % stages.length) + stages.length) % stages.length
    setPipeStep(normalized)
    if (tab === 'auditor') {
      const lead = stages[normalized].leadScript
      if (!fromAutoplay && V10_AUDIT_SCRIPTS[scriptIdx]?.stage !== normalized) {
        setScriptIdx(lead)
        if (scriptFilter !== 'all' && V10_AUDIT_SCRIPTS[lead]?.cat !== scriptFilter) setScriptFilter('all')
      }
    } else if (!fromAutoplay) {
      const slot = Math.min(stages[normalized].toolSlot, activeTools.length - 1)
      setSelectedToolId(activeTools[slot].id)
    }
    if (!fromAutoplay) setNotice(`${tab === 'auditor' ? 'Auditor preview guide' : 'Lint preview guide'} · Stage ${normalized + 1}/4: ${stages[normalized].title} (educational preview — no code executed)`)
  }

  const togglePlay = () => {
    if (playing || timerDisposeRef.current) {
      stopDryRun()
      setNotice('Preview walkthrough paused.')
      return
    }
    if (!guideOpen) setGuideOpen(true)
    setPlaying(true)
    playStepRef.current = 0
    if (tab === 'auditor') {
      if (scriptFilter !== 'all') setScriptFilter('all')
      selectScript(0, true)
      if (typeof ctx?.setInterval === 'function') {
        timerDisposeRef.current = ctx.setInterval(() => {
          playStepRef.current += 1
          if (playStepRef.current >= V10_AUDIT_SCRIPTS.length) {
            stopDryRun()
            selectScript(V10_AUDIT_SCRIPTS.length - 1, true)
            setNotice('Preview walkthrough complete · All 7 static Python modules previewed (no audit executed).')
            return
          }
          selectScript(playStepRef.current, true)
        }, 1250)
      }
    } else {
      selectStage(0, true)
      if (typeof ctx?.setInterval === 'function') {
        timerDisposeRef.current = ctx.setInterval(() => {
          playStepRef.current += 1
          if (playStepRef.current >= stages.length) {
            stopDryRun()
            selectStage(stages.length - 1, true)
            setNotice(`Lint preview walkthrough complete · Selected ${lintLang} tools previewed (no binaries launched).`)
            return
          }
          const nextStage = playStepRef.current
          setPipeStep(nextStage)
          const slot = Math.min(stages[nextStage].toolSlot, activeTools.length - 1)
          setSelectedToolId(activeTools[slot].id)
        }, 1300)
      }
    }
  }

  const switchTab = nextTab => {
    stopDryRun()
    setTab(nextTab)
    setPipeStep(nextTab === 'auditor' ? activeScript.stage : 0)
    setNotice(nextTab === 'auditor' ? 'Auditor · Click any script or open Interactive guide (preview only)' : 'Lint rules · Select a tool to inspect its binary & execution behavior')
  }

  const contextLine = tab === 'auditor'
    ? pipeStep === 0
      ? `${auditMode === 'quick' ? 'Quick bounded mode' : 'Full outward mode'} · ${projectName}: ${auditMode === 'quick' ? 'Limited profile capture; full context inventory remains unverified.' : 'Inspect profile context and evidenced outward references.'}`
      : pipeStep === 1
        ? `Memory: ${activeScript.module} checks captured profile memory references in both modes; incomplete coverage remains unknown.`
        : pipeStep === 2
          ? `Static Python [${activeScript.idx}/${String(V10_AUDIT_SCRIPTS.length).padStart(2, '0')}]: ${activeScript.module} reads ${activeScript.reads[0]} statically — zero repo hooks, scripts or network launched.`
          : `Outward scope: ${activeScript.module} traces evidenced paths in Full; Quick skips this collector and reports COULD NOT VERIFY.`
    : pipeStep === 0
      ? `Select checks: Toggle ${activeTool.tool} for ${projectName}; saving checkboxes updates preferences only and never triggers a background run.`
      : pipeStep === 1
        ? `Probe binaries: linter.py verifies ${activeTool.tool} binary & ${activeTool.inputs[0]} exist without auto-installing packages.`
        : pipeStep === 2
          ? `Spawn CLI linter: Manual LINT ▶ runs ${activeTool.cmd} (${activeTool.execLabel}).`
          : `Line diagnostics: Collects structured file, line & rule findings from ${activeTool.tool} without modifying repository files.`

  return jsxs('section', { id: 'settings', 'data-testid': 'v10-settings', 'data-project-name': projectName, 'data-audit-mode': auditMode, 'aria-label': 'Settings', style: panelStyle, children: [
    jsxs('header', { className: 'settings-top', 'data-testid': 'settings-top-header', style: { display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '16px', borderBottom: '1px solid var(--ui-stroke-secondary)', paddingBottom: '12px' }, children: [
      jsx('h1', { style: { margin: 0, fontSize: '15px', color: 'var(--ui-text-primary)' }, children: 'Project settings' }),
      jsxs('nav', { className: 'setting-tabs', 'aria-label': 'Settings sections', style: { display: 'flex', gap: '8px' }, children: [
        jsxs(Button, { id: 'auditor-tab', 'data-testid': 'auditor-tab', 'aria-pressed': tab === 'auditor', onClick: () => switchTab('auditor'), children: ['Auditor ', jsx('span', { className: 'tab-count', children: `${V10_AUDIT_SCRIPTS.length} scripts` })] }),
        jsxs(Button, { id: 'lint-tab', 'data-testid': 'lint-tab', 'aria-pressed': tab === 'lint', onClick: () => switchTab('lint'), children: ['Lint rules ', jsx('span', { className: 'tab-count', children: `${Object.values(V10_LINT_CHECK_GROUPS).flat().length} tools` })] })
      ] }),
      jsx('span', { style: { marginLeft: 'auto' } }),
      jsx(Button, { id: 'tutorial-toggle', 'data-testid': 'tutorial-toggle', 'aria-expanded': guideOpen, 'aria-pressed': guideOpen, onClick: () => { if (guideOpen) stopDryRun(); setGuideOpen(!guideOpen) }, children: `✦ Interactive guide [${playing ? 'Playing' : 'Preview'}]` }),
      jsx(Button, { id: 'back-button', 'data-testid': 'back-button', 'aria-label': 'Back to workspace', onClick: () => { stopDryRun(); model?.screen?.('main'); host.navigate(ROUTE_PATH) }, children: '← Workspace' })
    ] }),
    guideOpen ? jsxs('section', { id: 'tutorial-strip', 'data-testid': 'tutorial-strip', 'aria-label': 'Educational pipeline preview', 'data-glass-raised': true, style: { background: RAISED_FILL, color: 'var(--ui-text-primary)', padding: '10px 14px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '8px' }, children: [
      jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }, children: [
        jsx(Badge, { children: 'Preview demo' }),
        jsxs('div', { id: 'pipeline-bar', role: 'group', 'aria-label': 'Pipeline stages', style: { flex: 1, display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '6px' }, children: stages.map((s, i) => jsx(Button, {
          'data-testid': `v10-stage-card-${i}`,
          'aria-pressed': i === pipeStep,
          onClick: () => selectStage(i, false),
          children: `${i + 1}. ${s.title} — ${s.sub}`
        }, s.title)) }),
        jsxs('div', { 'aria-label': 'Guide playback controls', style: { display: 'flex', gap: '4px' }, children: [
          jsx(Button, { id: 'dry-run-button', 'data-testid': 'dry-run-button', 'aria-pressed': playing, onClick: togglePlay, children: playing ? '⏸ Pause' : '▶ Play' }),
          jsx(Button, { id: 'guide-prev', 'aria-label': 'Previous stage', onClick: () => selectStage(pipeStep - 1, false), children: '◀' }),
          jsx(Button, { id: 'guide-next', 'aria-label': 'Next stage', onClick: () => selectStage(pipeStep + 1, false), children: '▶' }),
          jsx(Button, { id: 'guide-hide', onClick: () => { stopDryRun(); setGuideOpen(false) }, children: 'Hide' })
        ] })
      ] }),
      jsxs('div', { 'data-testid': 'guide-context-line', style: { display: 'flex', alignItems: 'center', gap: '10px', fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: [
        jsx(Badge, { id: 'spot-badge', 'data-testid': 'spot-badge', children: `${tab === 'auditor' ? 'AUDITOR' : 'LINT'} · STAGE ${pipeStep + 1} OF ${stages.length}` }),
        jsx('p', { id: 'spot-text', 'data-testid': 'spot-text', style: { margin: 0, flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }, children: contextLine }),
        jsx('span', { id: 'spot-sync', 'data-testid': 'spot-sync', children: tab === 'auditor' ? `Synced: Script ${activeScript.idx}/${String(V10_AUDIT_SCRIPTS.length).padStart(2, '0')} (${activeScript.id})` : `Synced: ${activeTool.tool} (${lintLang})` })
      ] })
    ] }) : null,
    tab === 'auditor' ? jsxs('div', { id: 'auditor-panel', 'data-testid': 'auditor-panel', style: { display: 'grid', gridTemplateColumns: 'minmax(0, 1.25fr) minmax(320px, 0.95fr)', gap: '16px' }, children: [
      jsxs('div', { style: { display: 'flex', flexDirection: 'column', gap: '12px' }, children: [
        jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }, children: [
          jsx('h2', { style: { margin: 0, fontSize: '15px' }, children: 'Audit script pipeline' }),
          jsx(Badge, { children: 'Internal Python · Never executes repo code' }),
          jsxs('div', { role: 'group', 'aria-label': 'Filter scripts by stage', style: { display: 'flex', gap: '4px', flexWrap: 'wrap' }, children: [
            ['all', 'All (7)'],
            ['context', 'Hermes & memory (2)'],
            ['code', 'Project & code (3)'],
            ['outward', 'Locks & outward (2)']
          ].map(([cat, label]) => jsx(Button, {
            'data-testid': `script-filter-${cat}`,
            'aria-pressed': scriptFilter === cat,
            onClick: () => {
              stopDryRun()
              setScriptFilter(cat)
              const list = cat === 'all' ? V10_AUDIT_SCRIPTS : V10_AUDIT_SCRIPTS.filter(s => s.cat === cat)
              if (!list.includes(V10_AUDIT_SCRIPTS[scriptIdx])) {
                const nextIdx = V10_AUDIT_SCRIPTS.indexOf(list[0])
                setScriptIdx(nextIdx)
                setPipeStep(V10_AUDIT_SCRIPTS[nextIdx].stage)
              }
            },
            children: label
          }, cat)) }),
          jsx(Button, { 'aria-label': 'Previous script', onClick: () => selectScript(scriptIdx - 1, false), children: '◀' }),
          jsx('span', { id: 'script-counter', children: `Script ${scriptIdx + 1} / ${V10_AUDIT_SCRIPTS.length}` }),
          jsx(Button, { 'aria-label': 'Next script', onClick: () => selectScript(scriptIdx + 1, false), children: '▶' })
        ] }),
        jsx('div', { id: 'script-list', role: 'listbox', 'aria-label': 'Audit scripts', style: { display: 'flex', flexDirection: 'column', gap: '6px' }, children: visibleScripts.map(s => {
          const fullIdx = V10_AUDIT_SCRIPTS.indexOf(s)
          return jsxs('button', {
            type: 'button',
            'data-testid': `v10-script-row-${fullIdx}`,
            'aria-selected': fullIdx === scriptIdx,
            onClick: () => selectScript(fullIdx, false),
            style: { display: 'grid', gridTemplateColumns: '34px 1fr 1.2fr auto', gap: '10px', alignItems: 'center', padding: '10px', textAlign: 'left', border: `1px solid ${fullIdx === scriptIdx ? 'var(--ui-accent)' : 'var(--ui-stroke-secondary)'}`, borderRadius: '6px', background: 'transparent', color: 'var(--ui-text-primary)' },
            children: [
              jsx('span', { children: s.idx }),
              jsxs('div', { children: [jsx('b', { style: { display: 'block' }, children: s.title }), jsx('code', { style: { fontSize: '11px', color: 'var(--ui-text-secondary)' }, children: s.module })] }),
              jsx('span', { style: { fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: s.summary }),
              jsx(Badge, { children: s.catLabel })
            ]
          }, s.id)
        }) }),
        jsxs('div', { 'aria-label': 'Audit status meanings', style: { display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '8px' }, children: [
          jsxs('div', { style: { padding: '8px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', fontSize: '11px' }, children: [jsx('b', { children: '● Verified' }), jsx('div', { children: 'Static check completed on the captured snapshot. Does not guarantee runtime safety.' })] }),
          jsxs('div', { style: { padding: '8px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', fontSize: '11px' }, children: [jsx('b', { children: '◐ Could not verify' }), jsx('div', { children: 'Dynamic, excluded or unreadable region. Treated as unknown—never a pass.' })] }),
          jsxs('div', { style: { padding: '8px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', fontSize: '11px' }, children: [jsx('b', { children: '◈ Advisory report' }), jsx('div', { children: 'Saved in plugin storage with file & line evidence. Zero automatic edits or cleanup.' })] })
        ] })
      ] }),
      jsxs('aside', { 'aria-label': 'Selected script inspector', style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '10px' }, children: [
        jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' }, children: [
          jsx(Badge, { id: 'insp-step', children: `SCRIPT ${activeScript.idx} / 07` }),
          jsx('h3', { id: 'insp-title', 'data-testid': 'insp-title', style: { margin: 0 }, children: activeScript.title }),
          jsx(Button, { 'aria-label': 'Previous script', onClick: () => selectScript(scriptIdx - 1, false), children: '← Prev' }),
          jsx(Button, { 'aria-label': 'Next script', onClick: () => selectScript(scriptIdx + 1, false), children: 'Next →' })
        ] }),
        jsx('code', { id: 'insp-module', children: activeScript.module }),
        jsx('p', { id: 'insp-desc', 'data-testid': 'insp-desc', style: { margin: 0, fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: activeScript.desc }),
        jsxs('div', { children: [jsx('strong', { style: { fontSize: '11px' }, children: 'What this script reads (inputs): ' }), activeScript.reads.join(' · ')] }),
        jsxs('div', { children: [jsx('strong', { style: { fontSize: '11px' }, children: 'What it flags (checks): ' }), activeScript.checks.join(' · ')] }),
        jsxs('div', { children: [jsx('strong', { style: { fontSize: '11px' }, children: 'Hard boundary (never does): ' }), activeScript.never.join(' · ')] }),
        jsx('pre', { id: 'insp-sample', style: { margin: 0, padding: '8px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', fontSize: '11px', whiteSpace: 'pre-wrap' }, children: activeScript.sample })
      ] })
    ] }) : null,
    tab === 'lint' ? jsxs('div', { id: 'lint-panel', 'data-testid': 'lint-panel', style: { display: 'grid', gridTemplateColumns: 'minmax(0, 1.25fr) minmax(320px, 0.95fr)', gap: '16px' }, children: [
      jsxs('div', { style: { display: 'flex', flexDirection: 'column', gap: '10px' }, children: [
        jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }, children: [
          jsx('h2', { style: { margin: 0, fontSize: '15px' }, children: 'Enabled lint tools' }),
          jsx(Badge, { children: 'Spawns installed CLI binaries' }),
          jsxs('div', { 'aria-label': 'Lint language', style: { display: 'flex', gap: '4px', flexWrap: 'wrap' }, children: [
            ['typescript', 'TS / JS'],
            ['python', 'Python'],
            ['rust', 'Rust'],
            ['go', 'Go'],
            ['cpp', 'C / C++'],
            ['csharp', 'C#']
          ].map(([langKey, label]) => jsx(Button, {
            'data-testid': `v10-lint-lang-${langKey}`,
            'aria-pressed': lintLang === langKey,
            onClick: () => {
              stopDryRun()
              setLintLang(langKey)
              setPipeStep(0)
              setSelectedToolId(V10_LINT_CHECK_GROUPS[langKey][0].id)
            },
            children: label
          }, langKey)) }),
          jsx(Button, { id: 'lint-enable-all', 'data-testid': 'lint-enable-all', disabled: Boolean(state?.busy), onClick: () => toggleLanguageChecks(true), children: 'Enable all' }),
          jsx(Button, { id: 'lint-clear-all', 'data-testid': 'lint-clear-all', disabled: Boolean(state?.busy), onClick: () => toggleLanguageChecks(false), children: 'Clear' })
        ] }),
        jsxs('div', { className: 'lint-columns', style: { display: 'grid', gridTemplateColumns: '40px 1fr 1.2fr auto', gap: '10px', fontSize: '10px', textTransform: 'uppercase', color: 'var(--ui-text-quaternary)', padding: '2px 10px' }, children: [
          jsx('span', { children: 'Run' }),
          jsx('span', { children: 'Check / binary' }),
          jsx('span', { children: 'What it checks' }),
          jsx('span', { children: 'Execution behavior' })
        ] }),
        jsx('div', { id: 'lint-checks', style: { display: 'flex', flexDirection: 'column', gap: '6px' }, children: activeTools.map((item, idx) => jsxs('div', {
          'data-testid': `v10-lint-item-${item.id}`,
          'data-check': item.id,
          tabIndex: 0,
          onClick: () => {
            stopDryRun()
            setSelectedToolId(item.id)
            setPipeStep(idx === 0 ? 0 : 2)
          },
          style: { display: 'grid', gridTemplateColumns: '40px 1fr 1.2fr auto', gap: '10px', alignItems: 'center', padding: '10px', border: `1px solid ${activeTool.id === item.id ? 'var(--ui-accent)' : 'var(--ui-stroke-secondary)'}`, borderRadius: '6px', cursor: 'pointer' },
          children: [
            jsx('input', {
              type: 'checkbox',
              'aria-label': `Enable ${item.tool}`,
              disabled: Boolean(state?.busy),
              checked: isToolEnabled(item.id),
              onClick: e => e?.stopPropagation?.(),
              onChange: e => setToolEnabled(item, Boolean(e?.target?.checked))
            }),
            jsxs('div', { children: [jsx('b', { style: { display: 'block' }, children: item.title }), jsx('code', { style: { fontSize: '11px' }, children: item.tool })] }),
            jsx('span', { style: { fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: item.summary }),
            jsx(Badge, { children: item.execLabel })
          ]
        }, item.id)) }),
        jsxs('div', { 'aria-label': 'Lint execution rules', style: { display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '8px', marginTop: '4px' }, children: [
          jsxs('div', { style: { padding: '8px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', fontSize: '11px' }, children: [
            jsx('b', { children: '◈ Manual trigger only' }),
            jsx('div', { children: 'Nothing runs on save, git commit or chat activity. Saving checkboxes only updates preferences.' })
          ] }),
          jsxs('div', { style: { padding: '8px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', fontSize: '11px' }, children: [
            jsx('b', { children: '⚠ Binary execution' }),
            jsx('div', { children: 'Unlike Auditor, Lint launches installed CLI tools. Some tools (Biome, Oxlint, Clippy) can execute repo config or build scripts.' })
          ] }),
          jsxs('div', { style: { padding: '8px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', fontSize: '11px' }, children: [
            jsx('b', { children: '● Missing tools reported' }),
            jsx('div', { children: 'linter.py probes binary availability first and never silently installs packages.' })
          ] })
        ] })
      ] }),
      jsxs('aside', { 'aria-label': 'Selected lint tool details', style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '12px' }, children: [
        jsxs('section', { style: { display: 'flex', flexDirection: 'column', gap: '8px' }, children: [
          jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' }, children: [
            jsx(Badge, { id: 'check-tool', 'data-testid': 'check-tool', children: activeTool.tool }),
            jsx('h3', { id: 'check-title', style: { margin: 0 }, children: activeTool.title }),
            jsx(Badge, { id: 'check-exec-badge', children: activeTool.execLabel })
          ] }),
          jsx('code', { id: 'check-runner', children: 'linter.py · run_lint → lint_tools.py' }),
          jsx('p', { id: 'check-description', style: { margin: 0, fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: activeTool.detail }),
          jsx('div', { id: 'check-inputs', style: { fontSize: '11px' }, children: `Inputs: ${activeTool.inputs.join(', ')}` }),
          jsx('p', { id: 'check-warning', style: { margin: 0, fontSize: '11.5px', color: 'var(--ui-accent)' }, children: activeTool.warning }),
          jsx('pre', { id: 'check-cmd-preview', style: { margin: 0, padding: '8px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', fontSize: '11px' }, children: `$ ${activeTool.cmd}` })
        ] }),
        jsxs('section', { className: 'gate-card', style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '7px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '8px' }, children: [
          jsx('h3', { style: { margin: 0, fontSize: '13px' }, children: 'How Auditor & Lint differ' }),
          jsxs('div', { className: 'gate-grid', style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '11.5px' }, children: [
            jsxs('div', { className: 'gate-kv', style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '5px', padding: '6px 9px' }, children: [
              jsx('span', { style: { display: 'block', fontSize: '10px', color: 'var(--ui-text-quaternary)' }, children: `Auditor (${V10_AUDIT_SCRIPTS.length} scripts)` }),
              jsx('b', { children: 'Static Python readers' })
            ] }),
            jsxs('div', { className: 'gate-kv', style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '5px', padding: '6px 9px' }, children: [
              jsx('span', { style: { display: 'block', fontSize: '10px', color: 'var(--ui-text-quaternary)' }, children: `Lint rules (${Object.values(V10_LINT_CHECK_GROUPS).flat().length} tools)` }),
              jsx('b', { children: 'Spawns CLI binaries' })
            ] })
          ] }),
          jsx('p', { style: { margin: 0, fontSize: '11.5px', color: 'var(--ui-text-secondary)' }, children: 'Need to inspect Hermes profile drift, memory links or TOOLS.lock without launching any external binary?' }),
          jsx(Button, { onClick: () => switchTab('auditor'), children: '← Switch to Auditor script guide' })
        ] })
      ] })
    ] }) : null,
    jsx(CompanionPrefsSection, { ctx, rest: scopedRest || undefined, kitsUnavailable: String(state?.catalog?.notice || '').startsWith('Kits need the defuzz-componentize plugin') }),
    live ? jsx(ComputerToolsSection, { model: live, state: liveState || live.get(), project, projectState }) : null,
    jsxs('footer', { className: 'bottom', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', paddingTop: '8px', borderTop: '1px solid var(--ui-stroke-secondary)', fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: [
      jsx('span', { id: 'settings-status', role: 'status', children: notice }),
      tab === 'lint' ? jsx(Button, { id: 'lint-save', 'data-testid': 'lint-save', disabled: Boolean(state?.busy), onClick: saveLintChecks, children: 'Save checks' }) : null
    ] })
  ] })
}

export const DEFUZZ_BANNER_DATA_URL = 'data:image/webp;base64,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'

export function WorkspacePage({ ctx, initialScreen = 'main' }) {
  const [state, setState] = useState(null)
  const [file, setFile] = useState('')
  const [projectSearch, setProjectSearch] = useState('')
  const [templateFilter, setTemplateFilter] = useState('all')
  const [wrap, setWrap] = useState(false)
  const [fontSize, setFontSize] = useState(12)
  const [mdMode, setMdMode] = useState('preview')
  const [collapseAll, setCollapseAll] = useState(false)
  const [collapsedFolders, setCollapsedFolders] = useState({})
  const [newProjectModalOpen, setNewProjectModalOpen] = useState(false)
  const [modalIdea, setModalIdea] = useState('')
  const [modalName, setModalName] = useState('')
  const [modalTemplate, setModalTemplate] = useState('')
  const [modalUnsupportedKey, setModalUnsupportedKey] = useState('')
  const [modalAdapter, setModalAdapter] = useState('')
  const [modalTplOptions, setModalTplOptions] = useState({ id: '', options: null })
  const [choiceGoneNotice, setChoiceGoneNotice] = useState('')
  const [listSlow, setListSlow] = useState(false)
  const [createdProjectFiles, setCreatedProjectFiles] = useState({})
  const [auditModalOpen, setAuditModalOpen] = useState(false)
  const [auditMode, setAuditMode] = useState('full')
  const [auditConsent, setAuditConsent] = useState(false)
  const [auditDisclosure, setAuditDisclosure] = useState('')
  const [auditActionState, setAuditActionState] = useState({ busy: false, error: '', report: null, status: null })
  const [auditSummary, setAuditSummary] = useState({ runId: '', text: '', data: null, raw: false })
  const [storageModalOpen, setStorageModalOpen] = useState(false)
  const [actionNotice, setActionNotice] = useState('')
  const [footerLintByProject, setFooterLintByProject] = useState({})
  const [footerChecksByProject, setFooterChecksByProject] = useState({})
  const [model] = useState(() => createWorkspaceModel(ctx, setState, initialScreen))
  const [liveState, setLiveState] = useState(null)
  const [live] = useState(() => createLiveModel(ctx, setLiveState))
  const [scopedRest] = useState(() => createScopedRest(ctx))
  const auditPollDisposeRef = useRef(null)
  const auditScopeTokenRef = useRef(0)
  const auditRunTokenRef = useRef(0)
  const disposedRef = useRef(false)
  const footerLintRef = useRef({})
  const footerChecksRef = useRef({})
  const dragStateRef = useRef(null)
  const modalOpenerRef = useRef(null)
  const ideaMatchTimerRef = useRef(null)
  const acceptRecheckRef = useRef(null)
  const modalTemplateRef = useRef(modalTemplate)
  modalTemplateRef.current = modalTemplate
  const modalUnsupportedRef = useRef(modalUnsupportedKey)
  modalUnsupportedRef.current = modalUnsupportedKey
  const listInFlightRef = useRef(0)
  const projectsFolderRef = useRef({ status: 'unknown', source: '', path: '', defaultPath: '', message: '' })
  const [projectsFolder, setProjectsFolder] = useState(projectsFolderRef.current)
  projectsFolderRef.current = projectsFolder
  const folderLoadRef = useRef(null)
  const pendingCreateRef = useRef(false)
  const folderOpenerRef = useRef(null)
  const [folderDialogOpen, setFolderDialogOpen] = useState(false)
  const [folderDraft, setFolderDraft] = useState('')
  const [folderError, setFolderError] = useState('')
  const [folderBusy, setFolderBusy] = useState(false)
  const [folderMode, setFolderMode] = useState('choose')
  const [saveFallback, setSaveFallback] = useState('')
  const [manageOpen, setManageOpen] = useState(false)
  const [manageConfirm, setManageConfirm] = useState({ path: '', bulk: false })
  const [openExisting, setOpenExisting] = useState(false)
  const [existingPath, setExistingPath] = useState('')
  const [existingSelected, setExistingSelected] = useState('')
  const [existingBrowseNote, setExistingBrowseNote] = useState('')
  const [existingBrowseError, setExistingBrowseError] = useState('')
  const [lintConfirmPath, setLintConfirmPath] = useState('')
  const FOLDER_UNREACHABLE = 'Could not read the projects folder. Creating a project is unavailable until Defuzz can be reached.'

  const clearIdeaMatchTimer = () => {
    if (ideaMatchTimerRef.current !== null) {
      if (typeof ideaMatchTimerRef.current === 'function') ideaMatchTimerRef.current()
      else clearTimeout(ideaMatchTimerRef.current)
      ideaMatchTimerRef.current = null
    }
  }

  const clearAcceptRecheck = () => {
    if (acceptRecheckRef.current !== null) {
      if (typeof acceptRecheckRef.current === 'function') acceptRecheckRef.current()
      else clearTimeout(acceptRecheckRef.current)
      acceptRecheckRef.current = null
    }
  }

  const clearAuditPoll = () => {
    if (auditPollDisposeRef.current) {
      auditPollDisposeRef.current()
      auditPollDisposeRef.current = null
    }
  }

  useEffect(() => {
    disposedRef.current = false
    model.mount()
    live.mount()
    const handleDispose = () => {
      disposedRef.current = true
      auditScopeTokenRef.current += 1
      auditRunTokenRef.current += 1
      clearAuditPoll()
      clearIdeaMatchTimer()
      clearAcceptRecheck()
    }
    const unregister = ctx?.onDispose?.(handleDispose)
    return () => {
      handleDispose()
      if (typeof unregister === 'function') unregister()
      model.dispose()
      live.dispose()
    }
  }, [model, live, ctx])

  useEffect(() => { model.screen(initialScreen) }, [model, initialScreen])

  const navigateScreen = (screen, path) => {
    model.screen(screen)
    host.navigate(path)
  }

  const current = state || model.get()
  const liveCurrent = liveState || live.get()
  const splitVal = Math.max(20, Math.min(80, Number.isFinite(Number(current.settings?.split)) ? Number(current.settings.split) : 58))
  const setSplitVal = nextSplit => {
    const clamped = Math.max(20, Math.min(80, Math.round(Number(nextSplit))))
    model.settings({ ...model.get().settings, split: clamped })
  }

  const selectedProjectObj = current.projects.find(p => p.path === current.selected) || null
  const selectedIsExisting = selectedProjectObj?.template_id === 'existing'
  // Classification label for a non-existing selected project's footer only; never used as
  // editor or tree placeholder content.
  const activeTemplateSpec = V10_TEMPLATES.find(t => selectedProjectObj && t.id === projectBadgeFor(selectedProjectObj).template) || V10_TEMPLATES[0]
  // One card per canonical folder. Duplicate stored registrations (raw_path aliases) manage
  // separately, but the strip shows a single project and keeps the first display name.
  const canonicalFolder = project => project?.canonicalPath || project?.path || project?.name || ''
  const uniqueProjects = (() => {
    const seen = new Set()
    return current.projects.filter(project => {
      const key = canonicalFolder(project)
      if (!key) return true
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  })()
  const filteredProjects = uniqueProjects.filter(p => {
    const info = projectBadgeFor(p)
    const matchesTemplate = templateFilter === 'all' || info.template === templateFilter || (templateFilter === 'csharpier' && info.template === 'dotnet-golden')
    const matchesQuery = !projectSearch.trim() || `${p.name || ''} ${p.path || ''} ${info.template} ${info.badge}`.toLowerCase().includes(projectSearch.trim().toLowerCase())
    return matchesTemplate && matchesQuery
  })

  const manageRecords = []
  const seenRegistrations = new Set()
  for (const [recordKind, list] of [['current', current.projects], ['unavailable', current.unavailableProjects || []]]) {
    for (const project of list) {
      const key = project.registrationPath || project.path || `${project.name}|${project.folder_status}`
      if (seenRegistrations.has(key)) continue
      seenRegistrations.add(key)
      manageRecords.push({ ...project, recordKind })
    }
  }
  const nonverifiedRecords = current.coverage !== 'verified'
    ? manageRecords
    : manageRecords.filter(record => record.registered !== true || record.registrationStatus === 'could_not_verify')
  const missingCount = (current.unavailableProjects || []).filter(p => p.folder_status === 'missing').length
  const folderStatusText = status => status === 'not_directory' ? 'not a directory' : (status || 'unavailable')
  const manageConfirmPath = manageConfirm.bulk ? '' : manageConfirm.path

  const knownLockedFiles = selectedProjectObj?.locked_hashes && typeof selectedProjectObj.locked_hashes === 'object'
    ? Object.keys(selectedProjectObj.locked_hashes)
    : []
  const sessionCreatedFiles = selectedProjectObj?.path && Array.isArray(createdProjectFiles[selectedProjectObj.path])
    ? createdProjectFiles[selectedProjectObj.path]
    : []
  // A real, bounded file list is the only source of rows for an existing project. Its
  // reply belongs to one selection; anything else is discarded. Older registrations keep
  // their stored locked_hashes as the known-file fallback, never as guessed names.
  const activeTree = current.projectTree && current.projectTree.project === current.selected
    ? current.projectTree
    : { project: '', status: 'idle', files: [], coverage: '', truncated: false, omitted: 0, error: '' }
  const projectFiles = selectedProjectObj
    ? (selectedIsExisting
        ? (activeTree.status === 'ready' ? activeTree.files : [])
        : (Array.isArray(selectedProjectObj.files) && selectedProjectObj.files.length > 0
            ? selectedProjectObj.files
            : knownLockedFiles.length > 0
              ? knownLockedFiles
              : sessionCreatedFiles))
    : []
  const treeNoticeParts = []
  if (activeTree.truncated || activeTree.omitted > 0) {
    treeNoticeParts.push(`File list truncated: ${activeTree.files.length} shown${activeTree.omitted > 0 ? `, ${activeTree.omitted} omitted` : ''}.`)
  }
  if (activeTree.status === 'ready' && activeTree.coverage && activeTree.coverage !== 'verified') {
    treeNoticeParts.push('File list coverage could not be verified; it may be incomplete.')
  }
  if (activeTree.status === 'error') treeNoticeParts.push(`File list unavailable: ${activeTree.error}`)
  const treeNotice = selectedProjectObj
    ? (activeTree.status === 'loading' ? 'Loading file list…' : treeNoticeParts.join(' '))
    : ''
  const treeHierarchy = buildTreeFromPaths(projectFiles)
  let folderCount = 0
  let fileCount = 0
  const renderTreeNodes = (list, depth = 0) => list.flatMap(node => {
    if (node.children) {
      folderCount += 1
      const isExpanded = collapseAll ? false : collapsedFolders[node.path] !== true
      const folderBtn = jsxs('button', {
        type: 'button',
        className: 'tree-row folder',
        'data-folder': 'true',
        'data-path': node.path,
        'aria-expanded': isExpanded,
        onClick: () => {
          if (collapseAll) setCollapseAll(false)
          setCollapsedFolders(prev => ({ ...prev, [node.path]: isExpanded }))
        },
        style: { display: 'flex', alignItems: 'center', gap: '6px', padding: `4px 8px 4px ${8 + depth * 14}px`, textAlign: 'left', background: 'transparent', border: 0, color: 'var(--ui-text-primary)', fontFamily: 'var(--font-mono)', fontSize: '11px', cursor: 'pointer' },
        children: [
          jsx('span', { className: 'chevron', children: isExpanded ? '▾' : '▸' }),
          jsx('span', { className: 'file-icon folder-icon', children: '▱' }),
          jsx('span', { className: 'filename', children: node.name })
        ]
      }, `folder:${node.path}`)
      const childrenNodes = isExpanded
        ? jsx('div', { className: 'folder-children', children: renderTreeNodes(node.children, depth + 1) }, `children:${node.path}`)
        : null
      return [folderBtn, childrenNodes].filter(Boolean)
    }
    fileCount += 1
    const ext = node.name.split('.').pop()
    const icon = ext === 'ts' ? 'TS' : ext === 'md' ? 'M↓' : ext === 'json' ? '{}' : ext === 'yaml' || ext === 'yml' ? 'Y' : ext === 'py' ? 'Py' : ext === 'rs' ? 'R' : '≡'
    return [jsxs('button', {
      type: 'button',
      className: `tree-row${file === node.path ? ' selected' : ''}`,
      'data-path': node.path,
      'aria-pressed': file === node.path,
      onClick: () => {
        if (!current.selected) return
        const pending = model.preview(node.path)
        if (!pending) return
        setFile(node.path)
        setMdMode('preview')
        return pending
      },
      style: { display: 'flex', alignItems: 'center', gap: '6px', padding: `4px 8px 4px ${8 + depth * 14}px`, textAlign: 'left', background: file === node.path ? 'var(--ui-bg-secondary)' : 'transparent', border: `1px solid ${file === node.path ? 'var(--ui-accent)' : 'transparent'}`, borderRadius: '4px', color: 'var(--ui-text-primary)', fontFamily: 'var(--font-mono)', fontSize: '11px', cursor: 'pointer' },
      children: [
        jsx('span', { className: 'chevron', children: '' }),
        jsx('span', { className: 'file-icon', children: icon }),
        jsx('span', { className: 'filename', children: node.name })
      ]
    }, `file:${node.path}`)]
  })
  const renderedTreeItems = renderTreeNodes(treeHierarchy, 0)

  const pendingFocusRestoreRef = useRef(null)
  const restoreModalOpenerFocus = () => {
    const opener = modalOpenerRef.current
    modalOpenerRef.current = null
    if (opener) pendingFocusRestoreRef.current = opener
  }
  useEffect(() => {
    if (!newProjectModalOpen && !auditModalOpen && !storageModalOpen && !openExisting && pendingFocusRestoreRef.current) {
      const opener = pendingFocusRestoreRef.current
      pendingFocusRestoreRef.current = null
      opener.focus?.()
    }
  }, [newProjectModalOpen, auditModalOpen, storageModalOpen, openExisting])

  const handleModalKeyDown = (onClose) => e => {
    if (e?.key === 'Escape') {
      e.preventDefault?.()
      onClose()
    } else if (e?.key === 'Tab') {
      const target = e.currentTarget
      if (target && typeof target.querySelectorAll === 'function') {
        const items = [...target.querySelectorAll('button,input,select,[tabindex]')].filter(x => !x.disabled && x.tabIndex >= 0)
        if (items.length === 0) {
          e.preventDefault?.()
          return
        }
        const first = items[0]
        const last = items[items.length - 1]
        if (e.shiftKey && e.target === first) {
          e.preventDefault?.()
          last.focus?.()
        } else if (!e.shiftKey && e.target === last) {
          e.preventDefault?.()
          first.focus?.()
        }
      }
    }
  }

  const catalogEntries = current.catalog?.entries || []
  const chosenKey = current.selectedKitId ? `kit:${current.selectedKitId}` : modalTemplate ? `template:${modalTemplate}` : modalUnsupportedKey
  const chosenEntry = catalogEntries.find(e => catalogKey(e) === chosenKey && !e.coming_soon) || null
  const modalTplSpec = modalTemplate ? templateSpecFor(modalTemplate, chosenEntry) : null
  const choiceReady = Boolean(chosenEntry && (chosenEntry.kind === 'kit' ? current.selectedKitId : chosenEntry.kind === 'template' && modalTplSpec))
  const effectiveTplOptions = (() => {
    if (!modalTplSpec || current.matchFailed) return {}
    if (modalTplOptions.id === modalTplSpec.id && modalTplOptions.options) return modalTplOptions.options
    return fallbackTemplateOptions(modalTplSpec.id)
  })()
  const primaryOptionKey = Object.keys(effectiveTplOptions)[0] || null
  const primaryOptionSpec = primaryOptionKey ? effectiveTplOptions[primaryOptionKey] : null
  const adapterChoices = primaryOptionSpec && Array.isArray(primaryOptionSpec.choices)
    ? primaryOptionSpec.choices.map(c => [c, primaryOptionSpec.choiceLabels?.[c] || c])
    : []

  const modalChoiceKey = () => model.get().selectedKitId ? `kit:${model.get().selectedKitId}`
    : modalTemplateRef.current ? `template:${modalTemplateRef.current}` : modalUnsupportedRef.current
  // Clears a chosen row that a reloaded list no longer has, and says so in one line. The
  // row is never chosen again by itself if it comes back.
  const dropVanishedChoice = (key, title) => {
    if (!key || model.get().matchFailed) return
    if ((model.get().catalog?.entries || []).some(e => catalogKey(e) === key)) return
    const now = modalChoiceKey()
    if (now !== key && !(key.startsWith('kit:') && now === '')) return
    modalTemplateRef.current = ''
    modalUnsupportedRef.current = ''
    setModalTemplate('')
    setModalUnsupportedKey('')
    setModalAdapter('')
    setModalTplOptions({ id: '', options: null })
    if (key.startsWith('template:') && !model.get().busy && !model.get().partial) model.edit({})
    setChoiceGoneNotice(`“${title}” is no longer in the list; choose another row.`)
  }

  // Loads the pick-list and its "(suggested)" marks. It never changes which row is chosen,
  // except to clear a row the new list no longer has.
  const loadModalList = async () => {
    const key = modalChoiceKey()
    const before = (model.get().catalog?.entries || []).find(e => catalogKey(e) === key)
    const title = before?.title || key.slice(key.indexOf(':') + 1)
    const tplId = modalTemplateRef.current
    const tplSpec = tplId ? V10_TEMPLATES.find(t => t.id === tplId) : null
    const held = model.get().selectedKitId
      ? { building: model.get().answers?.building || 'other' }
      : tplSpec ? templateAnswers(tplSpec) : {}
    listInFlightRef.current += 1
    let res
    try { res = await model.match(held) } finally { listInFlightRef.current -= 1 }
    if (disposedRef.current || !res) return
    if (!modalTemplateRef.current) setModalAdapter('')
    dropVanishedChoice(key, title)
  }

  // The chosen template's options, from a separate request (see model.templateOptions);
  // the page's own options for the template are the fallback.
  const loadTemplateOptions = async tplId => {
    const spec = V10_TEMPLATES.find(t => t.id === tplId)
    const answers = spec ? templateAnswers(spec) : {}
    const fetched = Object.keys(answers).length ? await model.templateOptions(tplId, answers) : null
    if (disposedRef.current || modalTemplateRef.current !== tplId) return
    setModalTplOptions({ id: tplId, options: fetched })
    const opts = fetched || fallbackTemplateOptions(tplId)
    const optKey = Object.keys(opts)[0] || null
    const validChoices = optKey && Array.isArray(opts[optKey]?.choices) ? opts[optKey].choices : []
    setModalAdapter(optKey ? (opts[optKey]?.default || validChoices[0] || '') : '')
  }

  const pickModalEntry = async entry => {
    if (!entry || entry.coming_soon || model.get().busy || model.get().partial) return
    clearIdeaMatchTimer()
    setChoiceGoneNotice('')
    setModalTplOptions({ id: '', options: null })
    if (entry.kind === 'kit') {
      modalTemplateRef.current = ''
      modalUnsupportedRef.current = ''
      setModalTemplate('')
      setModalUnsupportedKey('')
      setModalAdapter('')
      return model.selectKit(entry.id)
    }
    if (entry.kind !== 'template') {
      modalTemplateRef.current = ''
      modalUnsupportedRef.current = catalogKey(entry)
      setModalTemplate('')
      setModalUnsupportedKey(catalogKey(entry))
      setModalAdapter('')
      return model.get().selectedKitId ? model.clearKit() : undefined
    }
    modalTemplateRef.current = entry.id
    modalUnsupportedRef.current = ''
    setModalTemplate(entry.id)
    setModalUnsupportedKey('')
    setModalAdapter(fallbackTemplateOptions(entry.id).http_adapter?.default || '')
    await model.clearKit()
    await discardModalProposalOnEdit({ answers: templateAnswers(templateSpecFor(entry.id, entry)) })
    await loadTemplateOptions(entry.id)
  }

  const applyProjectsRoot = result => {
    if (!result || typeof result !== 'object' || typeof result.source !== 'string') {
      const unchecked = { status: 'unchecked', source: '', path: '', defaultPath: '', message: '' }
      projectsFolderRef.current = unchecked
      setProjectsFolder(unchecked)
      return unchecked
    }
    const next = {
      status: 'ready',
      source: result.source,
      path: typeof result.path === 'string' ? result.path : '',
      defaultPath: typeof result.default_path === 'string' ? result.default_path : '',
      message: typeof result.message === 'string' ? result.message : ''
    }
    projectsFolderRef.current = next
    setProjectsFolder(next)
    return next
  }

  const openFolderDialog = (opener, prefill, mode) => {
    if (opener) folderOpenerRef.current = opener
    else if (!folderOpenerRef.current) folderOpenerRef.current = modalOpenerRef.current
    setFolderDraft(typeof prefill === 'string' ? prefill : '')
    setFolderMode(mode === 'change' ? 'change' : 'choose')
    setFolderError('')
    setSaveFallback('')
    setFolderDialogOpen(true)
  }

  const closeFolderDialog = () => {
    setFolderDialogOpen(false)
    setFolderError('')
    setSaveFallback('')
    pendingCreateRef.current = false
    const opener = folderOpenerRef.current
    folderOpenerRef.current = null
    if (opener && typeof opener.focus === 'function') opener.focus()
  }

  const ensureProjectsFolder = async (opener, askIfUnset = false) => {
    const run = (async () => {
      try {
        const result = await scopedRest('/scaffold/projects-root')
        if (disposedRef.current) return null
        const next = applyProjectsRoot(result)
        if (askIfUnset && next?.source === 'unset') openFolderDialog(opener, next.defaultPath, 'choose')
        return next
      } catch {
        if (disposedRef.current) return null
        const failed = { status: 'error', source: '', path: '', defaultPath: '', message: FOLDER_UNREACHABLE }
        projectsFolderRef.current = failed
        setProjectsFolder(failed)
        return failed
      }
    })()
    folderLoadRef.current = run
    return run
  }

  const saveProjectsRoot = path => {
    const params = { action: 'settings', key: 'defuzz', values: { projects_root: path } }
    if (typeof host.request === 'function') return host.request('plugins.manage', params)
    const gateway = typeof host.getGateway === 'function' ? host.getGateway() : null
    if (gateway && typeof gateway.request === 'function') return gateway.request('plugins.manage', params)
    return null
  }

  const openNewProjectModal = e => {
    const opener = e?.currentTarget || e?.target || null
    modalOpenerRef.current = opener
    setNewProjectModalOpen(true)
    setChoiceGoneNotice('')
    const folderPromise = ensureProjectsFolder(opener, true)
    if (!model.isMounted?.()) return folderPromise
    // While another request runs, the effect below loads the list once it ends.
    if (!model.get().busy && !model.get().partial) {
      return Promise.all([folderPromise, loadModalList()])
    }
    return folderPromise
  }

  const closeNewProjectModal = async () => {
    if (current.busy && !current.acceptJob) return
    clearIdeaMatchTimer()
    setNewProjectModalOpen(false)
    restoreModalOpenerFocus()
    // Closing while a polled job runs leaves the job to the server: no cancel, no discard.
    if (model.detachAccept()) { setActionNotice(CREATE_CLOSED_RUNNING_TEXT); return }
    if (!current.partial) {
      await model.discard()
    }
  }

  const discardModalProposalOnEdit = patch => {
    if (current.busy || current.partial) return undefined
    return model.edit(patch)
  }

  const acceptNewProjectModal = async () => {
    if (!modalNameValid || current.busy || current.partial || !choiceReady) return
    let folder = projectsFolderRef.current
    if (folder.status === 'unknown' || folder.status === 'loading') {
      if (folderLoadRef.current) {
        try { await folderLoadRef.current } catch { /* the folder status already records the failure */ }
      }
      folder = projectsFolderRef.current
    }
    if (folder.status === 'error') return
    if (folder.status === 'ready' && folder.source === 'unset') {
      pendingCreateRef.current = true
      if (!folderDialogOpen) openFolderDialog(folderOpenerRef.current || modalOpenerRef.current, folder.defaultPath, 'choose')
      return
    }
    if (folder.status === 'ready' && !folder.path && folder.source && folder.source !== 'unset') return
    const selectedKitId = model.get().selectedKitId
    const existingProp = model.get().proposal
    let prop = existingProp
    if (selectedKitId) {
      const matchesKitInputs = existingProp &&
        existingProp.kind === 'kit' &&
        existingProp.kit_id === selectedKitId &&
        model.get().name === modalName &&
        model.get().idea === modalIdea
      if (!matchesKitInputs) {
        model.edit({ name: modalName, answers: model.cleanKitAnswers(model.get().answers) })
        prop = await model.propose()
      }
    } else {
      const tpl = modalTplSpec
      const answers = templateAnswers(tpl)
      const resolvedOptions = effectiveTplOptions
      const optKey = Object.keys(resolvedOptions)[0] || null
      const optSpec = optKey ? resolvedOptions[optKey] : null
      const chosenAdapter = optKey
        ? (optSpec?.choices?.includes(modalAdapter) ? modalAdapter : (optSpec?.default || optSpec?.choices?.[0] || ''))
        : ''

      const matchesCurrentInputs = existingProp &&
        model.get().name === modalName &&
        model.get().idea === modalIdea &&
        (model.get().template?.template_id || model.get().template?.id) === tpl.id &&
        (!optKey || model.get().options?.[optKey] === chosenAdapter)

      if (!matchesCurrentInputs) {
        model.edit({ idea: modalIdea, name: modalName, answers })
        model.choose({
          template_id: tpl.id,
          id: tpl.id,
          name: tpl.label,
          options: resolvedOptions
        })
        if (optKey && chosenAdapter && optSpec?.choices?.includes(chosenAdapter)) {
          model.option(optKey, chosenAdapter)
        }
        prop = await model.propose()
      }
    }
    const activeProposal = prop?.proposal_id ? prop : model.get().proposal
    if (activeProposal?.proposal_id) {
      const acc = await model.accept()
      if (disposedRef.current) return
      // Cancelled (the dialog is as before Create) or the dialog was closed while it ran.
      if (model.get().acceptEnd === 'cancelled' || model.get().acceptEnd === 'detached') return
      if (model.get().acceptLost) return recoverLostAccept(modalName)
      const latest = model.get()
      const repos = acc?.repos || acc?.accepted_repos || []
      const hasUnregistered = repos.some(r => r.registration && r.registration !== 'registered')
      if (!latest.proposal && !latest.error && !latest.partial) {
        const isKitAccepted = Boolean(acc?.kind === 'kit' || acc?.placement === 'on' || activeProposal.kind === 'kit' || selectedKitId)
        const createdRepo = repos[0] || null
        const propRepo = Array.isArray(activeProposal.tree) ? activeProposal.tree[0] : (Array.isArray(activeProposal.repos) ? activeProposal.repos[0] : null)
        const createdName = createdRepo?.name || acc?.name || propRepo?.name || activeProposal.slug || latest.name || modalName
        const createdPath = isKitAccepted
          ? (acc?.dest || acc?.path || createdRepo?.path || propRepo?.dest || '')
          : (createdRepo?.path || propRepo?.dest || '')
        const createdFiles = Array.isArray(propRepo?.files) ? propRepo.files : (Array.isArray(propRepo?.tree) ? propRepo.tree : [])
        if (createdPath && createdFiles.length > 0) {
          setCreatedProjectFiles(prev => ({ ...prev, [createdPath]: createdFiles }))
        }
        modalTemplateRef.current = ''
        setModalTemplate('')
        setModalAdapter('')
        if (!hasUnregistered) {
          clearIdeaMatchTimer()
          setNewProjectModalOpen(false)
          restoreModalOpenerFocus()
        }
        setActionNotice(
          isKitAccepted
            ? `Project ${createdName} created${acc?.status ? ` (${acc.status})` : ''}${createdPath ? ` at ${createdPath}` : ''} · automatic file placement: ${acc?.placement || 'on'}.`
            : `Project ${createdName} created${acc?.status ? ` (${acc.status})` : ''}.`
        )
        await model.load()
      }
    }
  }

  // The accept answer was lost (or the server no longer has the proposal): the project may
  // exist anyway. Check the project list now and, for a lost answer, once more after a delay.
  const createdProjectNamed = name => (model.get().projects || [])
    .find(p => p.name === name || String(p.path || '').split('/').filter(Boolean).pop() === name) || null
  const finishRecoveredCreate = async project => {
    model.settleLostAccept({ created: true })
    modalTemplateRef.current = ''
    setModalTemplate('')
    setModalAdapter('')
    clearIdeaMatchTimer()
    setNewProjectModalOpen(false)
    restoreModalOpenerFocus()
    setActionNotice(`Project ${project.name || modalName} created.`)
    await model.load()
  }
  const recoverLostAccept = async name => {
    const lost = model.get().acceptLost
    await model.load()
    if (disposedRef.current) return
    const found = createdProjectNamed(name)
    if (found) return finishRecoveredCreate(found)
    if (lost === 'consumed' || lost === 'too-long') { model.settleLostAccept({ error: lost === 'consumed' ? CREATE_CONSUMED_TEXT : CREATE_TOO_LONG_TEXT }); return }
    const schedule = typeof ctx?.setTimeout === 'function' ? ctx.setTimeout : setTimeout
    clearAcceptRecheck()
    acceptRecheckRef.current = schedule(async () => {
      acceptRecheckRef.current = null
      if (disposedRef.current || model.get().acceptLost !== 'no-answer') return
      await model.load()
      if (disposedRef.current || model.get().acceptLost !== 'no-answer') return
      const again = createdProjectNamed(name)
      if (again) await finishRecoveredCreate(again)
    }, ACCEPT_RECHECK_MS)
  }

  const confirmProjectsFolder = async () => {
    if (folderBusy) return
    setFolderBusy(true)
    setFolderError('')
    setSaveFallback('')
    try {
      const validated = await scopedRest('/scaffold/projects-root?candidate=' + encodeURIComponent(folderDraft))
      if (disposedRef.current) return
      const candidate = validated && validated.candidate
      if (!candidate || candidate.valid !== true || typeof candidate.path !== 'string' || !candidate.path) {
        setFolderError(candidate && typeof candidate.message === 'string' && candidate.message
          ? candidate.message
          : 'That folder cannot be used. Choose another folder.')
        setFolderBusy(false)
        return
      }
      const savedPath = candidate.path
      let saveResult
      try {
        saveResult = await saveProjectsRoot(savedPath)
      } catch {
        if (!disposedRef.current) {
          setFolderError('Could not save the projects folder. Nothing was changed.')
          setFolderBusy(false)
        }
        return
      }
      if (saveResult == null) {
        setSaveFallback('hermes defuzz folder set ' + savedPath)
        setFolderError('Save this folder from your terminal, then check again.')
        setFolderBusy(false)
        return
      }
      if (saveResult.ok === false) {
        setFolderError('Could not save the projects folder. Nothing was changed.')
        setFolderBusy(false)
        return
      }
      const confirmed = await scopedRest('/scaffold/projects-root')
      if (disposedRef.current) return
      const confirmedPath = confirmed && typeof confirmed.path === 'string' ? confirmed.path : ''
      if (!confirmed || confirmed.source !== 'setting' || confirmedPath !== savedPath) {
        setFolderError('The folder was not saved. Check again before creating a project.')
        setFolderBusy(false)
        return
      }
      const next = {
        status: 'ready',
        source: 'setting',
        path: confirmedPath,
        defaultPath: typeof confirmed.default_path === 'string' ? confirmed.default_path : projectsFolderRef.current.defaultPath,
        message: typeof confirmed.message === 'string' ? confirmed.message : ''
      }
      projectsFolderRef.current = next
      setProjectsFolder(next)
      const shouldCreate = pendingCreateRef.current
      pendingCreateRef.current = false
      setFolderDialogOpen(false)
      setFolderError('')
      setSaveFallback('')
      setFolderBusy(false)
      const opener = folderOpenerRef.current
      folderOpenerRef.current = null
      if (!shouldCreate && opener && typeof opener.focus === 'function') opener.focus()
      if (shouldCreate) await acceptNewProjectModal()
    } catch {
      if (!disposedRef.current) {
        setFolderError(FOLDER_UNREACHABLE)
        setFolderBusy(false)
      }
    }
  }

  const checkProjectsFolderAgain = async () => {
    const next = await ensureProjectsFolder(folderOpenerRef.current, false)
    if (!next || disposedRef.current) return
    if (next.status === 'ready' && next.path && (next.source === 'setting' || next.source === 'env')) {
      const shouldCreate = pendingCreateRef.current
      pendingCreateRef.current = false
      setFolderDialogOpen(false)
      setFolderError('')
      setSaveFallback('')
      if (shouldCreate) await acceptNewProjectModal()
    }
  }

  const openExistingModal = e => {
    modalOpenerRef.current = e?.currentTarget || e?.target || null
    setExistingPath('')
    setExistingSelected('')
    setExistingBrowseNote('')
    setExistingBrowseError('')
    setOpenExisting(true)
    // Explicit open only: the list is never read on mount or in the background.
    return model.listExistingProjects()
  }

  const closeExistingModal = () => {
    setOpenExisting(false)
    setExistingPath('')
    setExistingSelected('')
    setExistingBrowseNote('')
    setExistingBrowseError('')
    restoreModalOpenerFocus()
  }

  // Browse is a convenience only: it supplies the path as this desktop sees it and never
  // reads the folder. The grant handle is not kept; the backend still validates the path.
  const browseExistingFolder = async () => {
    if (typeof ctx?.files?.requestFolder !== 'function') {
      setExistingBrowseError('Browse is not available on this desktop. Type the backend folder path instead.')
      return
    }
    setExistingBrowseError('')
    try {
      const picked = await ctx.files.requestFolder()
      if (!picked || !picked.ok || !picked.folder) return
      const pickedPath = typeof picked.folder === 'string' ? picked.folder : picked.folder.path
      if (typeof pickedPath !== 'string' || !pickedPath.trim()) {
        setExistingBrowseError('The picked folder did not report a path. Type the backend folder path instead.')
        return
      }
      setExistingPath(pickedPath)
      setExistingSelected('')
      setExistingBrowseNote(`Picked on this computer: ${pickedPath}. Use the path the backend machine can reach.`)
    } catch {
      setExistingBrowseError('The folder picker failed. Type the backend folder path instead.')
    }
  }

  const confirmOpenExisting = async () => {
    const manualPath = existingPath.trim()
    const row = !manualPath ? (current.existingList?.projects || []).find(project => project.path === existingSelected) : null
    const chosenPath = manualPath || row?.path || ''
    if (!chosenPath) {
      setExistingBrowseError('Choose a project or type the full folder path on the backend machine.')
      return
    }
    const result = await model.openExistingProject({ path: chosenPath, hermes_project_id: row?.id })
    if (result?.ok) {
      setActionNotice(`Opened ${result.path} as a reference. No files were copied or changed. Audit is read-only; lint can execute repository code.`)
      closeExistingModal()
    }
  }


  const openAuditModal = async (mode, e) => {
    modalOpenerRef.current = e?.currentTarget || e?.target || null
    const scopeToken = ++auditScopeTokenRef.current
    setAuditMode(mode)
    setAuditConsent(false)
    setAuditDisclosure('')
    setAuditActionState(prev => ({ ...prev, error: '' }))
    setAuditModalOpen(true)
    if (typeof ctx?.rest === 'function') {
      try {
        const res = await scopedRest('/audit/scope')
        if (disposedRef.current || auditScopeTokenRef.current !== scopeToken) return
        if (typeof res?.scope_disclosure === 'string' && res.scope_disclosure.trim()) {
          setAuditDisclosure(res.scope_disclosure)
        } else {
          throw new Error('Audit scope unavailable')
        }
      } catch (err) {
        if (disposedRef.current || auditScopeTokenRef.current !== scopeToken) return
        setAuditDisclosure('')
        setAuditConsent(false)
        setAuditActionState(prev => ({ ...prev, error: formatError(err) }))
      }
    }
  }

  const closeAuditModal = () => {
    auditScopeTokenRef.current += 1
    setAuditModalOpen(false)
    setAuditConsent(false)
    setAuditDisclosure('')
    restoreModalOpenerFocus()
  }

  const closeStorageModal = () => {
    setStorageModalOpen(false)
    restoreModalOpenerFocus()
  }

  const finalizeAuditRun = async (rId, statusSnap, runToken) => {
    const isRunCurrent = () => !disposedRef.current && auditRunTokenRef.current === runToken
    if (!isRunCurrent()) return
    clearAuditPoll()
    const st = statusSnap?.status || 'completed'
    let report = statusSnap?.report ?? null
    if (rId && st === 'completed') {
      try {
        const fetched = await scopedRest(`/audit/report?run_id=${encodeURIComponent(rId)}`)
        if (!isRunCurrent()) return
        report = fetched ?? report
      } catch (err) {
        if (!isRunCurrent()) return
        const msg = formatError(err)
        setAuditActionState(prev => ({ ...prev, busy: false, error: msg, runId: rId, status: statusSnap }))
        setActionNotice(`Audit report failed: ${msg}`)
        return
      }
    }
    if (!isRunCurrent()) return
    const cov = report?.coverage || statusSnap?.report?.coverage || ''
    setAuditActionState({ busy: false, error: '', runId: rId || '', status: statusSnap, report })
    if (st === 'completed') {
      setActionNotice(`${auditMode === 'quick' ? 'Quick' : 'Full'} audit finished.${cov && cov !== 'verified' && cov !== 'not_applicable' ? ' Some parts could not be checked.' : ''}`)
    } else {
      setActionNotice(`Audit (${auditMode}) ${st}${rId ? `: ${rId}` : ''}.`)
    }
    setAuditSummary({ runId: '', text: '', data: null, raw: false })
    if (!rId || st !== 'completed') return
    try {
      // Plain-language reading of the same run; any failure keeps the JSON view only.
      const fetched = await scopedRest(`/audit/summary?run_id=${encodeURIComponent(rId)}`)
      if (!isRunCurrent()) return
      const text = typeof fetched?.text === 'string' ? fetched.text : ''
      if (text || Array.isArray(fetched?.summary?.sections)) setAuditSummary({ runId: rId, text, data: fetched, raw: false })
    } catch {}
  }

  const pollAuditStatus = async (rId, runToken, fallbackStatus = null) => {
    const isRunCurrent = () => !disposedRef.current && auditRunTokenRef.current === runToken
    if (!isRunCurrent()) return
    const status = rId ? await scopedRest(`/audit/status?run_id=${encodeURIComponent(rId)}`) : fallbackStatus
    if (!isRunCurrent()) return
    const curStatus = status?.status || fallbackStatus?.status || 'completed'
    if (curStatus === 'running' || curStatus === 'queued') {
      setAuditActionState({ busy: true, error: '', runId: rId || '', status, report: null })
      setActionNotice(`Audit (${auditMode}) ${curStatus}${rId ? `: ${rId}` : ''}…`)
      if (typeof ctx?.setInterval === 'function' && rId && isRunCurrent()) {
        auditPollDisposeRef.current = ctx.setInterval(async () => {
          if (!isRunCurrent()) {
            clearAuditPoll()
            return
          }
          try {
            const polled = await scopedRest(`/audit/status?run_id=${encodeURIComponent(rId)}`)
            if (!isRunCurrent()) return
            const pSt = polled?.status || 'running'
            if (pSt === 'running' || pSt === 'queued') {
              setAuditActionState(prev => ({ ...prev, runId: rId, status: polled }))
              setActionNotice(`Audit (${auditMode}) ${pSt}: ${rId}…`)
            } else {
              await finalizeAuditRun(rId, polled, runToken)
            }
          } catch (pollErr) {
            if (!isRunCurrent()) return
            clearAuditPoll()
            const msg = formatError(pollErr)
            setAuditActionState(prev => ({ ...prev, busy: false, runId: rId, error: msg }))
            setActionNotice(`Audit poll failed: ${msg}`)
          }
        }, 1000)
      }
    } else {
      await finalizeAuditRun(rId, status, runToken)
    }
  }

  const retryAuditStatus = async () => {
    const rId = auditActionState.runId || auditActionState.status?.run_id
    if (!rId || auditActionState.busy || disposedRef.current) return
    clearAuditPoll()
    const runToken = ++auditRunTokenRef.current
    const isRunCurrent = () => !disposedRef.current && auditRunTokenRef.current === runToken
    setAuditActionState(prev => ({ ...prev, busy: true, error: '', runId: rId }))
    try {
      await pollAuditStatus(rId, runToken, auditActionState.status)
    } catch (err) {
      if (!isRunCurrent()) return
      clearAuditPoll()
      const msg = formatError(err)
      setAuditActionState(prev => ({ ...prev, busy: false, runId: rId, error: msg }))
      setActionNotice(`Audit error: ${msg}`)
    }
  }

  const runModalAudit = async () => {
    if (!auditConsent || !auditDisclosure || auditActionState.busy || disposedRef.current) return
    clearAuditPoll()
    auditScopeTokenRef.current += 1
    const runToken = ++auditRunTokenRef.current
    const isRunCurrent = () => !disposedRef.current && auditRunTokenRef.current === runToken
    setAuditActionState(prev => ({ ...prev, busy: true, error: '' }))
    let rId = ''
    try {
      const body = { selected_projects: current.selected ? [current.selected] : [], ...(auditMode === 'quick' ? { quick: true } : {}) }
      const started = await scopedRest('/audit/start', { method: 'POST', body })
      if (!isRunCurrent()) return
      rId = started?.run_id || ''
      setAuditActionState(prev => ({ ...prev, busy: true, error: '', runId: rId, status: started, report: null }))
      setAuditModalOpen(false)
      setAuditConsent(false)
      setAuditDisclosure('')
      restoreModalOpenerFocus()
      await pollAuditStatus(rId, runToken, started)
    } catch (err) {
      if (!isRunCurrent()) return
      clearAuditPoll()
      const msg = formatError(err)
      setAuditActionState(prev => ({ ...prev, busy: false, ...(rId ? { runId: rId } : {}), error: msg }))
      if (rId) setActionNotice(`Audit error: ${msg}`)
    }
  }

  const auditSummaryCurrent = auditSummary.runId === (auditActionState.runId || '')
  const auditModel = auditSummaryCurrent ? auditViewModel(auditSummary.data, auditActionState.report) : null
  const auditSummaryShown = auditSummaryCurrent && (!!auditSummary.text || !!auditModel)
  const activeLintState = (current.selected && footerLintByProject[current.selected]) || { busy: false, error: '', result: null, job: null }

  const runFooterLint = async () => {
    const targetProject = current.selected
    if (!targetProject || current.busy || footerLintRef.current[targetProject]?.busy || activeLintState.busy || disposedRef.current) return
    // An adopted-by-reference folder is untrusted: lint may run its tooling and write files.
    // It only runs after an explicit second click for this exact selected path.
    if (selectedIsExisting && lintConfirmPath !== targetProject) {
      setLintConfirmPath(targetProject)
      setActionNotice('Lint can execute repository code and write files. Click ▶ again to confirm for this existing project.')
      return
    }
    setLintConfirmPath('')
    const existingJob = footerLintRef.current[targetProject]?.job ?? activeLintState.job ?? null
    footerLintRef.current[targetProject] = { ...(footerLintRef.current[targetProject] || {}), busy: true, job: existingJob }
    setFooterLintByProject(prev => ({
      ...prev,
      [targetProject]: { ...(prev[targetProject] || { result: null, job: existingJob }), busy: true, error: '' }
    }))
    try {
      const mode = current.settings?.lint_mode || 'both'
      const res = existingJob
        ? await scopedRest(`/lint/${encodeURIComponent(existingJob)}`)
        : await scopedRest('/lint', { method: 'POST', body: { project: targetProject, mode } })
      if (disposedRef.current) return
      const nextJob = res?.state === 'running' ? res.job_id : null
      const isFailed = res?.state === 'failed' || (res?.ok === false && Boolean(res?.error))
      const failMsg = isFailed ? String(res.error || 'Lint execution failed') : ''
      footerLintRef.current[targetProject] = { busy: false, job: nextJob, result: res, error: failMsg }
      setFooterLintByProject(prev => ({
        ...prev,
        [targetProject]: { busy: false, error: failMsg, result: res, job: nextJob }
      }))
      if (model.get().selected === targetProject) {
        if (nextJob) setActionNotice(`Lint running (${nextJob})…`)
        else if (isFailed) setActionNotice(`Lint failed: ${failMsg}`)
        else setActionNotice('Lint completed.')
      }
    } catch (err) {
      if (disposedRef.current) return
      const msg = formatError(err)
      footerLintRef.current[targetProject] = { ...(footerLintRef.current[targetProject] || {}), busy: false, job: existingJob, error: msg }
      setFooterLintByProject(prev => ({
        ...prev,
        [targetProject]: { ...(prev[targetProject] || { result: null }), busy: false, job: existingJob, error: msg }
      }))
      if (model.get().selected === targetProject) {
        setActionNotice(`Lint error: ${msg}`)
      }
    }
  }

  const activeChecksKey = current.selected || ''
  const activeChecksState = footerChecksByProject[activeChecksKey] || { busy: false, error: '', result: null }

  const runFooterChecks = async () => {
    const targetProject = current.selected || ''
    if (current.busy || footerChecksRef.current[targetProject]?.busy || activeChecksState.busy || disposedRef.current) return
    footerChecksRef.current[targetProject] = { ...(footerChecksRef.current[targetProject] || {}), busy: true }
    setFooterChecksByProject(prev => ({
      ...prev,
      [targetProject]: { ...(prev[targetProject] || { result: null }), busy: true, error: '' }
    }))
    try {
      const toolsStatus = await scopedRest('/tools/status')
      if (disposedRef.current) return
      const lockStatus = targetProject
        ? await scopedRest(`/tools-lock?project=${encodeURIComponent(targetProject)}`)
        : null
      if (disposedRef.current) return
      const combined = { tools: toolsStatus, ...(lockStatus ? { lock: lockStatus } : {}) }
      const toolsFailed = toolsStatus?.state === 'failed' || (toolsStatus?.ok === false && Boolean(toolsStatus?.error)) || (!toolsStatus?.items && Boolean(toolsStatus?.error))
      const lockFailed = lockStatus?.state === 'failed' || (lockStatus?.ok === false && Boolean(lockStatus?.error)) || (!lockStatus?.lock && Boolean(lockStatus?.error))
      const isFailed = toolsFailed || lockFailed
      const failMsg = isFailed ? String((lockFailed ? lockStatus?.error : toolsStatus?.error) || 'Checks failed') : ''
      footerChecksRef.current[targetProject] = { busy: false, result: combined, error: failMsg }
      setFooterChecksByProject(prev => ({
        ...prev,
        [targetProject]: { busy: false, error: failMsg, result: combined }
      }))
      if ((model.get().selected || '') === targetProject) {
        if (isFailed) setActionNotice(`Checks failed: ${failMsg}`)
        else setActionNotice('Checks completed.')
      }
    } catch (err) {
      if (disposedRef.current) return
      const msg = formatError(err)
      footerChecksRef.current[targetProject] = { ...(footerChecksRef.current[targetProject] || {}), busy: false, error: msg }
      setFooterChecksByProject(prev => ({
        ...prev,
        [targetProject]: { ...(prev[targetProject] || { result: null }), busy: false, error: msg }
      }))
      if ((model.get().selected || '') === targetProject) {
        setActionNotice(`Checks error: ${msg}`)
      }
    }
  }

  const modalNameValid = /^[a-z][a-z0-9-]{0,47}$/.test(modalName) && !current.projects.some(p => (p.name || p.path) === modalName)
  const serverProposalRepo = Array.isArray(current.proposal?.tree) && current.proposal.tree[0] && typeof current.proposal.tree[0] === 'object'
    ? current.proposal.tree[0]
    : (Array.isArray(current.proposal?.repos) && current.proposal.repos[0] ? current.proposal.repos[0] : null)
  const formatKitFolderTree = tree => {
    if (!Array.isArray(tree)) return ''
    const folders = tree.filter(entry => typeof entry === 'string' && entry.endsWith('/'))
    const lines = folders.slice(0, 60).map(entry => {
      const parts = entry.replace(/^\/+|\/+$/g, '').split('/').filter(Boolean)
      const depth = Math.max(0, parts.length - 1)
      return `${'  '.repeat(depth)}${entry}`
    })
    if (folders.length > 60) lines.push(`… and ${folders.length - 60} more`)
    return lines.join('\n')
  }
  const selectedKitSummary = current.selectedKitId ? (current.kitPreview?.kit?.summary || chosenEntry?.line || '') : ''
  const proposalTreeText = current.selectedKitId
    ? formatKitFolderTree(current.kitPreview?.tree || serverProposalRepo?.files || [])
    : serverProposalRepo
      ? `${serverProposalRepo.name || modalName}/\n${(serverProposalRepo.files || serverProposalRepo.tree || []).map(f => `├── ${f}`).join('\n')}`
      : Array.isArray(current.proposal?.tree) && typeof current.proposal.tree[0] === 'string'
        ? `${current.proposal.slug || current.proposal.name || modalName}/\n${current.proposal.tree.map(f => `├── ${f}`).join('\n')}`
        : modalTplSpec
          ? `${modalName}/\n${(modalTplSpec.previewTree || []).map(f => `├── ${f}`).join('\n')}`
          : 'Choose a row in the list to see what it creates.'
  const proposalDestinationText = serverProposalRepo?.dest || projectDestinationText(projectsFolder.status === 'error' ? '' : projectsFolder.path, modalName)

  const isMdFile = /\.md$/i.test(file)
  const hasMatchingPreview = Boolean(current.preview && (!current.preview.path || current.preview.path === file))
  const rawFileContent = hasMatchingPreview
    ? (current.preview.content ?? JSON.stringify(current.preview, null, 2))
    : current.previewPath === file
      ? `Loading ${file}…`
      : 'Select a file to preview its contents.'
  const showMdPreview = isMdFile && mdMode === 'preview'
  const anyModalOpen = Boolean(newProjectModalOpen || auditModalOpen || storageModalOpen || folderDialogOpen || openExisting)
  const modalLocked = Boolean(current.busy || current.partial)
  const catalogNotice = current.catalog?.notice || ''
  const catalogSuggested = current.catalog?.suggested || []
  const catalogGroups = catalogEntries.reduce((groups, entry) => {
    const id = entry.group || entry.group_title
    const group = groups.find(g => g.id === id)
    if (group) group.entries.push(entry)
    else groups.push({ id, title: entry.group_title || auditSafe(entry.group) || 'Other', entries: [entry] })
    return groups
  }, [])
  const listUnavailable = Boolean(current.matchFailed || (current.catalog && catalogEntries.length === 0))
  // The dialog opened while another request ran: load the list once the model is free.
  useEffect(() => {
    if (!newProjectModalOpen || current.busy || current.partial || current.catalog || current.matchFailed) return
    if (listInFlightRef.current > 0 || !model.isMounted?.()) return
    loadModalList()
  }, [newProjectModalOpen, current.busy, current.partial, current.catalog, current.matchFailed])
  // A list that does not arrive: offer "Check again" next to the loading text after a short delay.
  const listLoading = Boolean(newProjectModalOpen && !current.catalog && !listUnavailable)
  useEffect(() => {
    if (!listLoading) { setListSlow(false); return undefined }
    const schedule = typeof ctx?.setTimeout === 'function' ? ctx.setTimeout : setTimeout
    const handle = schedule(() => { if (!disposedRef.current) setListSlow(true) }, LIST_SLOW_MS)
    return () => { if (typeof handle === 'function') handle(); else clearTimeout(handle) }
  }, [listLoading])
  const onChoiceKeyDown = e => {
    const selectableEntries = catalogEntries.filter(entry => !entry.coming_soon)
    if ((e?.key !== 'Home' && e?.key !== 'End') || modalLocked || selectableEntries.length === 0) return undefined
    e.preventDefault?.()
    const radios = [...(e.currentTarget?.querySelectorAll?.('input[type=radio]') || [])].filter(r => !r.disabled)
    radios[e.key === 'Home' ? 0 : radios.length - 1]?.focus?.()
    return pickModalEntry(selectableEntries[e.key === 'Home' ? 0 : selectableEntries.length - 1])
  }
  const choiceRow = entry => {
    const key = catalogKey(entry)
    const checked = !entry.coming_soon && key === chosenKey
    const index = catalogEntries.indexOf(entry)
    const inputId = choiceDomId('choice', index, key)
    const lineId = choiceDomId('choice-line', index, key)
    return jsxs('div', { 'data-testid': choiceDomId('choice-row', index, key), style: { display: 'grid', gridTemplateColumns: 'auto minmax(0, 1fr)', columnGap: '8px', alignItems: 'start', padding: '6px 8px', border: `1px solid ${checked ? 'var(--ui-accent)' : 'var(--ui-stroke-secondary)'}`, borderRadius: '6px' }, children: [
      jsx('input', { type: 'radio', id: inputId, name: 'new-project-choice', value: key, checked, disabled: modalLocked || entry.coming_soon === true, 'aria-disabled': entry.coming_soon ? 'true' : undefined, tabIndex: entry.coming_soon ? -1 : undefined, 'aria-describedby': entry.line ? lineId : undefined, onChange: () => pickModalEntry(entry) }),
      jsxs('label', { htmlFor: inputId, style: { fontWeight: 600, overflowWrap: 'anywhere', ...(entry.coming_soon ? { color: 'var(--ui-text-secondary)' } : {}) }, children: [entry.title, entry.coming_soon ? ' — Coming soon' : catalogSuggested.includes(key) ? ' (suggested)' : null] }),
      entry.line ? jsx('span', { id: lineId, style: { ...mutedText, gridColumn: '2', overflowWrap: 'anywhere' }, children: entry.line }) : null
    ] }, key)
  }

  const measureColumnsWidth = e => {
    const candidates = [
      e?.currentTarget?.parentElement,
      e?.target?.parentElement,
      e?.currentTarget,
      e?.target
    ]
    for (const el of candidates) {
      const w = Number(el?.getBoundingClientRect?.()?.width || el?.clientWidth || 0)
      if (Number.isFinite(w) && w > 20) return w
    }
    return 0
  }

  return jsx(ScrollArea, { style: { height: '100%' }, children: jsxs('main', { className: 'app', style: panelStyle, children: [
    jsxs('header', { className: 'top', 'data-testid': 'v10-top-bar', inert: anyModalOpen ? true : undefined, 'aria-hidden': anyModalOpen ? 'true' : undefined, style: { display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap', borderBottom: '1px solid var(--ui-stroke-secondary)', paddingBottom: '12px' }, children: [
      jsx('img', { className: 'locked-banner', 'data-testid': 'v10-locked-banner', src: DEFUZZ_BANNER_DATA_URL, alt: 'Project Defuzz', width: 688, height: 192, style: { height: '64px', width: 'auto', objectFit: 'contain' } }),
      jsx('span', { className: 'spacer', style: { flex: 1 } }),
      jsx(Button, { id: 'open-existing-project', 'data-testid': 'open-existing-project-btn', 'aria-label': 'Open an existing Hermes project', onClick: openExistingModal, children: 'Open existing project' }),
      jsx(Button, { id: 'start-project', 'data-testid': 'start-project-modal-btn', className: 'primary', 'aria-label': 'Open Start project modal', onClick: openNewProjectModal, children: '+ Start project' }),
      jsx(Button, { id: 'settings-button', 'data-testid': 'settings-button', className: 'steel-settings', 'aria-label': 'Settings', onClick: () => navigateScreen(current.screen === 'settings' ? 'main' : 'settings', current.screen === 'settings' ? ROUTE_PATH : `${ROUTE_PATH}/settings`), children: 'Settings' }),
      jsx(Button, { id: 'inspector-button', 'data-testid': 'inspector-button', 'aria-label': 'Adopted copy inspector', onClick: () => navigateScreen(current.screen === 'adopt' ? 'main' : 'adopt', current.screen === 'adopt' ? ROUTE_PATH : `${ROUTE_PATH}/inspector`), children: 'Adopted copies' })
    ] }),
    jsx('div', { role: 'status', inert: anyModalOpen ? true : undefined, 'aria-hidden': anyModalOpen ? 'true' : undefined, children: current.error || (current.busy ? 'Request pending…' : '') }),
    current.screen === 'settings' ? jsx('div', { inert: anyModalOpen ? true : undefined, 'aria-hidden': anyModalOpen ? 'true' : undefined, children: jsx(SettingsView, { ctx, model, state: current, project: current.selected, auditMode, scopedRest, live, liveState: liveCurrent, projectState: { projects: current.projects, selected: current.selected, coverage: current.coverage } }) }) :
    current.screen === 'adopt' ? jsxs('div', { inert: anyModalOpen ? true : undefined, 'aria-hidden': anyModalOpen ? 'true' : undefined, children: [
      jsx(Button, { id: 'inspector-back-button', 'data-testid': 'inspector-back-button', 'aria-label': 'Back to workspace', onClick: () => navigateScreen('main', ROUTE_PATH), children: '← Workspace' }),
      jsx(AdoptBeforeAfterPage, { ctx })
    ] }) :
    jsxs('section', { id: 'workspace', className: 'workspace', 'aria-label': 'Projects', 'data-testid': 'project-workspace-box', 'data-color-scheme': 'no-red-green', inert: anyModalOpen ? true : undefined, 'aria-hidden': anyModalOpen ? 'true' : undefined,
      style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '12px', padding: '16px', color: 'var(--ui-text-primary)', display: 'flex', flexDirection: 'column', gap: '10px' }, children: [
      jsxs('div', { className: 'projects-toolbar', 'data-testid': 'projects-toolbar', style: { display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }, children: [
        jsxs('h1', { style: { margin: 0, fontSize: '16px' }, children: ['Projects ', jsx('span', { id: 'project-count', className: 'project-count', children: String(uniqueProjects.length) })] }),
        jsx('span', { style: { flex: 1 } }),
        jsx('input', { id: 'project-search', type: 'text', 'aria-label': 'Filter projects', placeholder: 'Filter projects…', value: projectSearch, onChange: e => setProjectSearch(e.target.value), style: { padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--ui-stroke-secondary)', background: 'transparent', color: 'var(--ui-text-primary)' } }),
        action('Refresh projects', () => model.load(), Boolean(current.busy || current.forgetting)),
        action('Load workspace preferences', () => model.loadSettings(), current.busy),
        action('Save workspace preferences', () => model.saveSettings(), current.busy || !current.loaded),
        jsx(Button, {
          id: 'manage-projects-toggle',
          'data-testid': 'manage-projects-toggle',
          'aria-expanded': manageOpen,
          'aria-controls': 'manage-projects-panel',
          disabled: Boolean(current.busy || current.forgetting),
          onClick: () => {
            setManageConfirm({ path: '', bulk: false })
            setManageOpen(open => !open)
          },
          children: manageOpen ? 'Hide project management' : 'Manage projects'
        })
      ] }),
      jsxs('div', { 'data-testid': 'v10-template-filter-pills', role: 'group', 'aria-label': 'Template and tool filters', style: { display: 'flex', gap: '6px', flexWrap: 'wrap' }, children: [
        jsx(Button, { 'data-testid': 'filter-pill-all', 'aria-pressed': templateFilter === 'all', onClick: () => setTemplateFilter('all'), children: `All templates (${V10_TEMPLATES.length})` }),
        ...V10_TEMPLATES.map(t => jsx(Button, {
          'data-testid': `filter-pill-${t.id}`,
          'aria-pressed': templateFilter === t.id,
          onClick: () => setTemplateFilter(t.id),
          children: `${t.badge} · ${t.id}`
        }, t.id)),
        jsx(Button, { 'data-testid': 'filter-pill-csharpier', 'aria-pressed': templateFilter === 'csharpier', onClick: () => setTemplateFilter('csharpier'), children: 'C# · csharpier' })
      ] }),
      jsx('div', { id: 'project-cards', className: 'project-cards', 'data-testid': 'v10-project-strip', 'aria-label': 'Current projects', style: { display: 'flex', gap: '6px', overflowX: 'auto', paddingBottom: '8px', borderBottom: '1px solid var(--ui-stroke-secondary)' }, children: filteredProjects.map(project => {
        const info = projectBadgeFor(project)
        const displayName = project.name || project.path
        const isSelected = current.selected === project.path && Boolean(project.path)
        const accessiblePath = project.canonicalPath || project.path
        const registrationNote = project.registrationPath && project.registrationPath !== accessiblePath
          ? ` (registered as ${project.registrationPath})`
          : ''
        return jsx(Button, {
          className: 'project-card',
          'data-project': displayName,
          'data-template': info.template,
          'aria-pressed': isSelected,
          'aria-label': `${displayName} — ${accessiblePath || 'no path'}${registrationNote}`,
          title: project.path || project.name,
          disabled: !project.registered || !project.path,
          onClick: () => {
            model.select(project.path)
            setActionNotice('')
          },
          style: { display: 'inline-flex', alignItems: 'center', gap: '6px', height: '32px', padding: '4px 10px' },
          children: jsx('span', { className: 'project-name', children: displayName })
        }, project.canonicalPath || project.path || displayName)
      }) }),
      current.projectsLoaded && current.coverage !== 'verified' ? jsx('p', {
        id: 'projects-coverage-warning',
        'data-testid': 'projects-coverage-warning',
        role: 'status',
        style: { margin: 0, color: 'var(--ui-text-secondary)', fontSize: '11px' },
        children: 'Could not verify registry coverage; this list may be incomplete. Nothing here proves that an unlisted project is gone.'
      }) : null,
      filteredProjects.length === 0 && current.projects.length > 0 ? jsx('div', { id: 'no-project-match', className: 'no-match', children: 'No matching projects.' }) : null,
      !current.projects.length ? jsx('p', { children: current.busy ? 'Loading projects…' : current.projectsLoaded ? 'No projects returned. Unknown coverage is not proof that no projects exist.' : 'Projects not loaded. Refresh to read active-profile registrations.' }) : null,
      manageOpen ? jsxs('section', {
        id: 'manage-projects-panel',
        'data-testid': 'manage-projects-panel',
        'aria-label': 'Manage projects',
        'data-confirming': manageConfirmPath || (manageConfirm.bulk ? 'bulk' : undefined),
        style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', padding: '10px', display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' },
        children: [
          jsx('h2', { style: { margin: 0, fontSize: '13px' }, children: 'Manage projects' }),
          jsx('p', { style: { margin: 0, color: 'var(--ui-text-secondary)' }, children: 'Every registration Defuzz knows about. Forgetting removes the registry record only; folders on disk are never deleted.' }),
          current.coverage !== 'verified' ? jsxs('div', {
            id: 'manage-coverage-warning',
            'data-testid': 'manage-coverage-warning',
            role: 'status',
            style: { margin: 0, color: 'var(--ui-text-secondary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', padding: '6px 8px' },
            children: [
              jsx('strong', { children: 'Could not verify registry coverage. ' }),
              jsx('span', { children: `These registrations are unknown, not absent: ${nonverifiedRecords.length ? nonverifiedRecords.map(record => record.registrationPath || record.path || record.name).join(', ') : '(none listed)'}` })
            ]
          }) : null,
          jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }, children: [
            jsx('span', { children: `${current.projects.length} current · ${(current.unavailableProjects || []).length} unavailable` }),
            missingCount > 0 ? (manageConfirm.bulk ? jsxs('span', { 'data-testid': 'bulk-forget-confirm', style: { display: 'inline-flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }, children: [
              jsx('span', { children: `Remove ${missingCount} missing project${missingCount === 1 ? '' : 's'} from Defuzz? This removes them from Defuzz only; files untouched.` }),
              jsx(Button, { 'data-testid': 'confirm-forget-missing', disabled: Boolean(current.forgetting), onClick: () => { setManageConfirm({ path: '', bulk: false }); return model.forgetMissing() }, children: `Forget ${missingCount} missing` }),
              jsx(Button, { 'data-testid': 'cancel-forget-missing', onClick: () => setManageConfirm({ path: '', bulk: false }), children: 'Cancel' })
            ] }) : jsx(Button, { 'data-testid': 'forget-missing-projects', onClick: () => setManageConfirm({ path: '', bulk: true }), children: `Forget missing (${missingCount})` })) : null
          ] }),
          jsx('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px' }, children: manageRecords.length ? manageRecords.map(record => {
            const registrationPath = record.registrationPath || record.path || ''
            const confirming = manageConfirmPath && manageConfirmPath === registrationPath
            return jsxs('div', {
              'data-testid': 'manage-project-row',
              'data-path': registrationPath,
              'data-registration-path': registrationPath,
              'data-canonical-path': record.canonicalPath || record.path || '',
              'data-folder-status': record.folder_status,
              style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', padding: '6px 8px', display: 'flex', flexDirection: 'column', gap: '4px' },
              children: [
                jsxs('div', { style: { display: 'flex', alignItems: 'baseline', gap: '8px', flexWrap: 'wrap' }, children: [
                  jsx('strong', { className: 'manage-project-name', children: record.name }),
                  jsx('code', { style: { overflowWrap: 'anywhere' }, children: registrationPath || '(no path)' }),
                  record.canonicalPath && record.canonicalPath !== registrationPath
                    ? jsx('span', { style: { color: 'var(--ui-text-secondary)', overflowWrap: 'anywhere' }, children: `Canonical folder: ${record.canonicalPath}` })
                    : null,
                  jsx('span', { className: 'manage-project-folder-status', style: { color: 'var(--ui-text-secondary)' }, children: `Folder: ${folderStatusText(record.folder_status)}` })
                ] }),
                confirming ? jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }, children: [
                  jsx('span', { children: 'Remove this project from Defuzz? This removes it from Defuzz only; files untouched.' }),
                  jsx(Button, { 'data-testid': 'confirm-forget-project', disabled: Boolean(current.forgetting), onClick: () => { setManageConfirm({ path: '', bulk: false }); return model.forget(registrationPath) }, children: 'Forget' }),
                  jsx(Button, { 'data-testid': 'cancel-forget-project', onClick: () => setManageConfirm({ path: '', bulk: false }), children: 'Cancel' })
                ] }) : jsx(Button, {
                  'data-testid': 'forget-project',
                  'aria-label': `Forget ${record.name} — exact registration ${registrationPath || 'unavailable'}`,
                  disabled: Boolean(current.forgetting) || !registrationPath,
                  onClick: () => setManageConfirm({ path: registrationPath, bulk: false }),
                  children: current.forgetting === registrationPath ? 'Forgetting…' : 'Forget'
                })
              ]
            }, `${record.recordKind}|${registrationPath}|${record.folder_status}`)
          }) : jsx('p', { style: { margin: 0 }, children: 'No project registrations returned.' }) }),
          current.forgetNotice ? jsx('p', { id: 'forget-notice', role: 'status', style: { margin: 0, color: 'var(--ui-text-secondary)' }, children: current.forgetNotice }) : null
        ]
      }) : null,
      jsxs('div', { className: 'columns', style: { '--tree-size': `${splitVal}%`, '--split': `${splitVal}%`, display: 'grid', gap: '0px', gridTemplateColumns: `minmax(0, ${splitVal}%) 7px minmax(0, 1fr)`, border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', overflow: 'hidden' }, children: [
        jsxs('section', { className: 'explorer', 'aria-label': 'Project explorer', style: { minWidth: 0, padding: '10px', display: 'flex', flexDirection: 'column', gap: '6px' }, children: [
          jsxs('div', { className: 'pane-head', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' }, children: [
            jsx('h2', { id: 'active-project-title', style: { margin: 0, fontSize: '13px' }, children: selectedProjectObj ? (selectedProjectObj.name || selectedProjectObj.path) : 'No project selected' }),
            jsx(Button, { id: 'collapse-all', onClick: () => {
              const nextCollapse = !collapseAll
              setCollapseAll(nextCollapse)
              setCollapsedFolders({})
            }, children: collapseAll ? 'Expand all' : 'Collapse all' }),
            selectedIsExisting ? jsx(Button, { 'data-testid': 'tree-reload', disabled: activeTree.status === 'loading', onClick: () => model.loadTree(), children: activeTree.status === 'loading' ? 'Loading…' : 'Reload file list' }) : null
          ] }),
          treeNotice ? jsx('div', { 'data-testid': 'project-tree-notice', role: 'status', style: { fontSize: '11px', color: 'var(--ui-text-secondary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px', padding: '4px 8px' }, children: treeNotice }) : null,
          jsx('div', { id: 'tree', className: 'tree', role: 'tree', 'aria-label': 'Project file tree', style: { display: 'flex', flexDirection: 'column', gap: '2px' }, children: renderedTreeItems.length > 0 ? renderedTreeItems : jsx('div', { 'data-testid': 'file-listing-unavailable', style: { padding: '6px 4px', fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: selectedProjectObj ? (selectedIsExisting && activeTree.status === 'ready' ? 'No files were listed for this project.' : 'File listing unavailable for this project.') : 'File listing unavailable — select a registered project.' }) }),
          jsxs('div', { className: 'tree-footer', style: { display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--ui-text-secondary)', paddingTop: '6px', borderTop: '1px solid var(--ui-stroke-secondary)' }, children: [
            jsx('span', { id: 'tree-total', children: `${fileCount} files · ${folderCount} folders` }),
            jsx('span', { 'data-testid': 'tree-coverage', children: selectedIsExisting
              ? (activeTree.status === 'ready'
                  ? (activeTree.coverage === 'verified' ? 'File list verified' : 'File list unverified')
                  : activeTree.status === 'error' ? 'File list unavailable' : activeTree.status === 'loading' ? 'File list loading' : 'File list not loaded')
              : (selectedProjectObj ? activeTemplateSpec.id : '') })
          ] })
        ] }),
        jsx('div', {
          id: 'pane-divider',
          'data-testid': 'pane-divider',
          role: 'separator',
          tabIndex: 0,
          'aria-label': 'Resize project tree and file preview',
          'aria-orientation': 'vertical',
          'aria-valuemin': 20,
          'aria-valuemax': 80,
          'aria-valuenow': splitVal,
          'aria-valuetext': `${splitVal} percent project tree`,
          title: 'Drag left or right. Arrow keys adjust width.',
          onPointerDown: e => {
            if (current.busy) return
            if (e?.button !== undefined && e.button !== 0) return
            e?.preventDefault?.()
            const target = e?.currentTarget || e?.target || null
            const pointerId = e?.pointerId ?? 1
            target?.setPointerCapture?.(pointerId)
            dragStateRef.current = { pointerId, startX: e?.clientX ?? 0, startSplit: splitVal, width: measureColumnsWidth(e), target }
          },
          onPointerMove: e => {
            if (!dragStateRef.current || current.busy) return
            if (e?.pointerId !== undefined && dragStateRef.current.pointerId !== undefined && e.pointerId !== dragStateRef.current.pointerId) return
            const measuredWidth = measureColumnsWidth(e) || dragStateRef.current.width || 1000
            const deltaX = (e?.clientX ?? 0) - dragStateRef.current.startX
            const deltaPct = Math.round((deltaX / measuredWidth) * 100)
            setSplitVal(dragStateRef.current.startSplit + deltaPct)
          },
          onPointerUp: e => {
            if (!dragStateRef.current) return
            if (e?.pointerId !== undefined && dragStateRef.current.pointerId !== undefined && e.pointerId !== dragStateRef.current.pointerId) return
            const target = e?.currentTarget || e?.target || dragStateRef.current.target
            target?.releasePointerCapture?.(dragStateRef.current.pointerId)
            dragStateRef.current = null
          },
          onPointerCancel: e => {
            if (!dragStateRef.current) return
            const target = e?.currentTarget || e?.target || dragStateRef.current.target
            target?.releasePointerCapture?.(dragStateRef.current.pointerId)
            dragStateRef.current = null
          },
          onDoubleClick: () => { if (!current.busy) setSplitVal(58) },
          onKeyDown: e => {
            if (current.busy) return
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e?.key)) return
            e?.preventDefault?.()
            if (e.key === 'Home') setSplitVal(20)
            else if (e.key === 'End') setSplitVal(80)
            else setSplitVal(splitVal + (e.key === 'ArrowLeft' ? -1 : 1) * (e.shiftKey ? 10 : 4))
          },
          style: { width: '7px', cursor: 'col-resize', background: 'var(--ui-bg-tertiary)', borderInline: '1px solid var(--ui-stroke-secondary)' }
        }),
        jsxs('section', { className: 'inspector', 'aria-label': 'File preview', style: { minWidth: 0, padding: '10px', display: 'flex', flexDirection: 'column', gap: '8px' }, children: [
          jsxs('div', { className: 'pane-head', style: { display: 'flex', alignItems: 'center', gap: '8px' }, children: [
            jsx('span', { className: 'file-icon', style: { fontFamily: 'var(--font-mono)', fontSize: '11px' }, children: isMdFile ? 'MD' : file.endsWith('.ts') ? 'TS' : '≡' }),
            jsx('h2', { id: 'file-title', className: 'editor-title', style: { margin: 0, fontSize: '13px' }, children: file.split('/').pop() }),
            jsx('span', { style: { flex: 1 } }),
            jsx('code', { children: 'Preview' })
          ] }),
          jsx('div', { id: 'file-path', className: 'editor-path', style: { fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--ui-text-secondary)' }, children: file }),
          jsxs('div', { className: 'reader-controls', 'aria-label': 'File display controls', style: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', borderBottom: '1px solid var(--ui-stroke-secondary)', paddingBottom: '6px' }, children: [
            isMdFile ? jsxs('div', { id: 'markdown-modes', className: 'reader-segments', style: { display: 'flex', gap: '4px' }, children: [
              jsx(Button, { id: 'md-preview', 'data-testid': 'md-preview', 'aria-pressed': mdMode === 'preview', onClick: () => setMdMode('preview'), children: 'Preview' }),
              jsx(Button, { id: 'md-source', 'data-testid': 'md-source', 'aria-pressed': mdMode === 'source', onClick: () => setMdMode('source'), children: 'Source' })
            ] }) : null,
            !showMdPreview ? jsx(Button, { id: 'wrap-button', 'data-testid': 'wrap-button', 'aria-pressed': wrap, onClick: () => setWrap(!wrap), children: wrap ? 'Wrap on' : 'Wrap off' }) : null,
            jsx('span', { style: { flex: 1 } }),
            jsx(Button, { id: 'font-smaller', 'data-testid': 'font-smaller', 'aria-label': 'Smaller preview text', disabled: fontSize <= 10, onClick: () => setFontSize(Math.max(10, fontSize - 1)), children: 'A−' }),
            jsx('output', { id: 'font-size', 'data-testid': 'font-size', 'aria-label': 'Preview text size', children: String(fontSize) }),
            jsx(Button, { id: 'font-larger', 'data-testid': 'font-larger', 'aria-label': 'Larger preview text', disabled: fontSize >= 20, onClick: () => setFontSize(Math.min(20, fontSize + 1)), children: 'A+' })
          ] }),
          jsx('div', {
            id: 'editor',
            className: `editor ${wrap && !showMdPreview ? 'wrapped' : 'nowrap'}`,
            style: { fontSize: `${fontSize}px`, whiteSpace: showMdPreview ? 'normal' : (wrap ? 'pre-wrap' : 'pre'), overflowX: 'auto', fontFamily: showMdPreview ? 'inherit' : 'var(--font-mono)', padding: '8px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px' },
            children: showMdPreview
              ? renderSafeMarkdown(rawFileContent)
              : String(rawFileContent).split('\n').map((line, i) => jsxs('div', {
                  className: 'code-row',
                  style: { display: 'flex', gap: '10px' },
                  children: [
                    jsx('span', { className: 'line-number', style: { color: 'var(--ui-text-quaternary)', userSelect: 'none', minWidth: '24px' }, children: String(i + 1) }),
                    jsx('span', { className: 'code', style: { whiteSpace: wrap ? 'pre-wrap' : 'pre', overflowWrap: wrap ? 'anywhere' : 'normal' }, children: line })
                  ]
                }, `line-${i}`))
          }),
          current.selected ? jsx(ManualLintSection, { ctx, project: current.selected, mode: current.settings?.lint_mode || 'both', requireLintConfirmation: selectedIsExisting }, current.selected) : null
        ] })
      ] }),
      jsxs('footer', { className: 'bottom', 'data-testid': 'v10-workspace-footer', style: { display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap', marginTop: '6px', paddingTop: '10px', borderTop: '1px solid var(--ui-stroke-secondary)' }, children: [
        jsxs('div', { className: 'quick-actions', 'data-testid': 'v10-quick-actions', 'aria-label': 'Project actions', style: { display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }, children: [
          jsxs('div', { className: 'quick-action', style: { display: 'flex', alignItems: 'center', gap: '6px' }, children: [
            jsx('span', { children: 'LINT' }),
            jsx(Button, { 'data-testid': 'footer-lint-play', 'aria-label': 'Run lint', disabled: !current.selected || current.busy || activeLintState.busy, onClick: runFooterLint, children: '▶' })
          ] }),
          jsxs('div', { className: 'quick-action', style: { display: 'flex', alignItems: 'center', gap: '6px' }, children: [
            jsx('span', { children: 'CHECKS' }),
            jsx(Button, { 'data-testid': 'footer-checks-play', 'aria-label': 'Run checks', disabled: current.busy || activeChecksState.busy, onClick: runFooterChecks, children: '▶' })
          ] }),
          jsxs('div', { className: 'quick-action audit-actions', style: { display: 'flex', alignItems: 'center', gap: '6px' }, children: [
            jsx('span', { children: 'AUDIT' }),
            jsx(Button, { id: 'audit-full-button', 'data-testid': 'audit-full-button', 'aria-label': 'Review full audit', onClick: e => openAuditModal('full', e), children: 'Full ▶' }),
            jsx(Button, { id: 'audit-quick-button', 'data-testid': 'audit-quick-button', 'aria-label': 'Review quick audit', onClick: e => openAuditModal('quick', e), children: 'Quick ▶' })
          ] })
        ] }),
        jsxs('div', { className: 'audit-assurances', 'aria-label': 'Audit inspection boundaries', style: { display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap', paddingLeft: '12px', borderLeft: '1px solid var(--ui-stroke-secondary)' }, children: [
          jsx('span', { className: 'audit-assurances-label', style: { fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--ui-text-secondary)' }, children: 'AUDIT' }),
          jsx(Badge, { className: 'audit-safety', title: 'Audit only reads inspected project files. Lint is a separate action and can execute repository code and write files.', children: '🔒 Audit read-only' }),
          jsx(Badge, { className: 'audit-safety', title: 'Discovered project hooks and scripts are inspected, not launched.', children: '🚫 Runs none of your scripts' }),
          jsx(Badge, { className: 'audit-safety', title: 'The audit collector makes no outbound network calls.', children: '🚫 No internet use' }),
          jsx(Button, { id: 'plugin-storage-button', 'data-testid': 'plugin-storage-button', onClick: e => { modalOpenerRef.current = e?.currentTarget || e?.target || null; setStorageModalOpen(true) }, children: '💾 Plugin storage' })
        ] }),
        actionNotice ? jsx('span', { id: 'status', 'data-testid': 'audit-status-notice', role: 'status', children: actionNotice }) : null,
        jsx('code', { id: 'active-project-path', style: { marginLeft: 'auto', fontSize: '11px', color: 'var(--ui-text-secondary)' }, children: current.selected || 'No project selected' })
      ] }),
      activeLintState.result ? jsx('div', { 'data-testid': 'footer-lint-output', children: outputView(activeLintState.result) }) : null,
      activeChecksState.result ? jsx('div', { 'data-testid': 'footer-checks-output', children: outputView(activeChecksState.result) }) : null,
      auditActionState.status || auditActionState.report || (!auditModalOpen && auditActionState.error) ? jsxs('div', { 'data-testid': 'footer-audit-output', style: { borderTop: '1px solid var(--ui-stroke-secondary)', paddingTop: '8px' }, children: [
        jsx('p', { children: 'This audit cannot tell whether working code is correct. Anything marked “Could not verify” is not a pass. The audit only reports; it changes nothing.' }),
        auditActionState.error ? jsxs('div', { 'data-testid': 'footer-audit-error', role: 'alert', style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }, children: [
          jsx('span', { children: `Audit error: ${auditSafe(auditActionState.error)}` }),
          (auditActionState.runId || auditActionState.status?.run_id) ? jsx(Button, { id: 'audit-retry-button', 'data-testid': 'audit-retry-button', disabled: auditActionState.busy, onClick: retryAuditStatus, children: 'Retry status' }) : null
        ] }) : null,
        auditSummaryShown ? jsx(Button, { 'data-testid': 'audit-summary-toggle', onClick: () => setAuditSummary(prev => ({ ...prev, raw: !prev.raw })), children: auditSummary.raw ? 'Show summary' : 'Show raw report' }) : null,
        auditSummaryShown && !auditSummary.raw ? (auditModel ? auditSummaryView(auditModel) : jsx('pre', { 'data-testid': 'audit-summary', style: { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }, children: auditSafeBlock(auditSummary.text) })) : null,
        auditActionState.status && !(auditSummaryShown && !auditSummary.raw) ? outputView(auditSafeBlock(auditActionState.status)) : null,
        auditActionState.report && !(auditSummaryShown && !auditSummary.raw) ? outputView(auditSafeBlock(auditActionState.report)) : null
      ] }) : null
    ] }),
    newProjectModalOpen ? jsxs('div', { 'data-testid': 'modal-backdrop', 'data-modal-backdrop': 'true', inert: folderDialogOpen ? true : undefined, 'aria-hidden': folderDialogOpen ? 'true' : undefined, onClick: e => { if (!folderDialogOpen && e?.target === e?.currentTarget) closeNewProjectModal() }, style: { ...MODAL_SCRIM }, children: [
      jsxs('div', { id: 'new-project-dialog', 'data-testid': 'new-project-modal', role: 'dialog', 'data-glass-raised': true, 'aria-modal': 'true', 'aria-labelledby': 'new-project-title', tabIndex: -1, onKeyDown: e => { if (!folderDialogOpen) handleModalKeyDown(closeNewProjectModal)(e) }, style: { width: 'min(960px, 92vw)', maxWidth: '100%', maxHeight: '92vh', overflowY: 'auto', boxSizing: 'border-box', padding: '16px', background: RAISED_FILL, color: 'var(--ui-text-primary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '10px' }, children: [
        jsxs('header', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }, children: [
          jsx('h2', { id: 'new-project-title', style: { margin: 0 }, children: 'Start project' }),
          jsx(Button, { 'aria-label': 'Close project setup', disabled: current.busy && !current.acceptJob, onClick: closeNewProjectModal, children: '×' })
        ] }),
        projectsFolder.status === 'error' ? jsx('p', { id: 'projects-folder-status', role: 'alert', children: projectsFolder.message }) : null,
        projectsFolder.path ? jsxs('p', { id: 'projects-folder-current', style: { margin: '0 0 12px', overflowWrap: 'anywhere' }, children: [
          `Projects folder: ${projectsFolder.path}`,
          ' ',
          jsx('button', { type: 'button', id: 'projects-folder-change', onClick: e => openFolderDialog(e?.currentTarget || e?.target || null, projectsFolder.path, 'change'), style: { background: 'transparent', border: 0, padding: 0, color: 'var(--ui-accent)', textDecoration: 'underline', cursor: 'pointer', font: 'inherit' }, children: 'Change' })
        ] }) : null,
        field('Project idea', modalIdea, nextIdea => {
          setModalIdea(nextIdea)
          const res = discardModalProposalOnEdit({ idea: nextIdea })
          clearIdeaMatchTimer()
          const schedule = typeof ctx?.setTimeout === 'function' ? ctx.setTimeout : setTimeout
          ideaMatchTimerRef.current = schedule(() => {
            ideaMatchTimerRef.current = null
            if (disposedRef.current || !model.isMounted?.() || model.get().busy || model.get().partial) return
            return loadModalList()
          }, 400)
          return res
        }, modalLocked, { id: 'project-idea', autoFocus: true, 'data-initial-focus': 'true', placeholder: 'Optional: describe your idea to see suggestions' }),
        jsxs('fieldset', { id: 'new-project-choice', 'data-testid': 'new-project-choice', 'aria-describedby': catalogNotice ? 'kits-notice' : undefined, onKeyDown: onChoiceKeyDown, style: { margin: '12px 0 0', padding: '8px', minWidth: 0, maxHeight: 'min(45vh, 420px)', overflowY: 'auto', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '8px' }, children: [
          jsx('legend', { children: 'What to create' }),
          listUnavailable
            ? jsxs('div', { children: [
              jsx('p', { style: { margin: '0 0 6px' }, children: current.matchFailed ? 'The list of projects could not be loaded.' : 'No project types are available right now.' }),
              jsx(Button, { id: 'new-project-choice-retry', disabled: modalLocked, onClick: () => loadModalList(), children: 'Check again' })
            ] })
            : !current.catalog
              ? jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }, children: [
                jsx('p', { role: 'status', style: { ...mutedText, margin: 0 }, children: 'Loading the list…' }),
                listSlow ? jsx(Button, { id: 'new-project-choice-retry', disabled: Boolean(current.partial), onClick: () => loadModalList(), children: 'Check again' }) : null
              ] })
              : null,
          ...catalogGroups.map((g, gi) => jsxs('div', { role: 'group', 'aria-labelledby': choiceDomId('choice-group', gi, g.id), style: { display: 'flex', flexDirection: 'column', gap: '4px' }, children: [
            jsx('h4', { id: choiceDomId('choice-group', gi, g.id), style: { margin: '4px 0' }, children: g.title }),
            ...g.entries.map(choiceRow)
          ] }, `${gi}:${g.id}`)),
          catalogNotice ? jsx('div', { id: 'kits-notice', 'data-testid': 'kits-notice', style: mutedText, children: catalogNotice }) : null
        ] }),
        choiceGoneNotice ? jsx('p', { id: 'new-project-choice-gone', role: 'status', children: choiceGoneNotice }) : null,
        chosenEntry && chosenEntry.kind !== 'template' && chosenEntry.kind !== 'kit' ? jsx('p', { id: 'new-project-choice-unsupported', role: 'status', children: `This version of the page cannot create “${chosenEntry.title}”. Choose another row, or update Defuzz.` }) : null,
        jsxs('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', gap: '16px', marginTop: '12px' }, children: [
          jsxs('section', { children: [
            jsx('h3', { style: { marginTop: 0 }, children: 'Proposed project' }),
            jsx(Badge, { id: 'proposal-template', style: { overflowWrap: 'anywhere' }, children: chosenEntry?.title || 'Nothing chosen yet' }),
            selectedKitSummary ? jsx('p', { id: 'proposal-kit-summary', style: { margin: '6px 0', fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: selectedKitSummary }) : null,
            current.selectedKitId && current.kitPreviewError ? jsx('p', { id: 'kit-preview-error', role: 'alert', style: { margin: '6px 0', fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: current.kitPreviewError }) : null,
            jsx('pre', { id: 'proposal-tree', ...(current.selectedKitId ? { 'aria-label': 'Folders this workspace creates' } : {}), style: { fontFamily: 'var(--font-mono)', fontSize: '11px', whiteSpace: 'pre-wrap' }, children: proposalTreeText }),
            jsx('code', { id: 'proposal-destination', style: { overflowWrap: 'anywhere' }, children: proposalDestinationText })
          ] }),
          jsxs('section', { children: [
            jsx('h3', { style: { marginTop: 0 }, children: 'Setup' }),
            field('Project name', modalName, nextName => {
              setModalName(nextName)
              return discardModalProposalOnEdit({ name: nextName })
            }, modalLocked, { id: 'new-project-name', placeholder: 'my-project' }),
            !modalNameValid ? jsx('div', { id: 'proposal-error', role: 'status', children: current.projects.some(p => (p.name || p.path) === modalName) ? 'A project with this name already exists.' : 'Use a lowercase name starting with a letter; letters, numbers and hyphens only.' }) : null,
            jsxs('label', { htmlFor: 'new-project-adapter', children: ['Web server library', jsx('select', { id: 'new-project-adapter', 'aria-label': 'Web server library', disabled: modalLocked || Boolean(current.selectedKitId) || adapterChoices.length === 0, value: adapterChoices.length ? modalAdapter : '', onChange: async e => {
              setModalAdapter(e.target.value)
              if (primaryOptionKey && model.get().template) await model.option(primaryOptionKey, e.target.value)
              else if (model.get().proposal?.proposal_id) await discardModalProposalOnEdit({})
            }, children: adapterChoices.length > 0 ? adapterChoices.map(([val, lbl]) => jsx('option', { value: val, children: lbl }, val)) : [jsx('option', { value: '', children: 'No choices for this project type' }, 'none')] })] })
          ] })
        ] }),
        current.accepting || current.acceptLost === 'no-answer' || current.acceptNote
          ? jsx('p', { id: 'new-project-progress', role: 'status', children: current.acceptJob ? acceptJobText(current.acceptJob) : current.accepting ? CREATE_PROGRESS_TEXT : current.acceptNote || CREATE_STILL_RUNNING_TEXT })
          : null,
        current.error && !current.partial ? jsx('p', { role: 'alert', children: current.error }) : null,
        current.partial ? jsx('p', { role: 'alert', children: 'Some files were created before something went wrong. They were left in place (listed below); nothing will be deleted.' }) : null,
        current.output ? jsxs('section', { 'aria-label': 'What happened', style: { marginTop: '10px', padding: '10px', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px' }, children: [
          jsx('h3', { style: { marginTop: 0 }, children: 'What happened' }),
          ...(current.output.repos || current.output.accepted_repos || []).map((repo, index) => jsxs('article', { children: [
            jsx('h4', { children: repo.path || `Repository ${index + 1}` }),
            jsx('p', { children: repo.registration_result?.registered === true && repo.registration === 'registered' ? 'Registered in Hermes' : 'The project was created but not added to Hermes. Add it yourself:' }),
            outputView(repo.registration_result || { status: repo.registration || 'could_not_verify', reason: repo.registration_reason }),
            repo.registration !== 'registered' ? jsx('p', { children: `Desktop registration failed: ${JSON.stringify(repo.registration_result?.reason ?? repo.registration_reason ?? 'could_not_verify')}; project created at ${JSON.stringify(repo.path)}. Register manually with desktop_project ${JSON.stringify({ action: 'create', name: repo.registration_name ?? repo.name ?? current.name ?? modalName, path: repo.path })}.` }) : null
          ] }, repo.path || index)),
          outputView(current.output)
        ] }) : null,
        jsxs('footer', { style: { display: 'flex', justifyContent: 'flex-end', flexWrap: 'wrap', gap: '8px', marginTop: '12px' }, children: [
          !choiceReady ? jsx('span', { id: 'accept-project-reason', style: { ...mutedText, alignSelf: 'center', marginRight: 'auto' }, children: 'Choose a row in the list to create a project.' }) : null,
          jsx(Button, { id: 'cancel-project', 'data-testid': 'cancel-project', disabled: current.busy && !current.acceptJob, onClick: current.acceptJob ? model.cancelAccept : closeNewProjectModal, children: 'Cancel' }),
          jsx(Button, { id: 'accept-project', 'data-testid': 'accept-project', 'aria-describedby': choiceReady ? undefined : 'accept-project-reason', disabled: !modalNameValid || modalLocked || !choiceReady || projectsFolder.status === 'error' || (projectsFolder.status === 'ready' && projectsFolder.source !== 'unset' && !projectsFolder.path), onClick: acceptNewProjectModal, children: 'Accept & create' })
        ] })
      ] })
    ] }) : null,
    folderDialogOpen ? jsxs('div', { 'data-testid': 'projects-folder-backdrop', onClick: e => { if (e?.target === e?.currentTarget) closeFolderDialog() }, style: { ...MODAL_SCRIM, zIndex: 60, padding: '12px' }, children: [
      jsxs('div', { id: 'projects-folder-dialog', role: 'dialog', 'data-glass-raised': true, 'aria-modal': 'true', 'aria-labelledby': 'projects-folder-title', tabIndex: -1, onKeyDown: handleModalKeyDown(closeFolderDialog), style: { width: 'min(28rem, 100%)', maxWidth: '100%', boxSizing: 'border-box', padding: '16px', background: RAISED_FILL, color: 'var(--ui-text-primary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '10px', display: 'flex', flexDirection: 'column', gap: '12px' }, children: [
        jsx('h2', { id: 'projects-folder-title', style: { margin: 0, fontSize: '1.05rem' }, children: 'Where should your projects go?' }),
        jsx('p', { style: { margin: 0 }, children: 'Choose the folder where Defuzz creates new projects. Only new projects go here; nothing else on your machine is touched, and the folder is created when you create your first project.' }),
        folderMode === 'change' ? jsx('p', { id: 'projects-folder-change-note', style: { margin: 0 }, children: 'Existing projects stay where they are; only new projects will be created in this folder.' }) : null,
        jsxs('label', { htmlFor: 'projects-folder-input', children: [
          'Projects folder',
          jsx('input', {
            id: 'projects-folder-input',
            'aria-describedby': folderError ? 'projects-folder-help projects-folder-error' : 'projects-folder-help',
            value: folderDraft,
            autoFocus: true,
            'data-initial-focus': 'true',
            disabled: folderBusy,
            onChange: e => { setFolderDraft(e.target.value); setFolderError('') },
            style: { display: 'block', width: '100%', boxSizing: 'border-box', marginTop: '4px', padding: '8px', background: 'var(--ui-bg-secondary)', color: 'var(--ui-text-primary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px' }
          })
        ] }),
        jsx('p', { id: 'projects-folder-help', style: { margin: 0, fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: 'Type a full path, or keep the suggestion.' }),
        folderError ? jsx('p', { id: 'projects-folder-error', role: 'alert', style: { margin: 0, overflowWrap: 'anywhere' }, children: folderError }) : null,
        saveFallback ? jsxs('div', { children: [
          jsx('p', { style: { margin: '0 0 6px' }, children: 'Run this in your terminal:' }),
          jsx('code', { id: 'projects-folder-command', style: { display: 'block', overflowWrap: 'anywhere' }, children: saveFallback }),
          jsx(Button, { id: 'projects-folder-check', onClick: checkProjectsFolderAgain, children: 'Check again' })
        ] }) : null,
        jsxs('footer', { style: { display: 'flex', justifyContent: 'flex-end', gap: '8px', flexWrap: 'wrap' }, children: [
          jsx(Button, { id: 'projects-folder-cancel', onClick: closeFolderDialog, children: 'Cancel' }),
          jsx(Button, { id: 'projects-folder-use', className: 'primary', disabled: folderBusy, onClick: confirmProjectsFolder, children: 'Use this folder' })
        ] })
      ] })
    ] }) : null,
    openExisting ? jsxs('div', { 'data-testid': 'modal-backdrop', 'data-modal-backdrop': 'true', onClick: e => { if (e?.target === e?.currentTarget) closeExistingModal() }, style: { ...MODAL_SCRIM }, children: [
      jsxs('div', { id: 'open-existing-dialog', 'data-testid': 'open-existing-modal', role: 'dialog', 'data-glass-raised': true, 'aria-modal': 'true', 'aria-labelledby': 'open-existing-title', tabIndex: -1, onKeyDown: handleModalKeyDown(closeExistingModal), style: { width: 'min(620px, 92vw)', maxWidth: '100%', maxHeight: '92vh', overflowY: 'auto', boxSizing: 'border-box', padding: '16px', background: RAISED_FILL, color: 'var(--ui-text-primary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '10px', display: 'flex', flexDirection: 'column', gap: '10px' }, children: [
        jsxs('header', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' }, children: [
          jsx('h2', { id: 'open-existing-title', style: { margin: 0 }, children: 'Open existing Hermes project' }),
          jsx(Button, { 'aria-label': 'Close open existing project dialog', autoFocus: true, 'data-initial-focus': 'true', disabled: Boolean(current.existingOpenBusy), onClick: closeExistingModal, children: '×' })
        ] }),
        jsx('p', { id: 'open-existing-scope', style: { margin: 0 }, children: 'Opening adds a reference only. Audit is read-only; lint can execute repository code and write files.' }),
        jsx('p', { style: { margin: 0, fontSize: '11.5px', color: 'var(--ui-text-secondary)' }, children: 'Nothing in the folder is copied, moved, adopted, or trusted. Opening does not run lint, checks, installs, or adoption.' }),
        jsxs('section', { 'aria-label': 'Hermes projects', style: { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', padding: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }, children: [
          jsx('h3', { style: { margin: 0, fontSize: '13px' }, children: 'Hermes projects' }),
          (current.existingList?.status || 'idle') === 'loading'
            ? jsx('p', { role: 'status', style: { margin: 0, fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: 'Loading Hermes projects…' })
            : current.existingList?.status === 'error'
              ? jsx('p', { 'data-testid': 'open-existing-list-error', role: 'alert', style: { margin: 0, fontSize: '12px' }, children: `Could not verify Hermes projects: ${current.existingList.error}. Type the backend folder path below.` })
              : (current.existingList?.projects || []).length === 0
                ? jsx('p', { style: { margin: 0, fontSize: '12px', color: 'var(--ui-text-secondary)' }, children: 'No existing Hermes project folders were found. Type the backend folder path below.' })
                : jsx('div', { role: 'radiogroup', 'aria-label': 'Existing Hermes projects', style: { display: 'flex', flexDirection: 'column', gap: '4px' }, children: (current.existingList?.projects || []).map(project => {
                    const checked = existingSelected === project.path
                    return jsxs('div', { 'data-testid': 'existing-project-row', 'data-path': project.path, style: { display: 'grid', gridTemplateColumns: 'auto minmax(0, 1fr)', columnGap: '8px', alignItems: 'start', padding: '5px 7px', border: `1px solid ${checked ? 'var(--ui-accent)' : 'var(--ui-stroke-secondary)'}`, borderRadius: '6px' }, children: [
                      jsx('input', { 'data-testid': 'existing-project-select', 'aria-label': `${project.name} — ${project.path}`, type: 'radio', name: 'existing-project', checked, onChange: () => { setExistingSelected(project.path); setExistingPath(''); setExistingBrowseNote(''); setExistingBrowseError('') } }),
                      jsxs('div', { style: { minWidth: 0 }, children: [
                        jsx('strong', { style: { display: 'block', overflowWrap: 'anywhere' }, children: project.name }),
                        jsx('code', { style: { fontSize: '11px', overflowWrap: 'anywhere', color: 'var(--ui-text-secondary)' }, children: project.path })
                      ] })
                    ] }, project.path)
                  }) })
        ] }),
        jsxs('label', { htmlFor: 'open-existing-input', children: [
          'Folder path on the backend machine',
          jsx('input', {
            id: 'open-existing-input',
            'data-testid': 'open-existing-path',
            value: existingPath,
            placeholder: '/home/user/projects/my-project',
            disabled: Boolean(current.existingOpenBusy),
            onChange: e => { setExistingPath(e.target.value); setExistingSelected(''); setExistingBrowseNote(''); setExistingBrowseError('') },
            style: { display: 'block', width: '100%', boxSizing: 'border-box', marginTop: '4px', padding: '7px', background: 'var(--ui-bg-secondary)', color: 'var(--ui-text-primary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '6px' }
          })
        ] }),
        jsx('p', { id: 'open-existing-dialog-hint', 'data-testid': 'open-existing-dialog-hint', style: { margin: 0, fontSize: '11.5px', color: 'var(--ui-text-secondary)' }, children: 'Type the absolute path as the backend sees it. The backend validates every open; Browse is optional and picks on this computer only.' }),
        jsxs('div', { style: { display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }, children: [
          jsx(Button, { 'data-testid': 'open-existing-browse', disabled: Boolean(current.existingOpenBusy), onClick: browseExistingFolder, children: 'Browse this computer…' }),
          existingBrowseNote ? jsx('span', { 'data-testid': 'open-existing-browse-note', style: { fontSize: '11.5px', color: 'var(--ui-text-secondary)', overflowWrap: 'anywhere' }, children: existingBrowseNote }) : null
        ] }),
        existingBrowseError ? jsx('p', { 'data-testid': 'open-existing-browse-error', role: 'alert', style: { margin: 0 }, children: existingBrowseError }) : null,
        current.existingOpenError ? jsx('p', { 'data-testid': 'open-existing-error', role: 'alert', style: { margin: 0, overflowWrap: 'anywhere' }, children: current.existingOpenError }) : null,
        current.existingOpenNotice ? jsx('p', { 'data-testid': 'open-existing-notice', role: 'status', style: { margin: 0 }, children: current.existingOpenNotice }) : null,
        jsxs('footer', { style: { display: 'flex', justifyContent: 'flex-end', gap: '8px', flexWrap: 'wrap' }, children: [
          jsx(Button, { 'data-testid': 'open-existing-cancel', disabled: Boolean(current.existingOpenBusy), onClick: closeExistingModal, children: 'Cancel' }),
          jsx(Button, { 'data-testid': 'open-existing-confirm', className: 'primary', disabled: Boolean(current.existingOpenBusy) || (!existingSelected && !existingPath.trim()), onClick: confirmOpenExisting, children: current.existingOpenBusy ? 'Opening…' : 'Open' })
        ] })
      ] })
    ] }) : null,
    auditModalOpen ? jsxs('div', { 'data-testid': 'modal-backdrop', 'data-modal-backdrop': 'true', onClick: e => { if (e?.target === e?.currentTarget) closeAuditModal() }, style: { ...MODAL_SCRIM }, children: [
      jsxs('div', { id: 'audit-review-dialog', 'data-testid': 'audit-review-dialog', role: 'dialog', 'data-glass-raised': true, 'aria-modal': 'true', 'aria-labelledby': 'audit-review-title', tabIndex: -1, onKeyDown: handleModalKeyDown(closeAuditModal), style: { width: 'min(540px, 92vw)', padding: '16px', background: RAISED_FILL, color: 'var(--ui-text-primary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '10px' }, children: [
        jsxs('header', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }, children: [
          jsx('h2', { id: 'audit-review-title', style: { margin: 0 }, children: auditMode === 'quick' ? 'Review quick audit' : 'Review full audit' }),
          jsx(Button, { 'aria-label': 'Close audit review', autoFocus: true, 'data-initial-focus': 'true', onClick: closeAuditModal, children: '×' })
        ] }),
        jsxs('div', { children: [
          jsxs('div', { children: [jsx('span', { children: 'Project: ' }), jsx('b', { id: 'audit-target-project', children: current.selected ? (selectedProjectObj?.name || current.selected) : (auditMode === 'quick' ? 'No project selected: only your Hermes settings will be checked.' : 'No project selected: only your Hermes settings and the folders they point to will be checked.') })] }),
          jsxs('div', { children: [jsx('span', { children: 'Profile: ' }), jsx('b', { children: 'Active Hermes profile' })] }),
          jsxs('fieldset', { style: { display: 'flex', gap: '16px', margin: '12px 0' }, children: [
            jsx('legend', { children: 'Inspection' }),
            jsxs('label', { children: [
              jsx('input', { 'data-testid': 'audit-mode-full', type: 'radio', name: 'audit-mode', value: 'full', checked: auditMode === 'full', onChange: () => { setAuditMode('full'); setAuditConsent(false) } }),
              'Full check (also follows links to outside folders)'
            ] }),
            jsxs('label', { children: [
              jsx('input', { 'data-testid': 'audit-mode-quick', type: 'radio', name: 'audit-mode', value: 'quick', checked: auditMode === 'quick', onChange: () => { setAuditMode('quick'); setAuditConsent(false) } }),
              'Quick scan'
            ] })
          ] }),
          jsx('p', { id: 'audit-mode-summary', children: auditMode === 'quick'
            ? 'Bounded active-profile capture and selected-project checks. Outward collection is skipped; uncollected regions remain unknown—not clean.'
            : 'Inspect the selected project, active profile and evidenced outward references, within resource budgets.' }),
          jsxs('details', { open: true, children: [
            jsx('summary', { children: 'Scope & boundaries' }),
            jsxs('ul', { children: [
              jsx('li', { children: 'Outward references may lead into shared context or another profile.' }),
              jsx('li', { children: 'Inspect declarations without launching project hooks or scripts.' }),
              jsx('li', { children: 'No project edits or automatic cleanup; audit records use plugin storage.' }),
              jsx('li', { children: 'Uncollected or inaccessible regions remain unknown, not clean.' }),
              jsx('li', { children: 'The live backend disclosure must define sensitive-file handling before a real run.' })
            ] })
          ] }),
          auditDisclosure ? jsx('p', { 'data-testid': 'audit-live-disclosure', children: auditDisclosure }) : null,
          jsxs('label', { children: [
            jsx('input', {
              id: 'audit-review-consent',
              'data-testid': 'audit-review-consent',
              type: 'checkbox',
              disabled: !auditDisclosure || auditActionState.busy,
              checked: Boolean(auditDisclosure) && auditConsent,
              onChange: e => { if (auditDisclosure) setAuditConsent(Boolean(e?.target?.checked)) }
            }),
            'I reviewed this audit scope.'
          ] }),
          auditActionState.error ? jsx('div', { role: 'status', children: auditActionState.error }) : null
        ] }),
        jsxs('footer', { style: { display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '12px' }, children: [
          jsx(Button, { onClick: closeAuditModal, children: 'Cancel' }),
          jsx(Button, { id: 'audit-review-run', 'data-testid': 'audit-review-run', disabled: !auditDisclosure || !auditConsent || auditActionState.busy, onClick: runModalAudit, children: auditMode === 'quick' ? 'Run quick audit' : 'Run full audit' })
        ] })
      ] })
    ] }) : null,
    storageModalOpen ? jsxs('div', { 'data-testid': 'modal-backdrop', 'data-modal-backdrop': 'true', onClick: e => { if (e?.target === e?.currentTarget) closeStorageModal() }, style: { ...MODAL_SCRIM }, children: [
      jsxs('div', { id: 'plugin-storage-dialog', 'data-testid': 'plugin-storage-dialog', role: 'dialog', 'data-glass-raised': true, 'aria-modal': 'true', 'aria-labelledby': 'plugin-storage-title', tabIndex: -1, onKeyDown: handleModalKeyDown(closeStorageModal), style: { width: 'min(540px, 92vw)', padding: '16px', background: RAISED_FILL, color: 'var(--ui-text-primary)', border: '1px solid var(--ui-stroke-secondary)', borderRadius: '10px' }, children: [
        jsxs('header', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }, children: [
          jsx('h2', { id: 'plugin-storage-title', style: { margin: 0 }, children: 'Plugin storage' }),
          jsx(Button, { 'aria-label': 'Close storage information', autoFocus: true, 'data-initial-focus': 'true', onClick: closeStorageModal, children: '×' })
        ] }),
        jsx('p', { children: 'Audit records belong in the plugin’s data area. Selected project files stay in their own workspace.' }),
        jsxs('ul', { children: [
          jsx('li', { children: 'Audit reports and run records' }),
          jsx('li', { children: 'Saved plugin preferences' }),
          jsx('li', { children: 'No automatic project cleanup' })
        ] }),
        jsxs('footer', { style: { display: 'flex', justifyContent: 'flex-end', marginTop: '12px' }, children: [
          jsx(Button, { onClick: closeStorageModal, children: 'Close' })
        ] })
      ] })
    ] }) : null
  ] }) })
}

// One sidebar entry opens the page; Settings and the inspector are reached from the page's top bar.
// Every row is a route so deep links work; `command` rows also get a palette command.
export const WORKSPACE_SCREENS = [
  { screen: 'main', path: ROUTE_PATH, label: 'Main', command: 'Open', sidebar: 'Defuzz' },
  { screen: 'main', path: `${ROUTE_PATH}/projects`, label: 'Projects' },
  { screen: 'settings', path: `${ROUTE_PATH}/settings`, label: 'Settings', command: 'Settings' },
  { screen: 'adopt', path: `${ROUTE_PATH}/inspector`, label: 'Adopted copy inspector', command: 'Adopted copy inspector' }
]

export default {
  id: 'defuzz',
  name: 'Project Defuzz',
  register(ctx) {
    WORKSPACE_SCREENS.forEach(({ screen, path, label, command, sidebar }, index) => {
      const suffix = index === 0 ? '' : `-${label.toLowerCase().replaceAll(' ', '-')}`
      ctx.register({ id: `page${suffix}`, area: ROUTES_AREA, data: { path }, render: () => jsx(WorkspacePage, { ctx, initialScreen: screen }) })
      if (sidebar) ctx.register({ id: `nav${suffix}`, area: SIDEBAR_NAV_AREA, order: 75, data: { path, label: sidebar, codicon: 'folder-opened' } })
      if (command) ctx.register({ id: `open${suffix}`, area: PALETTE_AREA, data: {
        id: `defuzz.open${suffix}`, path, label: `Project Defuzz: ${command}`,
        keywords: ['adopt', 'scaffold', 'lint', 'projects', label.toLowerCase(), command.toLowerCase()], run: () => host.navigate(path)
      } })
    })
  }
}

// Run from worktree root: node --import ./desktop/tests/sdk-shim.mjs --test desktop/tests/
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  createSafeAutoSave,
  useSafeAutoSave,
  DEFAULT_AUTOSAVE_DEBOUNCE_MS
} from '../plugin.js'

function createFakeTimers() {
  let nextId = 1
  const pending = new Map()
  const delays = []
  const cleared = []

  function setTimeoutFn(cb, ms) {
    const id = nextId++
    delays.push(ms)
    pending.set(id, { cb, ms })
    return id
  }

  function clearTimeoutFn(id) {
    cleared.push(id)
    pending.delete(id)
  }

  async function drainMicrotasks(ticks = 20) {
    for (let i = 0; i < ticks; i++) {
      await Promise.resolve()
    }
  }

  async function flushAll(maxSteps = 50) {
    for (let step = 0; step < maxSteps; step++) {
      await drainMicrotasks()
      if (pending.size === 0) {
        break
      }
      const [firstId, entry] = pending.entries().next().value
      pending.delete(firstId)
      entry.cb()
    }
    await drainMicrotasks()
  }

  return { setTimeout: setTimeoutFn, clearTimeout: clearTimeoutFn, flushAll, delays, cleared, pending }
}

test('createSafeAutoSave coalesces rapid updates within 150ms window and increments seq monotonically', async () => {
  const timers = createFakeTimers()
  const savedPayloads = []
  const statusHistory = []

  const autoSave = createSafeAutoSave({
    namespace: 'rules',
    debounceMs: DEFAULT_AUTOSAVE_DEBOUNCE_MS,
    initialSeq: 10,
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    onSave: async payload => {
      savedPayloads.push(payload)
      return { applied: true, seq: payload.seq }
    },
    onStatusChange: snap => {
      statusHistory.push(snap)
    }
  })

  const s1 = autoSave.schedule('python:F401', { pre: true, post: false })
  const s2 = autoSave.schedule('python:F401', { pre: true, post: true })
  const s3 = autoSave.schedule('python:F401', { pre: false, post: true })

  assert.equal(s1.seq, 11)
  assert.equal(s2.seq, 12)
  assert.equal(s3.seq, 13)
  assert.equal(s3.status, 'coalescing')
  assert.equal(s3.dirty, true)
  assert.equal(savedPayloads.length, 0)
  // Previous two timers were cleared as new updates arrived
  assert.equal(timers.cleared.length, 2)
  assert.equal(timers.pending.size, 1)

  await timers.flushAll()

  assert.equal(savedPayloads.length, 1)
  assert.deepEqual(savedPayloads[0], {
    namespace: 'rules',
    key: 'python:F401',
    value: { pre: false, post: true },
    seq: 13
  })

  const finalSnap = autoSave.get('python:F401')
  assert.equal(finalSnap.seq, 13)
  assert.equal(finalSnap.savedSeq, 13)
  assert.equal(finalSnap.status, 'saved')
  assert.equal(finalSnap.dirty, false)
  assert.ok(statusHistory.length >= 4)
})

test('createSafeAutoSave rejects stale explicit seq numbers and handles flush() + cancel()', async () => {
  const timers = createFakeTimers()
  const saved = []

  const autoSave = createSafeAutoSave({
    namespace: 'layout',
    debounceMs: 150,
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    onSave: async payload => {
      saved.push(payload)
    }
  })

  autoSave.schedule('split_pct', 65, { seq: 5 })
  // Stale explicit seq <= 5 is ignored
  const staleSnap = autoSave.schedule('split_pct', 30, { seq: 3 })
  assert.equal(staleSnap.seq, 5)
  assert.equal(staleSnap.value, 65)

  // Immediate flush commits without waiting for timer
  const flushed = await autoSave.flush('split_pct')
  assert.equal(flushed.status, 'saved')
  assert.equal(flushed.savedSeq, 5)
  assert.equal(saved.length, 1)
  assert.equal(saved[0].value, 65)
  assert.equal(timers.pending.size, 0)

  // Schedule another update then cancel before timer fires
  autoSave.schedule('split_pct', 80, { seq: 6 })
  assert.equal(autoSave.get('split_pct').status, 'coalescing')
  autoSave.cancel('split_pct')
  await timers.flushAll()
  assert.equal(saved.length, 1)
  assert.equal(autoSave.get('split_pct').status, 'saved')
})

test('useSafeAutoSave hook exposes prototype-compatible seq, interval, label, and save()', async () => {
  const timers = createFakeTimers()
  const calls = []
  let latestHookState = null
  globalThis.__adoptTestStateHook = updater => {
    if (typeof updater === 'function') {
      latestHookState = updater(latestHookState)
    } else {
      latestHookState = updater
    }
  }

  try {
    const hook = useSafeAutoSave({
      namespace: 'ui',
      key: 'rules_matrix',
      initialValue: { count: 0 },
      seq: 14,
      interval: 150,
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout,
      onSave: async payload => {
        calls.push(payload)
      }
    })

    assert.equal(hook.seq, 14)
    assert.equal(hook.label, 'Coalesced Seq #14 Saved')

    const snap = hook.save({ count: 1 })
    assert.equal(snap.seq, 15)
    assert.equal(snap.status, 'coalescing')

    await timers.flushAll()
    assert.equal(calls.length, 1)
    assert.equal(calls[0].seq, 15)
    assert.deepEqual(calls[0].value, { count: 1 })
  } finally {
    delete globalThis.__adoptTestStateHook
  }
})

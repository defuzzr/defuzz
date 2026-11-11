// Run from worktree root: node --import ./desktop/tests/sdk-shim.mjs --test desktop/tests/
import test from 'node:test'
import assert from 'node:assert/strict'
import plugin, { createHandoff, HANDOFF_SUCCESS_OUTCOME } from '../plugin.js'

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
  }

  return { setTimeout: setTimeoutFn, clearTimeout: clearTimeoutFn, flushAll, delays, cleared, pending }
}

function createFakeGateway(script = [], callLog = []) {
  const queue = [...script]
  const requests = []
  return {
    requests,
    async request(method, params, timeoutMs) {
      const entry = { method, params, ...(timeoutMs !== undefined ? { timeoutMs } : {}) }
      requests.push(entry)
      callLog.push({ target: 'gateway', method, params, ...(timeoutMs !== undefined ? { timeoutMs } : {}) })
      if (queue.length === 0) {
        throw new Error(`Unexpected gateway.request(${method})`)
      }
      const next = queue.shift()
      if (next.expectMethod) {
        assert.equal(method, next.expectMethod)
      }
      if (typeof next.handler === 'function') {
        return next.handler(method, params, timeoutMs)
      }
      if (next.reject) {
        throw next.reject
      }
      return next.resolve
    }
  }
}

test('plugin default export and register() remain intact and side-effect free', () => {
  assert.equal(plugin.id, 'defuzz')
  assert.equal(typeof plugin.register, 'function')
  assert.equal(HANDOFF_SUCCESS_OUTCOME, 'completed')
  const registrations = []
  plugin.register({
    register(entry) {
      registrations.push(entry)
    }
  })
  assert.equal(registrations.length, 8) // 4 routes + 1 sidebar entry + 3 palette commands
})

test('input validation rejects synchronously when operationId, cwd, or prompt are missing/empty', async () => {
  const timers = createFakeTimers()
  const handoff = createHandoff({
    host: { getGateway: () => null, openSession: async () => {} },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })
  await assert.rejects(() => handoff.run({ operationId: '', cwd: '/tmp/repo', prompt: 'hi' }), /operationId/i)
  await assert.rejects(() => handoff.run({ operationId: 'op-1', cwd: '  ', prompt: 'hi' }), /cwd/i)
  await assert.rejects(() => handoff.run({ operationId: 'op-1', cwd: '/tmp/repo', prompt: '' }), /prompt/i)
})

test('a. happy path: exact ordered call list, exact allowlisted params, backoff timers, onSuccess called once', async () => {
  const callLog = []
  const gw = createFakeGateway(
    [
      {
        expectMethod: 'session.create',
        resolve: { session_id: 'sess-1', stored_session_id: 'stored-1', pending: [], running: false }
      },
      {
        expectMethod: 'session.resume',
        resolve: { session_id: 'sess-1', stored_session_id: 'stored-1', pending: [], running: false }
      },
      {
        expectMethod: 'prompt.submit',
        resolve: {
          admission_id: 'adm-1',
          session_id: 'sess-1',
          submission_id: 'op-happy:submit',
          status: 'started',
          outcome: null
        }
      },
      {
        expectMethod: 'prompt.receipt',
        resolve: { admission_id: 'adm-1', session_id: 'sess-1', status: 'started', outcome: null }
      },
      {
        expectMethod: 'prompt.receipt',
        resolve: {
          admission_id: 'adm-1',
          session_id: 'sess-1',
          status: 'terminal',
          outcome: 'completed',
          result: { summary: 'template adapted' }
        }
      }
    ],
    callLog
  )

  const timers = createFakeTimers()
  let onSuccessCalls = 0
  const fakeHost = {
    getGateway: () => gw,
    async openSession(storedId, opts) {
      callLog.push({ target: 'host.openSession', storedId, opts })
    }
  }

  const handoff = createHandoff({
    host: fakeHost,
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    pollIntervalMs: 1000,
    maxPollIntervalMs: 5000
  })

  const runPromise = handoff.run({
    operationId: 'op-happy',
    cwd: '/remote/work/templates',
    profile: 'default',
    title: 'Adapt template for game',
    prompt: 'Please adapt template',
    onSuccess: () => {
      onSuccessCalls += 1
      return true
    }
  })

  assert.equal(handoff.inFlight('op-happy'), true)
  await timers.flushAll()
  const res = await runPromise
  assert.equal(handoff.inFlight('op-happy'), false)

  assert.equal(onSuccessCalls, 1)
  assert.deepEqual(res, {
    operationId: 'op-happy',
    status: 'completed',
    outcome: 'completed',
    session_id: 'sess-1',
    stored_session_id: 'stored-1',
    admission_id: 'adm-1',
    navigation: 'opened',
    opened: true,
    lint: 'ok',
    result: { summary: 'template adapted' }
  })

  assert.deepEqual(
    callLog.map(c => (c.target === 'gateway' ? c.method : c.target)),
    ['session.create', 'session.resume', 'prompt.submit', 'host.openSession', 'prompt.receipt', 'prompt.receipt']
  )

  assert.deepEqual(callLog[0].params, {
    source: 'desktop',
    cwd: '/remote/work/templates',
    cwd_explicit: true,
    profile: 'default',
    title: 'Adapt template for game',
    hidden: false,
    request_id: 'op-happy:create'
  })
  assert.deepEqual(callLog[1].params, {
    session_id: 'sess-1',
    profile: 'default'
  })
  assert.deepEqual(callLog[2].params, {
    session_id: 'sess-1',
    profile: 'default',
    text: 'Please adapt template',
    submission_id: 'op-happy:submit',
    queued: false
  })
  assert.equal('unattended' in callLog[2].params, false)
  assert.equal('yolo' in callLog[2].params, false)
  assert.equal('finite' in callLog[2].params, false)

  assert.equal(callLog[3].storedId, 'stored-1')
  assert.deepEqual(callLog[3].opts, { profile: 'default' })

  assert.deepEqual(callLog[4].params, {
    session_id: 'sess-1',
    admission_id: 'adm-1',
    include_result: true
  })
  assert.deepEqual(timers.delays, [1000, 2000])
  assert.equal(timers.pending.size, 0)
  assert.equal(timers.cleared.length, timers.delays.length)
})

test('b. double-click idempotency: in-flight returns same promise, settled returns cached result without extra RPCs', async () => {
  const callLog = []
  const gw = createFakeGateway(
    [
      {
        expectMethod: 'session.create',
        resolve: { session_id: 'sess-2', stored_session_id: 'stored-2', pending: [] }
      },
      {
        expectMethod: 'session.resume',
        resolve: { session_id: 'sess-2', stored_session_id: 'stored-2', pending: [] }
      },
      {
        expectMethod: 'prompt.submit',
        resolve: { admission_id: 'adm-2', session_id: 'sess-2', submission_id: 'op-dbl:submit', status: 'started', outcome: null }
      },
      {
        expectMethod: 'prompt.receipt',
        resolve: { admission_id: 'adm-2', session_id: 'sess-2', status: 'terminal', outcome: 'completed' }
      }
    ],
    callLog
  )

  const timers = createFakeTimers()
  let onSuccessCalls = 0
  const handoff = createHandoff({
    host: { getGateway: () => gw, openSession: async () => {} },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })

  const op = {
    operationId: 'op-dbl',
    cwd: '/work',
    profile: 'default',
    title: 'Double click test',
    prompt: 'Fix lint',
    onSuccess: () => {
      onSuccessCalls += 1
    }
  }

  const p1 = handoff.run(op)
  const p2 = handoff.run(op)
  assert.strictEqual(p1, p2)

  await timers.flushAll()
  const r1 = await p1
  const r2 = await p2
  assert.deepEqual(r1, r2)
  assert.equal(onSuccessCalls, 1)
  assert.equal(gw.requests.length, 4)

  const r3 = await handoff.run(op)
  assert.deepEqual(r3, r1)
  assert.equal(gw.requests.length, 4)
  assert.equal(onSuccessCalls, 1)
})

test('c. lost submit response, recovered via session.resume pending input_id === submission_id', async () => {
  const callLog = []
  const gw = createFakeGateway(
    [
      {
        expectMethod: 'session.create',
        resolve: { session_id: 'sess-rec', stored_session_id: 'stored-rec', pending: [] }
      },
      {
        expectMethod: 'session.resume',
        resolve: { session_id: 'sess-rec', stored_session_id: 'stored-rec', pending: [] }
      },
      {
        expectMethod: 'prompt.submit',
        reject: new Error('Request timed out')
      },
      {
        expectMethod: 'session.resume',
        resolve: {
          session_id: 'sess-rec',
          stored_session_id: 'stored-rec',
          pending: [
            {
              admission_id: 'adm-recovered',
              input_id: 'op-rec:submit',
              text: 'Do work',
              status: 'started',
              outcome: null
            }
          ]
        }
      },
      {
        expectMethod: 'prompt.receipt',
        resolve: {
          admission_id: 'adm-recovered',
          session_id: 'sess-rec',
          status: 'terminal',
          outcome: 'completed'
        }
      }
    ],
    callLog
  )

  const timers = createFakeTimers()
  let onSuccessCalls = 0
  const handoff = createHandoff({
    host: { getGateway: () => gw, openSession: async () => {} },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })

  const p = handoff.run({
    operationId: 'op-rec',
    cwd: '/work',
    profile: 'default',
    title: 'Recover test',
    prompt: 'Do work',
    onSuccess: () => {
      onSuccessCalls += 1
    }
  })

  await timers.flushAll()
  const res = await p

  assert.equal(res.status, 'completed')
  assert.equal(res.admission_id, 'adm-recovered')
  assert.equal(onSuccessCalls, 1)
  assert.equal(gw.requests.filter(r => r.method === 'prompt.submit').length, 1)
})

test('d. lost submit response, not recoverable when pending is empty -> status unknown, onSuccess not called', async () => {
  const gw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-unrec', stored_session_id: 'stored-unrec', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-unrec', stored_session_id: 'stored-unrec', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      reject: new Error('Request timed out')
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-unrec', stored_session_id: 'stored-unrec', pending: [] }
    }
  ])

  const timers = createFakeTimers()
  let onSuccessCalls = 0
  const handoff = createHandoff({
    host: { getGateway: () => gw, openSession: async () => {} },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })

  const p = handoff.run({
    operationId: 'op-unrec',
    cwd: '/work',
    profile: 'default',
    title: 'Unrecoverable test',
    prompt: 'Do work',
    onSuccess: () => {
      onSuccessCalls += 1
    }
  })

  await timers.flushAll()
  const res = await p

  assert.equal(res.status, 'unknown')
  assert.equal(res.outcome, null)
  assert.equal(res.admission_id, null)
  assert.equal(onSuccessCalls, 0)
  assert.equal(gw.requests.filter(r => r.method === 'prompt.submit').length, 1)
})

test('e. receipt timeout is retried; receipt method-not-found returns untracked', async () => {
  const gwRetry = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-rt', stored_session_id: 'stored-rt', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-rt', stored_session_id: 'stored-rt', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-rt', session_id: 'sess-rt', submission_id: 'op-rt:submit', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      reject: new Error('RPC timeout waiting for prompt.receipt')
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-rt', session_id: 'sess-rt', status: 'terminal', outcome: 'completed' }
    }
  ])

  const timers1 = createFakeTimers()
  const handoff1 = createHandoff({
    host: { getGateway: () => gwRetry, openSession: async () => {} },
    setTimeout: timers1.setTimeout,
    clearTimeout: timers1.clearTimeout
  })

  const p1 = handoff1.run({
    operationId: 'op-rt',
    cwd: '/work',
    profile: 'default',
    title: 'Retry receipt',
    prompt: 'Do work'
  })
  await timers1.flushAll()
  const res1 = await p1
  assert.equal(res1.status, 'completed')
  assert.equal(gwRetry.requests.filter(r => r.method === 'prompt.receipt').length, 2)
  assert.equal(timers1.pending.size, 0)
  assert.equal(timers1.cleared.length, timers1.delays.length)

  const methodNotFoundErr = Object.assign(new Error('Method not found: prompt.receipt'), { code: -32601 })
  const gwUntracked = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-ut', stored_session_id: 'stored-ut', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-ut', stored_session_id: 'stored-ut', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-ut', session_id: 'sess-ut', submission_id: 'op-ut:submit', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      reject: methodNotFoundErr
    }
  ])

  const timers2 = createFakeTimers()
  let onSuccess2 = 0
  const handoff2 = createHandoff({
    host: { getGateway: () => gwUntracked, openSession: async () => {} },
    setTimeout: timers2.setTimeout,
    clearTimeout: timers2.clearTimeout
  })

  const p2 = handoff2.run({
    operationId: 'op-ut',
    cwd: '/work',
    profile: 'default',
    title: 'Untracked receipt',
    prompt: 'Do work',
    onSuccess: () => {
      onSuccess2 += 1
    }
  })
  await timers2.flushAll()
  const res2 = await p2
  assert.equal(res2.status, 'untracked')
  assert.equal(onSuccess2, 0)
  assert.equal(timers2.pending.size, 0)
  assert.equal(timers2.cleared.length, timers2.delays.length)
})

test('f. connection switch mid-await keeps using pinned gatewayA and never calls gatewayB', async () => {
  let activeGateway = null
  const gatewayB = createFakeGateway([])
  const gatewayA = createFakeGateway([
    {
      expectMethod: 'session.create',
      handler: async () => {
        activeGateway = gatewayB
        return { session_id: 'sess-sw', stored_session_id: 'stored-sw', pending: [] }
      }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-sw', stored_session_id: 'stored-sw', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-sw', session_id: 'sess-sw', submission_id: 'op-sw:submit', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      reject: new Error('Gateway socket is not connected')
    }
  ])
  activeGateway = gatewayA

  const timers = createFakeTimers()
  const handoff = createHandoff({
    host: { getGateway: () => activeGateway, openSession: async () => {} },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })

  const p = handoff.run({
    operationId: 'op-sw',
    cwd: '/work',
    profile: 'default',
    title: 'Switch test',
    prompt: 'Do work'
  })
  await timers.flushAll()
  const res = await p

  assert.equal(res.status, 'lost')
  assert.equal(gatewayB.requests.length, 0)
  assert.equal(gatewayA.requests.length, 4)
  assert.equal(timers.pending.size, 0)
  assert.equal(timers.cleared.length, timers.delays.length)
})

test('g. non-success outcomes (cancelled, failed, settled_unknown) map status and never call onSuccess', async () => {
  const cases = [
    { outcome: 'cancelled', expectedStatus: 'cancelled' },
    { outcome: 'failed', expectedStatus: 'failed' },
    { outcome: 'settled_unknown', expectedStatus: 'unknown' }
  ]

  for (const { outcome, expectedStatus } of cases) {
    const gw = createFakeGateway([
      {
        expectMethod: 'session.create',
        resolve: { session_id: `sess-${outcome}`, stored_session_id: `stored-${outcome}`, pending: [] }
      },
      {
        expectMethod: 'session.resume',
        resolve: { session_id: `sess-${outcome}`, stored_session_id: `stored-${outcome}`, pending: [] }
      },
      {
        expectMethod: 'prompt.submit',
        resolve: { admission_id: `adm-${outcome}`, session_id: `sess-${outcome}`, status: 'started', outcome: null }
      },
      {
        expectMethod: 'prompt.receipt',
        resolve: { admission_id: `adm-${outcome}`, session_id: `sess-${outcome}`, status: 'terminal', outcome }
      }
    ])

    const timers = createFakeTimers()
    let onSuccessCalls = 0
    const handoff = createHandoff({
      host: { getGateway: () => gw, openSession: async () => {} },
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout
    })

    const p = handoff.run({
      operationId: `op-${outcome}`,
      cwd: '/work',
      profile: 'default',
      title: `Outcome ${outcome}`,
      prompt: 'Do work',
      onSuccess: () => {
        onSuccessCalls += 1
      }
    })
    await timers.flushAll()
    const res = await p

    assert.equal(res.status, expectedStatus)
    assert.equal(res.outcome, outcome)
    assert.equal(onSuccessCalls, 0)
    assert.equal(timers.pending.size, 0)
    assert.equal(timers.cleared.length, timers.delays.length)
  }
})

test('h. openSession rejection does not fail the run (opened:false, open_error set) and tracking still completes', async () => {
  const gw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-open-err', stored_session_id: 'stored-open-err', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-open-err', stored_session_id: 'stored-open-err', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-open-err', session_id: 'sess-open-err', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-open-err', session_id: 'sess-open-err', status: 'terminal', outcome: 'completed' }
    }
  ])

  const timers = createFakeTimers()
  let onSuccessCalls = 0
  const handoff = createHandoff({
    host: {
      getGateway: () => gw,
      async openSession() {
        throw new Error('Draft session not yet persisted')
      }
    },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })

  const p = handoff.run({
    operationId: 'op-open-err',
    cwd: '/work',
    profile: 'default',
    title: 'Open error test',
    prompt: 'Do work',
    onSuccess: () => {
      onSuccessCalls += 1
    }
  })
  await timers.flushAll()
  const res = await p

  assert.equal(res.status, 'completed')
  assert.equal(res.opened, false)
  assert.match(res.open_error, /Draft session not yet persisted/)
  assert.equal(onSuccessCalls, 1)
})

test('i. null gateway returns status error with Hermes gateway unavailable and performs no RPC', async () => {
  const timers = createFakeTimers()
  let openCalled = false
  const handoff = createHandoff({
    host: {
      getGateway: () => null,
      async openSession() {
        openCalled = true
      }
    },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })

  const res = await handoff.run({
    operationId: 'op-null-gw',
    cwd: '/work',
    profile: 'default',
    title: 'Null gateway',
    prompt: 'Do work'
  })

  assert.equal(res.status, 'error')
  assert.equal(res.error, 'Hermes gateway unavailable')
  assert.equal(res.opened, false)
  assert.equal(openCalled, false)
})

test('j. bounded unknown receipt polling, requestTimeoutMs forwarding, recovery rejection -> lost, and onSuccess error caught', async () => {
  const gwUnknown = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-unk', stored_session_id: '', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-unk', stored_session_id: '', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-unk', session_id: 'sess-unk', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-unk', session_id: 'sess-unk', status: 'unknown', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-unk', session_id: 'sess-unk', status: 'unknown', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-unk', session_id: 'sess-unk', status: 'unknown', outcome: null }
    }
  ])

  const timers = createFakeTimers()
  const handoff = createHandoff({
    host: { getGateway: () => gwUnknown, openSession: async () => {} },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    requestTimeoutMs: 4500
  })

  const p = handoff.run({
    operationId: 'op-unk-bound',
    cwd: '/work',
    profile: 'default',
    title: 'Bounded unknown',
    prompt: 'Do work'
  })
  await timers.flushAll()
  const res = await p
  assert.equal(res.status, 'unknown')
  assert.equal(res.opened, false)
  assert.equal(gwUnknown.requests[0].timeoutMs, 4500)
  assert.equal(gwUnknown.requests.filter(r => r.method === 'prompt.receipt').length, 3)

  const gwRecLost = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-lost', stored_session_id: 'stored-lost', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-lost', stored_session_id: 'stored-lost', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      reject: new Error('submit timed out')
    },
    {
      expectMethod: 'session.resume',
      reject: new Error('socket closed')
    }
  ])
  const timersLost = createFakeTimers()
  const handoffLost = createHandoff({
    host: { getGateway: () => gwRecLost, openSession: async () => {} },
    setTimeout: timersLost.setTimeout,
    clearTimeout: timersLost.clearTimeout
  })
  const resLost = await handoffLost.run({
    operationId: 'op-rec-lost',
    cwd: '/work',
    profile: 'default',
    title: 'Recovery lost',
    prompt: 'Do work'
  })
  assert.equal(resLost.status, 'lost')

  const gwCbErr = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-cb', stored_session_id: 'stored-cb', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-cb', stored_session_id: 'stored-cb', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-cb', session_id: 'sess-cb', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-cb', session_id: 'sess-cb', status: 'terminal', outcome: 'completed' }
    }
  ])
  const timersCb = createFakeTimers()
  const handoffCb = createHandoff({
    host: { getGateway: () => gwCbErr, openSession: async () => {} },
    setTimeout: timersCb.setTimeout,
    clearTimeout: timersCb.clearTimeout
  })
  const pCb = handoffCb.run({
    operationId: 'op-cb-err',
    cwd: '/work',
    profile: 'default',
    title: 'Callback error',
    prompt: 'Do work',
    onSuccess: () => {
      throw new Error('lint rerun boom')
    }
  })
  await timersCb.flushAll()
  const resCb = await pCb
  assert.equal(resCb.status, 'completed')
  assert.match(resCb.error, /lint rerun boom/)
  assert.equal(timersCb.pending.size, 0)
  assert.equal(timersCb.cleared.length, timersCb.delays.length)
})

test('k. getGateway throwing settles as cached error result, clears inFlight, and never re-invokes getGateway/RPC', async () => {
  const timers = createFakeTimers()
  let getGatewayCalls = 0
  const handoff = createHandoff({
    host: {
      getGateway() {
        getGatewayCalls += 1
        throw new Error('gateway factory exploded')
      },
      openSession: async () => {}
    },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })

  const op = {
    operationId: 'op-gw-throw',
    cwd: '/work',
    profile: 'default',
    title: 'Gateway throw',
    prompt: 'Do work'
  }

  const res1 = await handoff.run(op)
  assert.equal(handoff.inFlight('op-gw-throw'), false)
  assert.equal(res1.status, 'error')
  assert.match(res1.error, /gateway factory exploded/)
  assert.equal(getGatewayCalls, 1)

  const res2 = await handoff.run(op)
  assert.deepEqual(res2, res1)
  assert.equal(handoff.inFlight('op-gw-throw'), false)
  assert.equal(getGatewayCalls, 1)
})

test('l. malformed prompt.receipt responses (including out-of-contract status:running) count toward bounded unknown budget and settle with malformed receipt error', async () => {
  const gwNulls = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-mal', stored_session_id: 'stored-mal', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-mal', stored_session_id: 'stored-mal', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-mal', session_id: 'sess-mal', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: null
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: 'not-an-object'
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { status: 'unrecognised_status' }
    }
  ])

  const timers = createFakeTimers()
  let onSuccessCalls = 0
  const handoff = createHandoff({
    host: { getGateway: () => gwNulls, openSession: async () => {} },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })

  const p = handoff.run({
    operationId: 'op-malformed',
    cwd: '/work',
    profile: 'default',
    title: 'Malformed receipts',
    prompt: 'Do work',
    onSuccess: () => {
      onSuccessCalls += 1
    }
  })

  await timers.flushAll()
  const res = await p
  assert.equal(res.status, 'unknown')
  assert.equal(res.outcome, null)
  assert.equal(res.error, 'malformed receipt')
  assert.equal(onSuccessCalls, 0)
  assert.equal(gwNulls.requests.filter(r => r.method === 'prompt.receipt').length, 3)
  assert.equal(timers.pending.size, 0)
  assert.equal(timers.cleared.length, timers.delays.length)

  const gwRunning = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-run-mal', stored_session_id: 'stored-run-mal', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-run-mal', stored_session_id: 'stored-run-mal', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-run-mal', session_id: 'sess-run-mal', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-run-mal', session_id: 'sess-run-mal', status: 'running', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-run-mal', session_id: 'sess-run-mal', status: 'running', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-run-mal', session_id: 'sess-run-mal', status: 'running', outcome: null }
    }
  ])

  const timersRun = createFakeTimers()
  let onSuccessRun = 0
  const handoffRun = createHandoff({
    host: { getGateway: () => gwRunning, openSession: async () => {} },
    setTimeout: timersRun.setTimeout,
    clearTimeout: timersRun.clearTimeout
  })

  const pRun = handoffRun.run({
    operationId: 'op-running-malformed',
    cwd: '/work',
    profile: 'default',
    title: 'Running receipts malformed',
    prompt: 'Do work',
    onSuccess: () => {
      onSuccessRun += 1
    }
  })

  await timersRun.flushAll()
  const resRun = await pRun
  assert.equal(resRun.status, 'unknown')
  assert.equal(resRun.outcome, null)
  assert.equal(resRun.error, 'malformed receipt')
  assert.equal(onSuccessRun, 0)
  assert.equal(gwRunning.requests.filter(r => r.method === 'prompt.receipt').length, 3)
  assert.equal(timersRun.pending.size, 0)
  assert.equal(timersRun.cleared.length, timersRun.delays.length)
})

test('m. release(operationId) is false/no-op while in-flight, without release re-runs after settlement never resubmit, and after release subsequent run() starts fresh', async () => {
  const gw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-f1', stored_session_id: 'stored-f1', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-f1', stored_session_id: 'stored-f1', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-f1', session_id: 'sess-f1', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: {
        admission_id: 'adm-f1',
        session_id: 'sess-f1',
        status: 'terminal',
        outcome: 'completed',
        result: { run: 1 }
      }
    },
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-f2', stored_session_id: 'stored-f2', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-f2', stored_session_id: 'stored-f2', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-f2', session_id: 'sess-f2', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: {
        admission_id: 'adm-f2',
        session_id: 'sess-f2',
        status: 'terminal',
        outcome: 'completed',
        result: { run: 2 }
      }
    }
  ])

  const timers = createFakeTimers()
  const handoff = createHandoff({
    host: { getGateway: () => gw, openSession: async () => {} },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout
  })

  const op = {
    operationId: 'op-release',
    cwd: '/work',
    profile: 'default',
    title: 'Release test',
    prompt: 'Do work'
  }

  assert.equal(handoff.release('op-release'), false)

  const p1 = handoff.run(op)
  assert.equal(handoff.inFlight('op-release'), true)
  assert.equal(handoff.release('op-release'), false)
  assert.strictEqual(handoff.run(op), p1)

  await timers.flushAll()
  const r1 = await p1
  assert.deepEqual(r1.result, { run: 1 })
  assert.equal(gw.requests.length, 4)
  assert.equal(gw.requests.filter(r => r.method === 'prompt.submit').length, 1)

  // Without release(), re-running after settlement returns cached result and never resubmits
  const rCached = await handoff.run(op)
  assert.deepEqual(rCached, r1)
  assert.deepEqual(rCached.result, { run: 1 })
  assert.equal(gw.requests.length, 4)
  assert.equal(gw.requests.filter(r => r.method === 'prompt.submit').length, 1)

  assert.equal(handoff.release('op-release'), true)
  assert.equal(handoff.release('op-release'), false)

  const p2 = handoff.run(op)
  await timers.flushAll()
  const r2 = await p2
  assert.deepEqual(r2.result, { run: 2 })
  assert.equal(r2.session_id, 'sess-f2')
  assert.equal(gw.requests.length, 8)
  assert.equal(gw.requests.filter(r => r.method === 'prompt.submit').length, 2)
  assert.equal(timers.pending.size, 0)
  assert.equal(timers.cleared.length, timers.delays.length)
})

test('n. narrow error classification: "session closed by owner" and "unsupported result format" are not treated as lost/untracked', async () => {
  for (const errMsg of ['session closed by owner', 'unsupported result format']) {
    const gw = createFakeGateway([
      {
        expectMethod: 'session.create',
        resolve: { session_id: 'sess-narrow', stored_session_id: 'stored-narrow', pending: [] }
      },
      {
        expectMethod: 'session.resume',
        resolve: { session_id: 'sess-narrow', stored_session_id: 'stored-narrow', pending: [] }
      },
      {
        expectMethod: 'prompt.submit',
        resolve: { admission_id: 'adm-narrow', session_id: 'sess-narrow', status: 'started', outcome: null }
      },
      {
        expectMethod: 'prompt.receipt',
        reject: new Error(errMsg)
      },
      {
        expectMethod: 'prompt.receipt',
        reject: new Error(errMsg)
      },
      {
        expectMethod: 'prompt.receipt',
        reject: new Error(errMsg)
      }
    ])

    const timers = createFakeTimers()
    const handoff = createHandoff({
      host: { getGateway: () => gw, openSession: async () => {} },
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout
    })

    const p = handoff.run({
      operationId: `op-narrow:${errMsg}`,
      cwd: '/work',
      profile: 'default',
      title: 'Narrow error regex test',
      prompt: 'Do work'
    })
    await timers.flushAll()
    const res = await p
    assert.equal(res.status, 'unknown')
    assert.equal(res.outcome, null)
    assert.equal(res.error, errMsg)
    assert.equal(gw.requests.filter(r => r.method === 'prompt.receipt').length, 3)
    assert.equal(timers.pending.size, 0)
    assert.equal(timers.cleared.length, timers.delays.length)
  }
})

test('o. backoff cap: pollIntervalMs:1000, maxPollIntervalMs:2500 produces delays [1000, 2000, 2500, 2500] and clears all timers', async () => {
  const gw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-cap', stored_session_id: 'stored-cap', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-cap', stored_session_id: 'stored-cap', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-cap', session_id: 'sess-cap', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-cap', session_id: 'sess-cap', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-cap', session_id: 'sess-cap', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-cap', session_id: 'sess-cap', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-cap', session_id: 'sess-cap', status: 'terminal', outcome: 'completed' }
    }
  ])

  const timers = createFakeTimers()
  const handoff = createHandoff({
    host: { getGateway: () => gw, openSession: async () => {} },
    setTimeout: timers.setTimeout,
    clearTimeout: timers.clearTimeout,
    pollIntervalMs: 1000,
    maxPollIntervalMs: 2500
  })

  const p = handoff.run({
    operationId: 'op-cap',
    cwd: '/work',
    profile: 'default',
    title: 'Backoff cap',
    prompt: 'Do work'
  })
  await timers.flushAll()
  const res = await p
  assert.equal(res.status, 'completed')
  assert.deepEqual(timers.delays, [1000, 2000, 2500, 2500])
  assert.equal(timers.pending.size, 0)
  assert.equal(timers.cleared.length, 4)
})

test('p. structured error codes classify generic message ("rpc failed") into untracked or lost', async () => {
  for (const code of [-32601, 'METHOD_NOT_FOUND']) {
    const err = Object.assign(new Error('rpc failed'), { code })
    const gw = createFakeGateway([
      {
        expectMethod: 'session.create',
        resolve: { session_id: `sess-code-${code}`, stored_session_id: `stored-code-${code}`, pending: [] }
      },
      {
        expectMethod: 'session.resume',
        resolve: { session_id: `sess-code-${code}`, stored_session_id: `stored-code-${code}`, pending: [] }
      },
      {
        expectMethod: 'prompt.submit',
        resolve: { admission_id: `adm-code-${code}`, session_id: `sess-code-${code}`, status: 'started', outcome: null }
      },
      {
        expectMethod: 'prompt.receipt',
        reject: err
      }
    ])

    const timers = createFakeTimers()
    let onSuccessCalls = 0
    const handoff = createHandoff({
      host: { getGateway: () => gw, openSession: async () => {} },
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout
    })

    const p = handoff.run({
      operationId: `op-code:${code}`,
      cwd: '/work',
      profile: 'default',
      title: `Method code ${code}`,
      prompt: 'Do work',
      onSuccess: () => {
        onSuccessCalls += 1
      }
    })
    await timers.flushAll()
    const res = await p
    assert.equal(res.status, 'untracked')
    assert.equal(res.outcome, null)
    assert.equal(res.error, 'rpc failed')
    assert.equal(onSuccessCalls, 0)
    assert.equal(gw.requests.filter(r => r.method === 'prompt.receipt').length, 1)
    assert.equal(timers.pending.size, 0)
    assert.equal(timers.cleared.length, timers.delays.length)
  }

  const disconnectCodes = ['ECONNRESET', 'ECONNREFUSED', 'EPIPE', 'ENOTCONN', 'ERR_SOCKET_CLOSED']
  for (const code of disconnectCodes) {
    const err = Object.assign(new Error('rpc failed'), { code })
    const gw = createFakeGateway([
      {
        expectMethod: 'session.create',
        resolve: { session_id: `sess-disc-${code}`, stored_session_id: `stored-disc-${code}`, pending: [] }
      },
      {
        expectMethod: 'session.resume',
        resolve: { session_id: `sess-disc-${code}`, stored_session_id: `stored-disc-${code}`, pending: [] }
      },
      {
        expectMethod: 'prompt.submit',
        resolve: { admission_id: `adm-disc-${code}`, session_id: `sess-disc-${code}`, status: 'started', outcome: null }
      },
      {
        expectMethod: 'prompt.receipt',
        reject: err
      }
    ])

    const timers = createFakeTimers()
    let onSuccessCalls = 0
    const handoff = createHandoff({
      host: { getGateway: () => gw, openSession: async () => {} },
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout
    })

    const p = handoff.run({
      operationId: `op-disc:${code}`,
      cwd: '/work',
      profile: 'default',
      title: `Disconnect code ${code}`,
      prompt: 'Do work',
      onSuccess: () => {
        onSuccessCalls += 1
      }
    })
    await timers.flushAll()
    const res = await p
    assert.equal(res.status, 'lost')
    assert.equal(res.outcome, null)
    assert.equal(res.error, 'rpc failed')
    assert.equal(onSuccessCalls, 0)
    assert.equal(gw.requests.filter(r => r.method === 'prompt.receipt').length, 1)
    assert.equal(timers.pending.size, 0)
    assert.equal(timers.cleared.length, timers.delays.length)
  }
})

test('q. overall maxWaitMs bound: infinite started/queued or timeout polls terminate as timed_out without retrying prompt.submit', async () => {
  let receiptCalls = 0
  const gwStarted = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-wait', stored_session_id: 'stored-wait', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-wait', stored_session_id: 'stored-wait', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-wait', session_id: 'sess-wait', submission_id: 'op-wait:submit', status: 'started', outcome: null }
    },
    ...Array.from({ length: 20 }, () => ({
      expectMethod: 'prompt.receipt',
      handler: async () => {
        receiptCalls += 1
        return { admission_id: 'adm-wait', session_id: 'sess-wait', status: 'started', outcome: null }
      }
    }))
  ])

  const timers1 = createFakeTimers()
  let onSuccessCalls = 0
  const handoff1 = createHandoff({
    host: { getGateway: () => gwStarted, openSession: async () => {} },
    setTimeout: timers1.setTimeout,
    clearTimeout: timers1.clearTimeout,
    pollIntervalMs: 1000,
    maxPollIntervalMs: 2000,
    maxWaitMs: 3500
  })

  const p1 = handoff1.run({
    operationId: 'op-wait',
    cwd: '/work',
    profile: 'default',
    title: 'Max wait test',
    prompt: 'Do work',
    onSuccess: () => {
      onSuccessCalls += 1
    }
  })

  await timers1.flushAll()
  const res1 = await p1

  assert.equal(res1.status, 'timed_out')
  assert.equal(res1.outcome, null)
  assert.match(res1.error, /timed out/i)
  assert.equal(onSuccessCalls, 0)
  assert.equal(gwStarted.requests.filter(r => r.method === 'prompt.submit').length, 1)
  assert.equal(receiptCalls, 2) // 1000ms + 2000ms polls; final 500ms hits 3500ms deadline so no post-deadline RPC
  assert.deepEqual(timers1.delays, [1000, 2000, 500])
  assert.equal(handoff1.inFlight('op-wait'), false)
  assert.equal(timers1.pending.size, 0)
  assert.equal(timers1.cleared.length, timers1.delays.length)

  // Repeated ETIMEDOUT on prompt.receipt is also bounded by maxWaitMs without retrying submit
  let timeoutReceiptCalls = 0
  const gwTimeoutLoop = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-to', stored_session_id: 'stored-to', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-to', stored_session_id: 'stored-to', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-to', session_id: 'sess-to', submission_id: 'op-to:submit', status: 'started', outcome: null }
    },
    ...Array.from({ length: 20 }, () => ({
      expectMethod: 'prompt.receipt',
      handler: async () => {
        timeoutReceiptCalls += 1
        throw Object.assign(new Error('ETIMEDOUT waiting for receipt'), { code: 'ETIMEDOUT' })
      }
    }))
  ])

  const timers2 = createFakeTimers()
  const handoff2 = createHandoff({
    host: { getGateway: () => gwTimeoutLoop, openSession: async () => {} },
    setTimeout: timers2.setTimeout,
    clearTimeout: timers2.clearTimeout,
    pollIntervalMs: 1000,
    maxPollIntervalMs: 2000,
    maxWaitMs: 3000
  })

  const p2 = handoff2.run({
    operationId: 'op-to',
    cwd: '/work',
    profile: 'default',
    title: 'Timeout loop test',
    prompt: 'Do work'
  })

  await timers2.flushAll()
  const res2 = await p2

  assert.equal(res2.status, 'timed_out')
  assert.equal(res2.outcome, null)
  assert.match(res2.error, /timed out/i)
  assert.equal(gwTimeoutLoop.requests.filter(r => r.method === 'prompt.submit').length, 1)
  assert.equal(timeoutReceiptCalls, 1)
  assert.equal(timers2.pending.size, 0)
  assert.equal(timers2.cleared.length, timers2.delays.length)
})

test('t. wall-clock maxWaitMs bound: maxWaitMs 10, poll 5ms, receipts delayed 80ms settles timed_out within ~maxWaitMs with at most one in-flight receipt and ignores late responses', async () => {
  let receiptCalls = 0
  let inFlightReceipts = 0
  let maxInFlightReceipts = 0
  let onSuccessCalls = 0

  const gwSlowReceipt = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-wc', stored_session_id: 'stored-wc', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-wc', stored_session_id: 'stored-wc', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-wc',
        session_id: 'sess-wc',
        submission_id: 'op-wc:submit',
        status: 'started',
        outcome: null
      }
    },
    ...Array.from({ length: 5 }, () => ({
      expectMethod: 'prompt.receipt',
      handler: async () => {
        receiptCalls += 1
        inFlightReceipts += 1
        maxInFlightReceipts = Math.max(maxInFlightReceipts, inFlightReceipts)
        await new Promise(resolve => setTimeout(resolve, 80))
        inFlightReceipts -= 1
        return {
          admission_id: 'adm-wc',
          session_id: 'sess-wc',
          status: 'terminal',
          outcome: 'completed',
          result: { late: true }
        }
      }
    }))
  ])

  const handoff = createHandoff({
    host: { getGateway: () => gwSlowReceipt, openSession: async () => {} },
    pollIntervalMs: 5,
    maxPollIntervalMs: 10,
    maxWaitMs: 10
  })

  const start = performance.now()
  const res = await handoff.run({
    operationId: 'op-wc',
    cwd: '/work',
    profile: 'default',
    title: 'Wall-clock repro',
    prompt: 'Do work',
    onSuccess: () => {
      onSuccessCalls += 1
    }
  })
  const elapsed = performance.now() - start

  assert.equal(res.status, 'timed_out')
  assert.equal(res.outcome, null)
  assert.ok(elapsed < 55, `Expected settlement near 10ms maxWaitMs, got ${elapsed.toFixed(1)}ms`)
  // A loaded event loop may consume the entire 10ms budget before the first
  // poll. Zero calls is correct fail-closed behavior, not a deadline violation.
  assert.ok(receiptCalls <= 1)
  assert.equal(maxInFlightReceipts, receiptCalls)
  const issuedReceiptCalls = receiptCalls

  // Every issued RPC received timeout = min(default, remaining)
  for (const req of gwSlowReceipt.requests) {
    assert.equal(typeof req.timeoutMs, 'number')
    assert.ok(req.timeoutMs > 0 && req.timeoutMs <= 10, `Expected timeoutMs in (0, 10], got ${req.timeoutMs}`)
  }
  const receiptReq = gwSlowReceipt.requests.find(r => r.method === 'prompt.receipt')
  if (receiptReq) assert.ok(receiptReq.timeoutMs <= 6, `Expected receipt timeoutMs <= 6ms remaining, got ${receiptReq.timeoutMs}`)

  // Wait for the delayed 80ms receipt to finish and verify late completion/callbacks are ignored
  await new Promise(resolve => setTimeout(resolve, 95))
  assert.equal(onSuccessCalls, 0)
  assert.equal(receiptCalls, issuedReceiptCalls)
  const cached = await handoff.run({
    operationId: 'op-wc',
    cwd: '/work',
    profile: 'default',
    title: 'Wall-clock repro',
    prompt: 'Do work'
  })
  assert.equal(cached.status, 'timed_out')

  // Also verify deadline covers create/resume/submit/openSession without issuing subsequent RPCs
  let afterSubmitCalls = 0
  let openCalls = 0
  const gwSlowSubmit = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-wc2', stored_session_id: 'stored-wc2', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-wc2', stored_session_id: 'stored-wc2', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      handler: async () => {
        await new Promise(resolve => setTimeout(resolve, 80))
        return { admission_id: 'adm-wc2', session_id: 'sess-wc2', status: 'started', outcome: null }
      }
    },
    {
      expectMethod: 'session.resume',
      handler: async () => {
        afterSubmitCalls += 1
        return { session_id: 'sess-wc2', stored_session_id: 'stored-wc2', pending: [] }
      }
    }
  ])

  const handoffSlowSubmit = createHandoff({
    host: {
      getGateway: () => gwSlowSubmit,
      async openSession() {
        openCalls += 1
      }
    },
    pollIntervalMs: 5,
    maxWaitMs: 10
  })

  const start2 = performance.now()
  const res2 = await handoffSlowSubmit.run({
    operationId: 'op-wc-submit',
    cwd: '/work',
    profile: 'default',
    title: 'Slow submit deadline',
    prompt: 'Do work'
  })
  const elapsed2 = performance.now() - start2

  assert.equal(res2.status, 'timed_out')
  assert.ok(elapsed2 < 55, `Expected submit timeout near 10ms, got ${elapsed2.toFixed(1)}ms`)
  assert.equal(afterSubmitCalls, 0)
  assert.equal(openCalls, 0)
  await new Promise(resolve => setTimeout(resolve, 95))
  assert.equal(afterSubmitCalls, 0)
  assert.equal(openCalls, 0)
})

test('u. explicit op.connection validated on getGateway path: fails closed before first RPC when gateway connection id differs or is unavailable', async () => {
  // 1. host.activeConnectionId() !== op.connection on getGateway path
  let openCalled = false
  const gwMismatchHost = createFakeGateway([
    {
      expectMethod: 'session.create',
      handler: async () => {
        await new Promise(resolve => setTimeout(resolve, 10))
        return { session_id: 'sess-should-not-run', stored_session_id: 'stored-no', pending: [] }
      }
    }
  ])

  const handoffMismatchHost = createHandoff({
    host: {
      activeConnectionId: () => 'conn-B',
      getGateway: () => gwMismatchHost,
      async openSession() {
        openCalled = true
      }
    }
  })

  const res1 = await handoffMismatchHost.run({
    operationId: 'op-conn-gw-mismatch-1',
    cwd: '/work',
    profile: 'default',
    title: 'Explicit conn mismatch via host',
    prompt: 'Do work',
    connection: 'conn-A'
  })

  assert.equal(res1.status, 'lost')
  assert.equal(res1.outcome, null)
  assert.equal(res1.session_id, null)
  assert.equal(res1.admission_id, null)
  assert.equal(res1.opened, false)
  assert.match(res1.error, /connection|gateway/i)
  assert.equal(gwMismatchHost.requests.length, 0)
  assert.equal(openCalled, false)

  // 2. Invented gateway metadata cannot substitute for public host identity
  const gwMismatchDirect = Object.assign(createFakeGateway([]), { connectionId: 'conn-B' })
  const handoffMismatchDirect = createHandoff({
    host: {
      getGateway: () => gwMismatchDirect,
      openSession: async () => {
        openCalled = true
      }
    }
  })

  const res2 = await handoffMismatchDirect.run({
    operationId: 'op-conn-gw-mismatch-2',
    cwd: '/work',
    profile: 'default',
    title: 'Explicit conn mismatch on gateway instance',
    prompt: 'Do work',
    connection: 'conn-A'
  })

  assert.equal(res2.status, 'lost')
  assert.equal(gwMismatchDirect.requests.length, 0)
  assert.equal(openCalled, false)

  // 3. op.connection passed, but gateway/host connection identity is unavailable (null)
  const gwNoConnId = createFakeGateway([])
  const handoffNoConnId = createHandoff({
    host: {
      activeConnectionId: () => null,
      getGateway: () => gwNoConnId,
      openSession: async () => {
        openCalled = true
      }
    }
  })

  const res3 = await handoffNoConnId.run({
    operationId: 'op-conn-gw-null',
    cwd: '/work',
    profile: 'default',
    title: 'Explicit conn with null gateway identity',
    prompt: 'Do work',
    connection: 'conn-A'
  })

  assert.equal(res3.status, 'lost')
  assert.equal(gwNoConnId.requests.length, 0)
  assert.equal(openCalled, false)

  // 4. Matching op.connection on getGateway path succeeds with deferred RPCs
  const gwMatch = createFakeGateway([
    {
      expectMethod: 'session.create',
      handler: async () => {
        await new Promise(resolve => setTimeout(resolve, 5))
        return { session_id: 'sess-match', stored_session_id: 'stored-match', pending: [] }
      }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-match', stored_session_id: 'stored-match', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-match', session_id: 'sess-match', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      handler: async () => {
        await new Promise(resolve => setTimeout(resolve, 5))
        return { admission_id: 'adm-match', session_id: 'sess-match', status: 'terminal', outcome: 'completed' }
      }
    }
  ])

  const handoffMatch = createHandoff({
    host: {
      activeConnectionId: () => 'conn-A',
      getGateway: () => gwMatch,
      openSession: async () => {}
    },
    pollIntervalMs: 5,
    maxWaitMs: 500
  })

  const res4 = await handoffMatch.run({
    operationId: 'op-conn-gw-match',
    cwd: '/work',
    profile: 'default',
    title: 'Explicit conn match',
    prompt: 'Do work',
    connection: 'conn-A'
  })

  assert.equal(res4.status, 'completed')
  assert.equal(gwMatch.requests.length, 4)
})

test('v. host.openSession does not escape pinned connection: passes captured remote owner route when supported else fails closed (status lost, no navigation) when active connection differs', async () => {
  // 1. Bare connectionId pinned ('conn-A'), active connection switches to 'conn-B' during deferred submit -> fails closed ('lost', opened: false, openSession not called)
  let currentConn = 'conn-A'
  let openCalls = 0
  let onSuccessCalls = 0

  const gwSwitchBeforeOpen = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-open-guard', stored_session_id: 'stored-open-guard', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-open-guard', stored_session_id: 'stored-open-guard', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      handler: async () => {
        await new Promise(resolve => setTimeout(resolve, 5))
        currentConn = 'conn-B'
        return {
          admission_id: 'adm-open-guard',
          session_id: 'sess-open-guard',
          submission_id: 'op-open-guard:submit',
          status: 'started',
          outcome: null
        }
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-open-guard', session_id: 'sess-open-guard', status: 'terminal', outcome: 'completed' }
    }
  ])

  const handoffSwitch = createHandoff({
    host: {
      activeConnectionId: () => currentConn,
      getGateway: () => gwSwitchBeforeOpen,
      async openSession() {
        openCalls += 1
      }
    },
    pollIntervalMs: 5,
    maxWaitMs: 500
  })

  const resSwitch = await handoffSwitch.run({
    operationId: 'op-open-guard',
    cwd: '/work',
    profile: 'default',
    title: 'Open guard switch',
    prompt: 'Do work',
    onSuccess: () => {
      onSuccessCalls += 1
    }
  })

  assert.equal(resSwitch.status, 'lost')
  assert.equal(resSwitch.opened, false)
  assert.equal(resSwitch.session_id, 'sess-open-guard')
  assert.equal(resSwitch.stored_session_id, 'stored-open-guard')
  assert.equal(resSwitch.admission_id, 'adm-open-guard')
  assert.equal(openCalls, 0)
  assert.equal(onSuccessCalls, 0)
  assert.equal(gwSwitchBeforeOpen.requests.filter(r => r.method === 'prompt.receipt').length, 0)

  // 2. Active connection becomes null before openSession -> fails closed ('lost', opened: false, openSession not called)
  let connDrop = 'conn-A'
  let openDropCalls = 0
  const gwDropBeforeOpen = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-open-drop', stored_session_id: 'stored-open-drop', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-open-drop', stored_session_id: 'stored-open-drop', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      handler: async () => {
        await new Promise(resolve => setTimeout(resolve, 5))
        connDrop = null
        return {
          admission_id: 'adm-open-drop',
          session_id: 'sess-open-drop',
          submission_id: 'op-open-drop:submit',
          status: 'started',
          outcome: null
        }
      }
    }
  ])

  const handoffDrop = createHandoff({
    host: {
      activeConnectionId: () => connDrop,
      getGateway: () => gwDropBeforeOpen,
      async openSession() {
        openDropCalls += 1
      }
    },
    pollIntervalMs: 5,
    maxWaitMs: 500
  })

  const resDrop = await handoffDrop.run({
    operationId: 'op-open-drop',
    cwd: '/work',
    profile: 'default',
    title: 'Open guard drop',
    prompt: 'Do work'
  })

  assert.equal(resDrop.status, 'lost')
  assert.equal(resDrop.opened, false)
  assert.equal(openDropCalls, 0)

  // 3. When an explicit remote PluginProfileRoute is captured, openSession receives { profile, route }
  let connRoute = 'remote-vps'
  const openRouteCalls = []
  const gwRoute = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-route', stored_session_id: 'stored-route', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-route', stored_session_id: 'stored-route', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      handler: async () => {
        await new Promise(resolve => setTimeout(resolve, 5))
        connRoute = 'other-conn'
        return { admission_id: 'adm-route', session_id: 'sess-route', status: 'started', outcome: null }
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-route', session_id: 'sess-route', status: 'terminal', outcome: 'completed' }
    }
  ])

  const capturedRoute = {
    connectionId: 'remote-vps',
    mode: 'remote',
    profile: 'default',
    targetProfile: 'default'
  }

  const handoffRoute = createHandoff({
    host: {
      activeConnectionId: () => connRoute,
      getGateway: () => gwRoute,
      requestProfile: async (route, method, params, timeoutMs) => {
        assert.equal(route.connectionId, 'remote-vps')
        return gwRoute.request(method, params, timeoutMs)
      },
      async openSession(storedId, opts) {
        openRouteCalls.push({ storedId, opts })
      }
    },
    pollIntervalMs: 5,
    maxWaitMs: 500
  })

  const resRoute = await handoffRoute.run({
    operationId: 'op-open-route',
    cwd: '/work',
    profile: 'default',
    title: 'Open with route',
    prompt: 'Do work',
    connection: capturedRoute
  })

  assert.equal(resRoute.status, 'completed')
  assert.equal(resRoute.opened, true)
  assert.equal(openRouteCalls.length, 1)
  assert.deepEqual(openRouteCalls[0], {
    storedId: 'stored-route',
    opts: { profile: 'default', route: capturedRoute }
  })
})

test('r. host.request fallback when host.getGateway is absent, including single-connection pinning across mid-operation switches', async () => {
  const hostCalls = []
  const fakeGw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-hr', stored_session_id: 'stored-hr', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-hr', stored_session_id: 'stored-hr', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: { admission_id: 'adm-hr', session_id: 'sess-hr', submission_id: 'op-hr:submit', status: 'started', outcome: null }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-hr', session_id: 'sess-hr', status: 'terminal', outcome: 'completed', result: { via: 'host.request' } }
    }
  ])

  const timers1 = createFakeTimers()
  let onSuccessCalls = 0
  const hostWithoutGetGateway = {
    activeConnectionId: () => null,
    state: { connectionId: { get: () => 'local' } },
    async request(method, params, timeoutMs) {
      hostCalls.push({ method, params, timeoutMs })
      return fakeGw.request(method, params, timeoutMs)
    },
    async openSession(storedId, opts) {
      hostCalls.push({ method: 'openSession', storedId, opts })
    }
  }

  const handoff1 = createHandoff({
    host: hostWithoutGetGateway,
    setTimeout: timers1.setTimeout,
    clearTimeout: timers1.clearTimeout,
    requestTimeoutMs: 5000
  })

  const p1 = handoff1.run({
    operationId: 'op-hr',
    cwd: '/work/fallback',
    profile: 'default',
    title: 'Fallback test',
    prompt: 'Fix issues',
    onSuccess: () => {
      onSuccessCalls += 1
    }
  })
  await timers1.flushAll()
  const res1 = await p1

  assert.equal(res1.status, 'completed')
  assert.equal(res1.outcome, 'completed')
  assert.equal(res1.opened, true)
  assert.deepEqual(res1.result, { via: 'host.request' })
  assert.equal(onSuccessCalls, 1)
  assert.equal(hostCalls[0].timeoutMs, 5000)

  // Connection switch mid-operation when using host.request fallback fails closed as 'lost'
  let currentConnId = 'conn-A'
  const swGw = createFakeGateway([
    {
      expectMethod: 'session.create',
      handler: async () => {
        currentConnId = 'conn-B'
        return { session_id: 'sess-hr-sw', stored_session_id: 'stored-hr-sw', pending: [] }
      }
    }
  ])

  const timers2 = createFakeTimers()
  const hostWithSwitchingConn = {
    activeConnectionId: () => currentConnId,
    state: { connectionId: { get: () => currentConnId } },
    async request(method, params, timeoutMs) {
      return swGw.request(method, params, timeoutMs)
    },
    openSession: async () => {}
  }

  const handoff2 = createHandoff({
    host: hostWithSwitchingConn,
    setTimeout: timers2.setTimeout,
    clearTimeout: timers2.clearTimeout
  })

  const res2 = await handoff2.run({
    operationId: 'op-hr-sw',
    cwd: '/work/fallback',
    profile: 'default',
    title: 'Fallback switch test',
    prompt: 'Fix issues'
  })

  assert.equal(res2.status, 'lost')
  assert.match(res2.error, /connection|gateway/i)
  assert.equal(swGw.requests.length, 1)
})

test('w. host.request fallback guard fails closed when connection identity is null at start or becomes null/different later before further side effects', async () => {
  // 1. Connection identity unavailable (null) at start -> fails closed before first RPC
  let startNullRpcCalls = 0
  let startNullOpenCalls = 0
  const handoffStartNull = createHandoff({
    host: {
      activeConnectionId: () => null,
      state: { connectionId: { get: () => null } },
      async request() {
        startNullRpcCalls += 1
        return { session_id: 'sess-never', stored_session_id: 'stored-never', pending: [] }
      },
      async openSession() {
        startNullOpenCalls += 1
      }
    }
  })

  const resStartNull = await handoffStartNull.run({
    operationId: 'op-fb-start-null',
    cwd: '/work/fallback',
    profile: 'default',
    title: 'Fallback null at start',
    prompt: 'Fix issues'
  })

  assert.equal(resStartNull.status, 'lost')
  assert.equal(resStartNull.session_id, null)
  assert.equal(resStartNull.admission_id, null)
  assert.equal(resStartNull.opened, false)
  assert.match(resStartNull.error, /connection|gateway/i)
  assert.equal(startNullRpcCalls, 0)
  assert.equal(startNullOpenCalls, 0)

  // 2. Connection identity becomes null during deferred session.create -> rejects before session.resume/submit/openSession
  let connDropMid = 'conn-A'
  let dropOpenCalls = 0
  const dropGw = createFakeGateway([
    {
      expectMethod: 'session.create',
      handler: async () => {
        await new Promise(resolve => setTimeout(resolve, 5))
        connDropMid = null
        return { session_id: 'sess-fb-drop', stored_session_id: 'stored-fb-drop', pending: [] }
      }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-fb-drop', stored_session_id: 'stored-fb-drop', pending: [] }
    }
  ])

  const handoffDropMid = createHandoff({
    host: {
      activeConnectionId: () => connDropMid,
      state: { connectionId: { get: () => connDropMid } },
      async request(method, params, timeoutMs) {
        return dropGw.request(method, params, timeoutMs)
      },
      async openSession() {
        dropOpenCalls += 1
      }
    },
    pollIntervalMs: 5,
    maxWaitMs: 500
  })

  const resDropMid = await handoffDropMid.run({
    operationId: 'op-fb-drop-mid',
    cwd: '/work/fallback',
    profile: 'default',
    title: 'Fallback becomes null mid-op',
    prompt: 'Fix issues'
  })

  assert.equal(resDropMid.status, 'lost')
  assert.equal(resDropMid.opened, false)
  assert.equal(dropGw.requests.length, 1)
  assert.equal(dropOpenCalls, 0)

  // 3. Connection identity becomes null during deferred session.resume (before prompt.submit) -> rejects before prompt.submit and does not issue recovery resume or openSession
  let connDropBeforeSubmit = 'conn-A'
  let dropSubmitOpenCalls = 0
  const dropSubmitGw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-fb-sub', stored_session_id: 'stored-fb-sub', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      handler: async () => {
        await new Promise(resolve => setTimeout(resolve, 5))
        connDropBeforeSubmit = null
        return { session_id: 'sess-fb-sub', stored_session_id: 'stored-fb-sub', pending: [] }
      }
    }
  ])

  const handoffDropSubmit = createHandoff({
    host: {
      activeConnectionId: () => connDropBeforeSubmit,
      async request(method, params, timeoutMs) {
        return dropSubmitGw.request(method, params, timeoutMs)
      },
      async openSession() {
        dropSubmitOpenCalls += 1
      }
    },
    pollIntervalMs: 5,
    maxWaitMs: 500
  })

  const resDropSubmit = await handoffDropSubmit.run({
    operationId: 'op-fb-drop-submit',
    cwd: '/work/fallback',
    profile: 'default',
    title: 'Fallback becomes null before submit',
    prompt: 'Fix issues'
  })

  assert.equal(resDropSubmit.status, 'lost')
  assert.equal(resDropSubmit.admission_id, null)
  assert.equal(resDropSubmit.opened, false)
  assert.equal(dropSubmitGw.requests.length, 2)
  assert.equal(dropSubmitOpenCalls, 0)
})

test('s. inspector AdoptBeforeAfterPage passes folder.id string (not folder object) to all four ctx.files.readText calls', async () => {
  const registrations = []
  const readCalls = []
  let latestState = null
  globalThis.__adoptTestStateHook = next => {
    latestState = typeof next === 'function' ? next(latestState || {
      folderLabel: '',
      report: null,
      rules: null,
      agentsMd: '',
      placeLog: [],
      error: ''
    }) : next
  }

  try {
    const fakeCtx = {
      register(entry) {
        registrations.push(entry)
      },
      files: {
        async requestFolder() {
          return {
            ok: true,
            folder: {
              id: 'grant-1234567890abcdef',
              name: 'my-adopted-copy',
              path: '/tmp/my-adopted-copy'
            }
          }
        },
        async readText(folder, relPath) {
          readCalls.push({ folder, relPath })
          if (typeof folder !== 'string') {
            return { ok: false, error: 'not-granted', message: 'This plugin has no access to that folder.' }
          }
          if (relPath === '.adopt/report.json') {
            return {
              ok: true,
              text: JSON.stringify({
                copy_root: '/tmp/my-adopted-copy',
                counts: { total_files_verified: 5, moved: 2 },
                baseline_commit_sha: 'deadbeef123456'
              })
            }
          }
          if (relPath === '.adopt/rules.json') {
            return { ok: true, text: JSON.stringify({ placement_rules: [] }) }
          }
          if (relPath === 'AGENTS.md') {
            return { ok: true, text: '# AGENTS\n' }
          }
          if (relPath === '.adopt/place-log.json') {
            return { ok: true, text: JSON.stringify([]) }
          }
          return { ok: false, error: 'not-found', message: 'Not found' }
        }
      }
    }

    plugin.register(fakeCtx)
    const pageReg = registrations.find(r => r.id === 'page')
    assert.ok(pageReg, 'page registration found')

    const { AdoptBeforeAfterPage } = await import('../plugin.js')
    const tree = AdoptBeforeAfterPage({ ctx: fakeCtx })
    // Locate the Button with onClick = loadFolder
    function findButtonOnClick(node) {
      if (!node || typeof node !== 'object') return null
      if (node.type === 'Button' && typeof node.props?.onClick === 'function') {
        return node.props.onClick
      }
      const children = node.props?.children
      if (Array.isArray(children)) {
        for (const child of children) {
          const found = findButtonOnClick(child)
          if (found) return found
        }
      } else if (children) {
        return findButtonOnClick(children)
      }
      return null
    }

    const loadFolder = findButtonOnClick(tree)
    assert.equal(typeof loadFolder, 'function')
    await loadFolder()

    assert.equal(readCalls.length, 4)
    for (const call of readCalls) {
      assert.equal(typeof call.folder, 'string')
      assert.equal(call.folder, 'grant-1234567890abcdef')
    }
    assert.deepEqual(
      readCalls.map(c => c.relPath),
      ['.adopt/report.json', '.adopt/rules.json', 'AGENTS.md', '.adopt/place-log.json']
    )
    assert.equal(latestState?.error, '')
    assert.equal(latestState?.folderLabel, '/tmp/my-adopted-copy')
  } finally {
    delete globalThis.__adoptTestStateHook
  }
})

test('x. slow uncancellable openSession (80ms) with maxWaitMs 10 settles near 10ms with navigation pending, never flips status on late navigation, and resolves via onNavigation', async () => {
  // 1. Receipt completes quickly (at ~5ms) while openSession takes 80ms with maxWaitMs 10 ->
  //    settles completed well within ~10ms with navigation: 'pending', and never reports timed_out just because navigation is slow.
  const navEventsCompleted = []
  const gwFastReceiptSlowOpen = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-nav-ok', stored_session_id: 'stored-nav-ok', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-nav-ok', stored_session_id: 'stored-nav-ok', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-nav-ok',
        session_id: 'sess-nav-ok',
        submission_id: 'op-nav-ok:submit',
        status: 'started',
        outcome: null
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: {
        admission_id: 'adm-nav-ok',
        session_id: 'sess-nav-ok',
        status: 'terminal',
        outcome: 'completed'
      }
    }
  ])

  const handoffFastReceipt = createHandoff({
    host: {
      getGateway: () => gwFastReceiptSlowOpen,
      async openSession() {
        await new Promise(resolve => setTimeout(resolve, 80))
      }
    },
    pollIntervalMs: 5,
    maxWaitMs: 10
  })

  const startOk = performance.now()
  const resOk = await handoffFastReceipt.run({
    operationId: 'op-nav-ok',
    cwd: '/work',
    profile: 'default',
    title: 'Fast receipt with 80ms openSession and maxWaitMs 10',
    prompt: 'Do work',
    onNavigation: ev => navEventsCompleted.push(ev)
  })
  const elapsedOk = performance.now() - startOk

  assert.equal(Object.isFrozen(resOk), true)
  assert.equal(resOk.status, 'completed')
  assert.equal(resOk.outcome, 'completed')
  assert.equal(resOk.navigation, 'pending')
  assert.equal(resOk.opened, false)
  assert.equal(navEventsCompleted.length, 0)
  assert.ok(elapsedOk < 55, `Expected completed settlement near 10ms despite 80ms openSession, got ${elapsedOk.toFixed(1)}ms`)

  await new Promise(resolve => setTimeout(resolve, 95))
  assert.equal(navEventsCompleted.length, 1)
  assert.deepEqual(navEventsCompleted[0], {
    operationId: 'op-nav-ok',
    navigation: 'opened',
    opened: true,
    session_id: 'sess-nav-ok',
    stored_session_id: 'stored-nav-ok',
    admission_id: 'adm-nav-ok'
  })
  // Settled snapshot is immutable and never changes after settlement
  assert.equal(resOk.status, 'completed')
  assert.equal(resOk.navigation, 'pending')
  assert.equal(resOk.opened, false)
  // Double-click caller also receives the original settled snapshot
  const resOkDbl = await handoffFastReceipt.run({
    operationId: 'op-nav-ok',
    cwd: '/work',
    profile: 'default',
    title: 'Fast receipt with 80ms openSession and maxWaitMs 10',
    prompt: 'Do work'
  })
  assert.strictEqual(resOkDbl, resOk)
  assert.equal(resOkDbl.navigation, 'pending')
  // Latest snapshot exposes updated navigation
  const latestOk = handoffFastReceipt.latest('op-nav-ok')
  assert.equal(Object.isFrozen(latestOk), true)
  assert.equal(latestOk.status, 'completed')
  assert.equal(latestOk.navigation, 'opened')
  assert.equal(latestOk.opened, true)

  // 2. Receipt polling also exceeds maxWaitMs 10 while openSession takes 80ms (and later rejects) ->
  //    settles timed_out at ~10ms with navigation: 'pending', and late navigation failure updates latest snapshot and onNavigation without mutating settled snapshot.
  const navEventsTimeout = []
  const gwSlowOpenTimeout = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-nav-to', stored_session_id: 'stored-nav-to', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-nav-to', stored_session_id: 'stored-nav-to', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-nav-to',
        session_id: 'sess-nav-to',
        submission_id: 'op-nav-to:submit',
        status: 'started',
        outcome: null
      }
    },
    ...Array.from({ length: 5 }, () => ({
      expectMethod: 'prompt.receipt',
      resolve: { admission_id: 'adm-nav-to', session_id: 'sess-nav-to', status: 'started', outcome: null }
    }))
  ])

  const handoffTimeout = createHandoff({
    host: {
      getGateway: () => gwSlowOpenTimeout,
      async openSession() {
        await new Promise(resolve => setTimeout(resolve, 80))
        throw new Error('Late dial failure')
      }
    },
    pollIntervalMs: 5,
    maxWaitMs: 10
  })

  const startTo = performance.now()
  const resTo = await handoffTimeout.run({
    operationId: 'op-nav-to',
    cwd: '/work',
    profile: 'default',
    title: 'Slow openSession with receipt timeout at maxWaitMs 10',
    prompt: 'Do work',
    onNavigation: ev => navEventsTimeout.push(ev)
  })
  const elapsedTo = performance.now() - startTo

  assert.equal(Object.isFrozen(resTo), true)
  assert.equal(resTo.status, 'timed_out')
  assert.equal(resTo.outcome, null)
  assert.equal(resTo.navigation, 'pending')
  assert.equal(resTo.opened, false)
  assert.equal(navEventsTimeout.length, 0)
  assert.ok(elapsedTo < 55, `Expected timed_out settlement near 10ms maxWaitMs, got ${elapsedTo.toFixed(1)}ms`)

  await new Promise(resolve => setTimeout(resolve, 95))

  assert.equal(navEventsTimeout.length, 1)
  assert.deepEqual(navEventsTimeout[0], {
    operationId: 'op-nav-to',
    navigation: 'failed',
    opened: false,
    session_id: 'sess-nav-to',
    stored_session_id: 'stored-nav-to',
    admission_id: 'adm-nav-to',
    open_error: 'Late dial failure'
  })
  // Settled snapshot remains unchanged
  assert.equal(resTo.status, 'timed_out')
  assert.equal(resTo.outcome, null)
  assert.equal(resTo.navigation, 'pending')
  assert.equal(resTo.opened, false)
  assert.equal('open_error' in resTo, false)
  // Latest snapshot has updated navigation failure without flipping status
  const latestTo = handoffTimeout.latest('op-nav-to')
  assert.equal(Object.isFrozen(latestTo), true)
  assert.equal(latestTo.status, 'timed_out')
  assert.equal(latestTo.outcome, null)
  assert.equal(latestTo.navigation, 'failed')
  assert.equal(latestTo.opened, false)
  assert.equal(latestTo.open_error, 'Late dial failure')

  // 3. openSession is NOT called (navigation: 'skipped') when no time remains in maxWaitMs after prompt.submit
  let skippedOpenCalled = false
  const gwNoTimeForOpen = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-nav-skip', stored_session_id: 'stored-nav-skip', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-nav-skip', stored_session_id: 'stored-nav-skip', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-nav-skip',
        session_id: 'sess-nav-skip',
        submission_id: 'op-nav-skip:submit',
        status: 'started',
        outcome: null
      }
    }
  ])

  let fakeNow = 1000
  const handoff3 = createHandoff({
    host: {
      getGateway: () => gwNoTimeForOpen,
      async openSession() {
        skippedOpenCalled = true
      }
    },
    now: () => fakeNow,
    maxWaitMs: 10
  })

  const origRequest = gwNoTimeForOpen.request.bind(gwNoTimeForOpen)
  gwNoTimeForOpen.request = async (method, params, timeoutMs) => {
    const out = await origRequest(method, params, timeoutMs)
    if (method === 'prompt.submit') {
      fakeNow += 15
    }
    return out
  }

  const res3 = await handoff3.run({
    operationId: 'op-nav-skip',
    cwd: '/work',
    profile: 'default',
    title: 'No time left for openSession',
    prompt: 'Do work'
  })

  assert.equal(skippedOpenCalled, false)
  assert.equal(res3.navigation, 'skipped')
  assert.equal(res3.opened, false)
  assert.equal(res3.status, 'timed_out')
})

test('y. completed receipt + 80ms onSuccess with maxWaitMs 10 settles status completed promptly and reports lint result separately', async () => {
  const lintEvents = []
  const gw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-lint-slow', stored_session_id: 'stored-lint-slow', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-lint-slow', stored_session_id: 'stored-lint-slow', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-lint-slow',
        session_id: 'sess-lint-slow',
        submission_id: 'op-lint-slow:submit',
        status: 'started',
        outcome: null
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: {
        admission_id: 'adm-lint-slow',
        session_id: 'sess-lint-slow',
        status: 'terminal',
        outcome: 'completed',
        result: { adapted: true }
      }
    }
  ])

  let lintFinished = false
  const handoff = createHandoff({
    host: {
      getGateway: () => gw,
      async openSession() {}
    },
    pollIntervalMs: 2,
    maxWaitMs: 10,
    lintTimeoutMs: 500
  })

  const start = performance.now()
  const res = await handoff.run({
    operationId: 'op-lint-slow',
    cwd: '/work',
    profile: 'default',
    title: 'Slow onSuccess lint',
    prompt: 'Do work',
    onSuccess: async () => {
      await new Promise(resolve => setTimeout(resolve, 80))
      lintFinished = true
      return true
    },
    onLint: ev => {
      lintEvents.push(ev)
    }
  })
  const elapsed = performance.now() - start

  // Main promise settles as soon as receipt status is known (well before 80ms onSuccess finishes)
  assert.equal(Object.isFrozen(res), true)
  assert.equal(res.status, 'completed')
  assert.equal(res.outcome, 'completed')
  assert.equal(res.navigation, 'opened')
  assert.equal(res.opened, true)
  assert.equal(res.lint, 'pending')
  assert.equal(lintFinished, false)
  assert.ok(elapsed < 50, `Expected prompt settlement before 80ms onSuccess, got ${elapsed.toFixed(1)}ms`)
  assert.ok(res.lintDone && typeof res.lintDone.then === 'function', 'Expected res.lintDone promise')

  const lintOutcome = await res.lintDone
  assert.equal(lintFinished, true)
  assert.equal(Object.isFrozen(lintOutcome), true)
  assert.notStrictEqual(lintOutcome, res)
  assert.equal(lintOutcome.status, 'completed')
  assert.equal(lintOutcome.navigation, 'opened')
  assert.equal(lintOutcome.lint, 'ok')
  // Settled snapshot returned by run() remains frozen with lint: 'pending'
  assert.equal(res.lint, 'pending')
  assert.equal(res.status, 'completed')
  // Latest snapshot matches lintDone snapshot
  assert.deepEqual(handoff.latest('op-lint-slow'), lintOutcome)
  assert.equal(lintEvents.length, 1)
  assert.equal(lintEvents[0].lint, 'ok')
})

test('z. never-resolving onSuccess settles main promise promptly and reports lint timed_out after lintTimeoutMs', async () => {
  const lintEvents = []
  const gw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-lint-hung', stored_session_id: 'stored-lint-hung', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-lint-hung', stored_session_id: 'stored-lint-hung', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-lint-hung',
        session_id: 'sess-lint-hung',
        submission_id: 'op-lint-hung:submit',
        status: 'started',
        outcome: null
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: {
        admission_id: 'adm-lint-hung',
        session_id: 'sess-lint-hung',
        status: 'terminal',
        outcome: 'completed'
      }
    }
  ])

  const handoff = createHandoff({
    host: {
      getGateway: () => gw,
      async openSession() {}
    },
    pollIntervalMs: 2,
    maxWaitMs: 50,
    lintTimeoutMs: 25
  })

  const start = performance.now()
  const res = await handoff.run({
    operationId: 'op-lint-hung',
    cwd: '/work',
    profile: 'default',
    title: 'Never-resolving onSuccess',
    prompt: 'Do work',
    onSuccess: () => new Promise(() => {}),
    onLint: ev => {
      lintEvents.push(ev)
    }
  })
  const settleElapsed = performance.now() - start

  assert.equal(Object.isFrozen(res), true)
  assert.equal(res.status, 'completed')
  assert.equal(res.outcome, 'completed')
  assert.equal(res.lint, 'pending')
  assert.ok(settleElapsed < 25, `Expected main settlement before lintTimeoutMs, got ${settleElapsed.toFixed(1)}ms`)

  const lintOutcome = await res.lintDone
  const totalElapsed = performance.now() - start

  assert.equal(Object.isFrozen(lintOutcome), true)
  assert.notStrictEqual(lintOutcome, res)
  assert.equal(lintOutcome.status, 'completed')
  assert.equal(lintOutcome.lint, 'timed_out')
  assert.match(lintOutcome.lint_error, /timed out/i)
  // Settled snapshot remains frozen with lint: 'pending'
  assert.equal(res.lint, 'pending')
  assert.equal('lint_error' in res, false)
  assert.equal(res.status, 'completed')
  assert.deepEqual(handoff.latest('op-lint-hung'), lintOutcome)
  assert.ok(totalElapsed >= 15 && totalElapsed < 100, `Expected lint timeout near 25ms, got ${totalElapsed.toFixed(1)}ms`)
  assert.equal(lintEvents.length, 1)
  assert.equal(lintEvents[0].lint, 'timed_out')
})

test('aa. async throwing onNavigation and onLint observers are caught without unhandledRejection and lint timeout timer calls unref?.()', async () => {
  const unhandled = []
  const onUnhandled = reason => {
    unhandled.push(reason)
  }
  process.on('unhandledRejection', onUnhandled)

  try {
    let unrefCalled = 0
    const realSetTimeout = globalThis.setTimeout
    const realClearTimeout = globalThis.clearTimeout
    const wrappedSetTimeout = (cb, ms) => {
      const handle = realSetTimeout(cb, ms)
      const origUnref = typeof handle?.unref === 'function' ? handle.unref.bind(handle) : null
      if (handle && typeof handle === 'object') {
        handle.unref = () => {
          unrefCalled += 1
          return origUnref ? origUnref() : handle
        }
      }
      return handle
    }

    const gw = createFakeGateway([
      {
        expectMethod: 'session.create',
        resolve: { session_id: 'sess-obs', stored_session_id: 'stored-obs', pending: [] }
      },
      {
        expectMethod: 'session.resume',
        resolve: { session_id: 'sess-obs', stored_session_id: 'stored-obs', pending: [] }
      },
      {
        expectMethod: 'prompt.submit',
        resolve: {
          admission_id: 'adm-obs',
          session_id: 'sess-obs',
          submission_id: 'op-obs:submit',
          status: 'started',
          outcome: null
        }
      },
      {
        expectMethod: 'prompt.receipt',
        resolve: {
          admission_id: 'adm-obs',
          session_id: 'sess-obs',
          status: 'terminal',
          outcome: 'completed',
          result: { ok: true }
        }
      }
    ])

    let navObserverCalled = 0
    let lintObserverCalled = 0

    const handoff = createHandoff({
      host: {
        getGateway: () => gw,
        async openSession() {
          await new Promise(resolve => realSetTimeout(resolve, 30))
        }
      },
      setTimeout: wrappedSetTimeout,
      clearTimeout: realClearTimeout,
      pollIntervalMs: 2,
      maxWaitMs: 20,
      lintTimeoutMs: 500
    })

    const res = await handoff.run({
      operationId: 'op-obs',
      cwd: '/work',
      profile: 'default',
      title: 'Async observer rejection test',
      prompt: 'Do work',
      onSuccess: async () => {
        await new Promise(resolve => realSetTimeout(resolve, 45))
        throw new Error('async lint failed')
      },
      onNavigation: async () => {
        navObserverCalled += 1
        await new Promise(resolve => realSetTimeout(resolve, 5))
        throw new Error('async onNavigation boom')
      },
      onLint: async () => {
        lintObserverCalled += 1
        await new Promise(resolve => realSetTimeout(resolve, 5))
        throw new Error('async onLint boom')
      }
    })

    assert.equal(Object.isFrozen(res), true)
    assert.equal(res.status, 'completed')
    assert.equal(res.navigation, 'pending')
    assert.equal(res.lint, 'pending')
    assert.ok(unrefCalled >= 1, `Expected lint timeout timer .unref() to be called, got ${unrefCalled}`)

    const finalSnap = await res.lintDone
    await new Promise(resolve => realSetTimeout(resolve, 30))

    assert.equal(navObserverCalled, 1)
    assert.equal(lintObserverCalled, 1)
    assert.equal(unhandled.length, 0, `Expected 0 unhandled rejections, got ${unhandled.length}`)

    // Initial settled snapshot never mutated
    assert.equal(res.navigation, 'pending')
    assert.equal(res.opened, false)
    assert.equal(res.lint, 'pending')
    assert.equal('error' in res, false)
    assert.equal('lint_error' in res, false)

    // Final snapshot from lintDone and handoff.latest() has both late navigation and late lint updates, frozen
    assert.equal(Object.isFrozen(finalSnap), true)
    assert.equal(finalSnap.status, 'completed')
    assert.equal(finalSnap.navigation, 'opened')
    assert.equal(finalSnap.opened, true)
    assert.equal(finalSnap.lint, 'failed')
    assert.match(finalSnap.lint_error, /async lint failed/)
    assert.match(finalSnap.error, /async lint failed/)
    assert.deepEqual(handoff.latest('op-obs'), finalSnap)

    // Double-click run() still returns the original settled snapshot, while release() clears both settled and latest
    const dbl = await handoff.run({
      operationId: 'op-obs',
      cwd: '/work',
      profile: 'default',
      title: 'Async observer rejection test',
      prompt: 'Do work'
    })
    assert.strictEqual(dbl, res)
    assert.equal(handoff.release('op-obs'), true)
    assert.equal(handoff.latest('op-obs'), null)
  } finally {
    process.off('unhandledRejection', onUnhandled)
  }
})

test('ab. onSuccess lint report mapping: report.ok===true & complete => ok, status incomplete or ok===false => incomplete with lintReport, non-object => ok only if true else unknown', async () => {
  function makeGatewayFor(id) {
    return createFakeGateway([
      {
        expectMethod: 'session.create',
        resolve: { session_id: `sess-${id}`, stored_session_id: `stored-${id}`, pending: [] }
      },
      {
        expectMethod: 'session.resume',
        resolve: { session_id: `sess-${id}`, stored_session_id: `stored-${id}`, pending: [] }
      },
      {
        expectMethod: 'prompt.submit',
        resolve: {
          admission_id: `adm-${id}`,
          session_id: `sess-${id}`,
          submission_id: `${id}:submit`,
          status: 'started',
          outcome: null
        }
      },
      {
        expectMethod: 'prompt.receipt',
        resolve: {
          admission_id: `adm-${id}`,
          session_id: `sess-${id}`,
          status: 'terminal',
          outcome: 'completed'
        }
      }
    ])
  }

  // 1. Report object with ok: true and status: 'complete' / 'clean' / 'findings' => lint: 'ok' + frozen lintReport
  for (const status of ['complete', 'clean', 'findings']) {
    const gw = makeGatewayFor(`rep-ok-${status}`)
    const timers = createFakeTimers()
    const lintEvents = []
    const handoff = createHandoff({
      host: { getGateway: () => gw, openSession: async () => {} },
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout
    })
    const reportObj = { ok: true, status, findings: status === 'findings' ? [{ rule: 'x' }] : [] }
    const p = handoff.run({
      operationId: `rep-ok-${status}`,
      cwd: '/work',
      profile: 'default',
      title: 'Lint report ok',
      prompt: 'Do work',
      onSuccess: async () => reportObj,
      onLint: ev => lintEvents.push(ev)
    })
    await timers.flushAll()
    const res = await p
    assert.equal(Object.isFrozen(res), true)
    assert.equal(res.status, 'completed')
    assert.equal(res.lint, 'ok')
    assert.deepEqual(res.lintReport, reportObj)
    assert.equal(Object.isFrozen(res.lintReport), true)
    assert.equal(lintEvents.length, 1)
    assert.equal(lintEvents[0].lint, 'ok')
    assert.deepEqual(lintEvents[0].lintReport, reportObj)
  }

  // 2. Report object with status: 'incomplete' or ok: false (both fast and delayed) => lint: 'incomplete' with lintReport attached
  const incompleteCases = [
    { id: 'inc-status', report: { ok: false, status: 'incomplete', tool_errors: [{ tool: 'clippy', status: 'not_installed' }] }, delayed: false },
    { id: 'inc-ok-false', report: { ok: false, status: 'error', error: 'bad env' }, delayed: false },
    { id: 'inc-status-only', report: { ok: true, status: 'incomplete', warnings: ['missing binary'] }, delayed: true }
  ]

  for (const { id, report, delayed } of incompleteCases) {
    const gw = makeGatewayFor(id)
    const lintEvents = []
    const handoff = createHandoff({
      host: { getGateway: () => gw, openSession: async () => {} },
      pollIntervalMs: 2,
      maxWaitMs: 50,
      lintTimeoutMs: 500
    })
    const res = await handoff.run({
      operationId: id,
      cwd: '/work',
      profile: 'default',
      title: 'Lint report incomplete',
      prompt: 'Do work',
      onSuccess: async () => {
        if (delayed) {
          await new Promise(resolve => setTimeout(resolve, 25))
        }
        return report
      },
      onLint: ev => lintEvents.push(ev)
    })

    if (delayed) {
      assert.equal(res.lint, 'pending')
      assert.equal('lintReport' in res, false)
      const finalSnap = await res.lintDone
      assert.equal(res.lint, 'pending')
      assert.equal(finalSnap.status, 'completed')
      assert.equal(finalSnap.lint, 'incomplete')
      assert.deepEqual(finalSnap.lintReport, report)
      assert.equal(Object.isFrozen(finalSnap.lintReport), true)
      assert.deepEqual(handoff.latest(id), finalSnap)
    } else {
      assert.equal(res.status, 'completed')
      assert.equal(res.lint, 'incomplete')
      assert.deepEqual(res.lintReport, report)
      assert.equal(Object.isFrozen(res.lintReport), true)
      const finalSnap = await res.lintDone
      assert.strictEqual(finalSnap, res)
    }
    assert.equal(lintEvents.length, 1)
    assert.equal(lintEvents[0].lint, 'incomplete')
    assert.deepEqual(lintEvents[0].lintReport, report)
  }

  // 3. Non-object resolution => 'ok' ONLY if explicitly true, else 'unknown'
  const nonObjectCases = [
    { id: 'prim-true', val: true, expected: 'ok' },
    { id: 'prim-undef', val: undefined, expected: 'unknown' },
    { id: 'prim-null', val: null, expected: 'unknown' },
    { id: 'prim-false', val: false, expected: 'unknown' },
    { id: 'prim-str', val: 'ok', expected: 'unknown' },
    { id: 'prim-num', val: 1, expected: 'unknown' },
    { id: 'prim-empty-obj', val: {}, expected: 'unknown' }
  ]

  for (const { id, val, expected } of nonObjectCases) {
    const gw = makeGatewayFor(id)
    const timers = createFakeTimers()
    const handoff = createHandoff({
      host: { getGateway: () => gw, openSession: async () => {} },
      setTimeout: timers.setTimeout,
      clearTimeout: timers.clearTimeout
    })
    const p = handoff.run({
      operationId: id,
      cwd: '/work',
      profile: 'default',
      title: `Non-object ${id}`,
      prompt: 'Do work',
      onSuccess: async () => val
    })
    await timers.flushAll()
    const res = await p
    assert.equal(res.status, 'completed')
    assert.equal(res.lint, expected, `Expected lint=${expected} for ${id}`)
    if (val && typeof val === 'object') {
      assert.deepEqual(res.lintReport, val)
    } else {
      assert.equal('lintReport' in res, false)
    }
  }
})

test('ac. generation-safe release and latest(): release while lint pending keeps latest() null; release + rerun same id (session s2) + old lint/navigation completes keeps latest() at s2', async () => {
  // 1. release while lint (and navigation) pending => latest() stays null after lint and navigation complete
  const gw1 = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 's1', stored_session_id: 'stored-s1', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 's1', stored_session_id: 'stored-s1', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-s1',
        session_id: 's1',
        submission_id: 'op-gen-1:submit',
        status: 'started',
        outcome: null
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: {
        admission_id: 'adm-s1',
        session_id: 's1',
        status: 'terminal',
        outcome: 'completed',
        result: { run: 1 }
      }
    }
  ])

  const handoff1 = createHandoff({
    host: {
      getGateway: () => gw1,
      async openSession() {
        await new Promise(resolve => setTimeout(resolve, 40))
      }
    },
    pollIntervalMs: 2,
    maxWaitMs: 30,
    lintTimeoutMs: 500
  })

  const res1 = await handoff1.run({
    operationId: 'op-gen-1',
    cwd: '/work',
    profile: 'default',
    title: 'Release while lint pending',
    prompt: 'Do work',
    onSuccess: async () => {
      await new Promise(resolve => setTimeout(resolve, 50))
      return { ok: true, status: 'clean' }
    }
  })

  assert.equal(res1.session_id, 's1')
  assert.equal(res1.lint, 'pending')
  assert.equal(res1.navigation, 'pending')
  assert.equal(handoff1.latest('op-gen-1')?.session_id, 's1')

  // Release while lint and navigation are still pending
  assert.equal(handoff1.release('op-gen-1'), true)
  assert.equal(handoff1.release('op-gen-1'), false)
  assert.equal(handoff1.latest('op-gen-1'), null)

  // Old lintDone and navigationDone promises still resolve with their own frozen snapshot,
  // but never repopulate latestOps/settledOps caches.
  const [oldLintSnap, oldNavSnap] = await Promise.all([res1.lintDone, res1.navigationDone])
  assert.equal(Object.isFrozen(oldLintSnap), true)
  assert.equal(oldLintSnap.session_id, 's1')
  assert.equal(oldLintSnap.lint, 'ok')
  assert.equal(Object.isFrozen(oldNavSnap), true)
  assert.equal(oldNavSnap.session_id, 's1')
  assert.equal(oldNavSnap.navigation, 'opened')
  assert.equal(handoff1.latest('op-gen-1'), null)

  // 2. release + rerun same id (session s2) + old lint/navigation completes => latest() is s2
  const gw2 = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 's1', stored_session_id: 'stored-s1', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 's1', stored_session_id: 'stored-s1', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-s1',
        session_id: 's1',
        submission_id: 'op-gen-rerun:submit',
        status: 'started',
        outcome: null
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: {
        admission_id: 'adm-s1',
        session_id: 's1',
        status: 'terminal',
        outcome: 'completed',
        result: { session: 's1' }
      }
    },
    {
      expectMethod: 'session.create',
      resolve: { session_id: 's2', stored_session_id: 'stored-s2', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 's2', stored_session_id: 'stored-s2', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-s2',
        session_id: 's2',
        submission_id: 'op-gen-rerun:submit',
        status: 'started',
        outcome: null
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: {
        admission_id: 'adm-s2',
        session_id: 's2',
        status: 'terminal',
        outcome: 'completed',
        result: { session: 's2' }
      }
    }
  ])

  let openCallCount = 0
  const handoff2 = createHandoff({
    host: {
      getGateway: () => gw2,
      async openSession() {
        openCallCount += 1
        if (openCallCount === 1) {
          await new Promise(resolve => setTimeout(resolve, 60))
        }
      }
    },
    pollIntervalMs: 2,
    maxWaitMs: 30,
    lintTimeoutMs: 500
  })

  const run1 = await handoff2.run({
    operationId: 'op-gen-rerun',
    cwd: '/work',
    profile: 'default',
    title: 'Run 1 (s1)',
    prompt: 'Do work 1',
    onSuccess: async () => {
      await new Promise(resolve => setTimeout(resolve, 75))
      return { ok: false, status: 'incomplete', from: 's1' }
    }
  })

  assert.equal(run1.session_id, 's1')
  assert.equal(run1.lint, 'pending')
  assert.equal(run1.navigation, 'pending')

  // Release op-gen-rerun and immediately start run 2 (session s2) before run 1's lint or navigation completes
  assert.equal(handoff2.release('op-gen-rerun'), true)
  assert.equal(handoff2.latest('op-gen-rerun'), null)

  const run2 = await handoff2.run({
    operationId: 'op-gen-rerun',
    cwd: '/work',
    profile: 'default',
    title: 'Run 2 (s2)',
    prompt: 'Do work 2',
    onSuccess: async () => ({ ok: true, status: 'clean', from: 's2' })
  })

  assert.equal(run2.session_id, 's2')
  assert.equal(run2.lint, 'ok')
  assert.equal(run2.navigation, 'opened')
  assert.equal(handoff2.latest('op-gen-rerun')?.session_id, 's2')

  // Wait for run 1's slow lint and navigation to finish
  const [run1LintDone, run1NavDone] = await Promise.all([run1.lintDone, run1.navigationDone])
  assert.equal(run1LintDone.session_id, 's1')
  assert.equal(run1LintDone.lint, 'incomplete')
  assert.equal(run1NavDone.session_id, 's1')
  assert.equal(run1NavDone.navigation, 'opened')

  // latest() and cached run() MUST still be s2, never overwritten by run 1's late callbacks
  const latestAfterOldLint = handoff2.latest('op-gen-rerun')
  assert.equal(latestAfterOldLint?.session_id, 's2')
  assert.equal(latestAfterOldLint?.lint, 'ok')
  assert.deepEqual(latestAfterOldLint?.lintReport, { ok: true, status: 'clean', from: 's2' })
  const cachedRun2 = await handoff2.run({
    operationId: 'op-gen-rerun',
    cwd: '/work',
    profile: 'default',
    title: 'Run 2 cached',
    prompt: 'Do work 2'
  })
  assert.strictEqual(cachedRun2, run2)
  assert.equal(cachedRun2.session_id, 's2')
})

test('ad. snapshots freeze detached clones without freezing caller objects: async onSuccess mutating receipt.result.nested.n after a delay succeeds and lint is ok', async () => {
  const callerReceipt = {
    admission_id: 'adm-mut',
    session_id: 'sess-mut',
    status: 'terminal',
    outcome: 'completed',
    result: {
      nested: { n: 1 },
      fn: () => 'non-cloneable-fn'
    }
  }
  const callerLintReport = {
    ok: true,
    status: 'clean',
    details: { count: 0 },
    helper: () => 'drop-me'
  }

  const gw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-mut', stored_session_id: 'stored-mut', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-mut', stored_session_id: 'stored-mut', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-mut',
        session_id: 'sess-mut',
        submission_id: 'op-mut:submit',
        status: 'started',
        outcome: null
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: callerReceipt
    }
  ])

  const handoff = createHandoff({
    host: { getGateway: () => gw, openSession: async () => {} },
    pollIntervalMs: 2,
    maxWaitMs: 50,
    lintTimeoutMs: 500
  })

  const settledSnap = await handoff.run({
    operationId: 'op-mut',
    cwd: '/work',
    profile: 'default',
    title: 'Caller mutation test',
    prompt: 'Do work',
    onSuccess: async receiptArg => {
      // Wait so that run() has already built and frozen its initial settled snapshot
      await new Promise(resolve => setTimeout(resolve, 25))
      // Mutating receipt.result.nested.n in place after a delay must NOT throw TypeError
      receiptArg.result.nested.n += 41
      callerLintReport.details.count = receiptArg.result.nested.n
      return callerLintReport
    }
  })

  // Settled snapshot is deeply frozen on its own detached clone
  assert.equal(Object.isFrozen(settledSnap), true)
  assert.equal(Object.isFrozen(settledSnap.result), true)
  assert.equal(Object.isFrozen(settledSnap.result.nested), true)
  assert.equal(settledSnap.result.nested.n, 1)
  assert.equal('_droppedNonCloneableNote' in settledSnap.result, false)

  // Caller receipt object was never frozen
  assert.equal(Object.isFrozen(callerReceipt), false)
  assert.equal(Object.isFrozen(callerReceipt.result), false)
  assert.equal(Object.isFrozen(callerReceipt.result.nested), false)

  const lintSnap = await settledSnap.lintDone
  assert.equal(lintSnap.lint, 'ok')
  assert.equal(callerReceipt.result.nested.n, 42)
  // Settled snapshot's cloned result.nested.n remains 1 even after caller mutated receiptArg
  assert.equal(settledSnap.result.nested.n, 1)
  assert.equal(lintSnap.result.nested.n, 1)

  // Caller lintReport object returned by onSuccess is also not frozen in place, while snapshot's lintReport clone IS frozen
  assert.equal(Object.isFrozen(callerLintReport), false)
  assert.equal(Object.isFrozen(callerLintReport.details), false)
  callerLintReport.details.count = 99
  assert.equal(callerLintReport.details.count, 99)
  assert.equal(Object.isFrozen(lintSnap.lintReport), true)
  assert.equal(Object.isFrozen(lintSnap.lintReport.details), true)
  assert.equal(lintSnap.lintReport.details.count, 42)
  assert.equal('_droppedNonCloneableNote' in lintSnap.lintReport, false)
})

test('ae. lintDone vs navigationDone: lintDone resolves at lint completion while navigation is still pending, and navigationDone resolves when navigation settles', async () => {
  const gw = createFakeGateway([
    {
      expectMethod: 'session.create',
      resolve: { session_id: 'sess-navdone', stored_session_id: 'stored-navdone', pending: [] }
    },
    {
      expectMethod: 'session.resume',
      resolve: { session_id: 'sess-navdone', stored_session_id: 'stored-navdone', pending: [] }
    },
    {
      expectMethod: 'prompt.submit',
      resolve: {
        admission_id: 'adm-navdone',
        session_id: 'sess-navdone',
        submission_id: 'op-navdone:submit',
        status: 'started',
        outcome: null
      }
    },
    {
      expectMethod: 'prompt.receipt',
      resolve: {
        admission_id: 'adm-navdone',
        session_id: 'sess-navdone',
        status: 'terminal',
        outcome: 'completed'
      }
    }
  ])

  const handoff = createHandoff({
    host: {
      getGateway: () => gw,
      async openSession() {
        await new Promise(resolve => setTimeout(resolve, 75))
      }
    },
    pollIntervalMs: 2,
    maxWaitMs: 30,
    lintTimeoutMs: 500
  })

  const res = await handoff.run({
    operationId: 'op-navdone',
    cwd: '/work',
    profile: 'default',
    title: 'lintDone vs navigationDone',
    prompt: 'Do work',
    onSuccess: async () => {
      await new Promise(resolve => setTimeout(resolve, 20))
      return { ok: true, status: 'clean' }
    }
  })

  assert.equal(res.status, 'completed')
  assert.equal(res.lint, 'pending')
  assert.equal(res.navigation, 'pending')
  assert.ok(res.lintDone && typeof res.lintDone.then === 'function')
  assert.ok(res.navigationDone && typeof res.navigationDone.then === 'function')
  assert.equal(Object.prototype.propertyIsEnumerable.call(res, 'lintDone'), false)
  assert.equal(Object.prototype.propertyIsEnumerable.call(res, 'navigationDone'), false)

  // lintDone resolves at ~20ms while navigation (75ms) is still pending
  const atLintDone = await res.lintDone
  assert.equal(Object.isFrozen(atLintDone), true)
  assert.equal(atLintDone.lint, 'ok')
  assert.equal(atLintDone.navigation, 'pending')
  assert.equal(atLintDone.opened, false)

  // navigationDone resolves at ~75ms when openSession settles
  const atNavDone = await res.navigationDone
  assert.equal(Object.isFrozen(atNavDone), true)
  assert.equal(atNavDone.lint, 'ok')
  assert.equal(atNavDone.navigation, 'opened')
  assert.equal(atNavDone.opened, true)
  assert.deepEqual(handoff.latest('op-navdone'), atNavDone)
})

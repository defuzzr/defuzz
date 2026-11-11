import test from 'node:test'
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import { createToolsLockClient, createWorkspaceModel, createHandoff, ManualLintSection } from '../plugin.js'

test('D2 disposal cancels receipt polling waits without another RPC', async t => {
  scope(t)
  const calls = [], timers = new Set()
  host.getGateway = () => ({ request: async method => {
    calls.push(method)
    return method === 'session.create' ? { session_id: 's', stored_session_id: 'stored' } : method === 'prompt.submit' ? { admission_id: 'a' } : {}
  } })
  const handoff = createHandoff({ setTimeout(fn, ms) { const id = setTimeout(fn, ms); timers.add(id); return id }, clearTimeout(id) { clearTimeout(id); timers.delete(id) } })
  const pending = handoff.run(op)
  await tick(); handoff.dispose()
  const result = await pending
  assert.equal(result.status, 'lost')
  assert.deepEqual(calls, ['session.create', 'session.resume', 'prompt.submit'])
  assert.equal(timers.size, 0)
})

function mount(t, Component, props) {
  const slots = [], effects = []
  let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  globalThis.__adoptTestUseEffect = fn => { const i = cursor++; if (!(i in slots)) { slots[i] = true; effects.push(fn()) } }
  t.after(() => { delete globalThis.__adoptTestUseState; delete globalThis.__adoptTestUseEffect })
  return { render() { cursor = 0; return Component(props) }, unmount() { effects.forEach(fn => fn?.()) } }
}
const nodes = n => !n || typeof n !== 'object' ? [] : [n, ...[n.props?.children].flat().flatMap(nodes)]
const button = (tree, label) => nodes(tree).find(n => n.type === 'Button' && n.props.children === label)

for (const surface of ['lint']) for (const cleanup of ['unmount', 'unload']) test(`D2 ${surface} ${cleanup} cancels held handoff`, async t => {
  scope(t)
  const calls = [], timers = new Set(), disposers = []
  let resolveCreate
  host.getGateway = () => ({ request: async method => {
    calls.push(method)
    if (method === 'session.create') return new Promise(resolve => { resolveCreate = resolve })
    return {}
  } })
  const ctx = {
    onDispose(fn) { disposers.push(fn) },
    setTimeout(fn, ms) { const id = setTimeout(fn, ms); timers.add(id); return () => { clearTimeout(id); timers.delete(id) } },
    rest: async () => ({ findings: [] })
  }
  t.after(() => { for (const id of timers) clearTimeout(id) })
  const ui = mount(t, ManualLintSection, { ctx, project: '/A' })
  await button(ui.render(), 'Run lint').props.onClick()
  const pending = button(ui.render(), 'Fix with Hermes').props.onClick()
  await tick(); if (cleanup === 'unmount') ui.unmount(); else disposers.forEach(fn => fn())
  resolveCreate({ session_id: 's', stored_session_id: 'stored' })
  await pending
  assert.deepEqual(calls, ['session.create'])
  assert.equal(timers.size, 0)
})

for (const heldMethod of ['session.create', 'session.resume', 'prompt.submit']) test(`D3 profile switch during ${heldMethod} prevents later RPC/navigation`, async t => {
  const owner = scope(t)
  const calls = []
  let finish
  host.openSession = async () => { calls.push('openSession') }
  host.getGateway = () => ({ request: async method => {
    calls.push(method)
    const response = method === 'session.create' ? { session_id: 's', stored_session_id: 'stored' } : method === 'prompt.submit' ? { admission_id: 'a' } : {}
    if (method === heldMethod) return new Promise(resolve => { finish = () => resolve(response) })
    return response
  } })
  const handoff = createHandoff({ pollIntervalMs: 0, maxWaitMs: 30 })
  const pending = handoff.run(op)
  await tick(); owner.profile('B'); finish()
  const result = await pending
  assert.equal(result.status, 'lost')
  assert.deepEqual(calls, ['session.create', 'session.resume', 'prompt.submit'].slice(0, ['session.create', 'session.resume', 'prompt.submit'].indexOf(heldMethod) + 1))
})

test('D4 resolved partial creation preserves paths and blocks retry/discard', async () => {
  const calls = []
  const replies = [{ proposal_id: 'p' }, { ok: false, created_dirs: ['/partial'], accepted_repos: [] }]
  const model = createWorkspaceModel({ rest: async path => { calls.push(path); return replies.shift() } })
  model.edit({ name: 'Example' }); model.choose({ template_id: 'ts-node-golden' })
  await model.propose(); await model.accept()
  assert.equal(model.get().partial, true)
  await model.accept(); await model.discard()
  assert.deepEqual(calls, ['/scaffold/propose', '/scaffold/accept'])
  assert.deepEqual(model.get().output.created_dirs, ['/partial'])
  assert.equal(model.get().proposal.proposal_id, 'p')
})

test('D2 disposal settles a pending navigation observer', async t => {
  scope(t)
  host.openSession = () => new Promise(() => {})
  host.getGateway = () => ({ request: async method => method === 'session.create' ? { session_id: 's', stored_session_id: 'stored' } : method === 'prompt.submit' ? { admission_id: 'a' } : method === 'prompt.receipt' ? { status: 'terminal', outcome: 'completed' } : {} })
  const handoff = createHandoff({ pollIntervalMs: 0 })
  const result = await handoff.run(op)
  let settled = false
  result.navigationDone.then(() => { settled = true })
  handoff.dispose(); await tick()
  assert.equal(settled, true)
})

test('D2 remount rejects responses from the disposed workspace lifetime', async () => {
  let finish
  const model = createWorkspaceModel({ rest: () => new Promise(resolve => { finish = resolve }) })
  const pending = model.load()
  model.dispose(); model.mount()
  finish({ projects: [{ name: 'stale', path: '/stale', registered: true }], coverage: 'verified' }); await pending
  assert.deepEqual(model.get().projects, [])
  assert.equal(model.get().busy, false)
})

const tick = () => new Promise(resolve => setImmediate(resolve))
const op = { operationId: 'review', cwd: '/A', profile: 'A', prompt: 'Review' }

function scope(t) {
  const original = { ...host }
  let profile = 'A', connection = 'local'
  host.state = { profile: { get: () => profile } }
  host.activeConnectionId = () => connection
  t.after(() => { for (const key of Object.keys(host)) delete host[key]; Object.assign(host, original) })
  return { profile: value => { profile = value }, connection: value => { connection = value } }
}

test('D1 retained Tools Lock client refuses every mutation after owner changes', async t => {
  const owner = scope(t)
  const calls = []
  const client = createToolsLockClient({ rest: async (...args) => { calls.push(args); return {} } })
  owner.profile('B')
  for (const invoke of [() => client.initLock('/A'), () => client.acceptInstalled('/A', 'node', 'reviewed'), () => client.setReason('/A', 'node', 'reviewed'), () => client.snooze('/A', 'node')]) {
    await assert.rejects(async () => invoke(), /Connection or profile changed/)
  }
  owner.profile('A'); owner.connection('remote')
  await assert.rejects(async () => client.initLock('/A'), /Connection or profile changed/)
  assert.equal(calls.length, 0)
})

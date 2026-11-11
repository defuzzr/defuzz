import test from 'node:test'
import assert from 'node:assert/strict'
import * as plugin from '../plugin.js'

test('the single-file plugin exports reachable autosave controllers', () => {
  assert.equal(typeof plugin.createSafeAutoSave, 'function')
  assert.equal(typeof plugin.useSafeAutoSave, 'function')
})

test('autosave uses scoped timer disposers and stops on plugin unload', async () => {
  const pending = new Set()
  const cleanups = []
  let saved = 0
  const ctx = {
    setTimeout(fn, ms) {
      assert.equal(ms, 150)
      pending.add(fn)
      return () => pending.delete(fn)
    },
    onDispose(fn) { cleanups.push(fn) }
  }
  const controller = plugin.createSafeAutoSave({ ctx, onSave: () => { saved++ } })
  controller.schedule('key', 1)
  controller.schedule('key', 2)
  assert.equal(pending.size, 1)
  assert.equal(cleanups.length, 1)
  cleanups[0]()
  assert.equal(pending.size, 0)
  await controller.flush()
  assert.equal(saved, 0)
  assert.throws(() => controller.schedule('key', 3), /disposed/)
})

test('handoff reads identity only through public host APIs', async () => {
  const gateway = { request: async () => ({}) }
  for (const key of ['connectionId', 'connection', 'id', 'route']) {
    Object.defineProperty(gateway, key, { get() { throw new Error(`private ${key} read`) } })
  }
  const routes = []
  const route = { connectionId: 'remote', mode: 'remote', profile: 'default', targetProfile: 'default' }
  const handoff = plugin.createHandoff({ host: {
    getGateway: () => gateway,
    activeConnectionId: () => 'remote',
    requestProfile: async (captured, method) => {
      routes.push(captured)
      if (method === 'session.create') return { session_id: 's', stored_session_id: 's' }
      if (method === 'prompt.submit') return { admission_id: 'a' }
      if (method === 'prompt.receipt') return { status: 'terminal', outcome: 'completed' }
      return {}
    },
    openSession: async () => {}
  } })
  const result = await handoff.run({ operationId: 'sdk', cwd: '/project', profile: 'default', prompt: 'test', route })
  assert.equal(result.status, 'completed')
  assert.equal(routes.length, 4)
  assert.ok(routes.every(captured => captured.connectionId === 'remote'))
})

test('Tools Lock never falls back to the dashboard fetch API', async () => {
  const ctx = { fetchJSON() { throw new Error('wrong SDK') } }
  await assert.rejects(plugin.callToolsLockApi(ctx, '/tools-lock'), /context rest unavailable/)
})

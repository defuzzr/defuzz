import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { host } from '@hermes/plugin-sdk'
import plugin, { createWorkspaceModel, WorkspacePage, SettingsView, ManualLintSection } from '../plugin.js'
import { catalog, chooseRow, runEffectsOnce, typeProjectName } from './choiceList.mjs'

const nodes = (node, predicate) => !node || typeof node !== 'object' ? [] : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
const button = (tree, label) => nodes(tree, n => n.type === 'Button' && [n.props.children].flat().join('') === label)[0]
const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]

function fixture(replies = []) {
  const calls = []
  let dispose
  const ctx = { onDispose(fn) { dispose = fn }, async rest(path, opts) {
    calls.push({ path, opts })
    if (path === '/scaffold/projects-root' || String(path).startsWith('/scaffold/projects-root?')) {
      return { path: '/home/user/Tools', source: 'setting', valid: true, default_path: '/home/user/Tools', message: '' }
    }
    const response = replies.shift()
    if (response instanceof Error) throw response
    return typeof response === 'function' ? response() : response
  } }
  return { ctx, calls, model: createWorkspaceModel(ctx), dispose: () => dispose() }
}
const template = { template_id: 'ts-node-golden', name: 'TypeScript', options: { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } } }
const answers = { building: 'service', layout: 'single', languages: ['typescript'] }

function renderHarness(t, Component, props) {
  const slots = []
  let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  return () => { cursor = 0; return Component(props) }
}

test('public single-file ESM, registered workspace and no automatic API activity', () => {
  const source = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')
  for (const [, specifier] of source.matchAll(/from\s+['"]([^'"]+)['"]/g)) assert.ok(['react', 'react/jsx-runtime', '@hermes/plugin-sdk'].includes(specifier), specifier)
  assert.doesNotMatch(source, /localStorage|document\.|window\.|__HERMES_PLUGIN_SDK__|fetchJSON/)
  const h = fixture()
  const entries = []
  plugin.register({ ...h.ctx, register: entry => entries.push(entry) })
  assert.equal(entries.find(e => e.id === 'page').render().type, WorkspacePage)
  assert.equal(h.calls.length, 0)
})

test('idea, list, A/B default, staged failure and discard', async () => {
  const h = fixture([{ matches: [template] }, { proposal_id: 'p1', tree: ['.env.example'] }, { ok: false, check: { stdout: 'failed staged ci' }, created_dirs: [] }, { discarded: true }])
  h.model.edit({ idea: 'Invoice API in TypeScript', name: 'Invoices', answers })
  assert.equal(h.model.get().name, 'Invoices')
  await h.model.match()
  assert.deepEqual(h.calls[0].opts.body, { prompt: 'Invoice API in TypeScript', answers: {} }, 'the list request carries only the idea')
  assert.equal(h.model.get().output, null, 'the list reply is not shown as check output')
  h.model.choose(h.model.get().matches[0])
  assert.equal(h.model.get().options.http_adapter, 'hono')
  h.model.option('http_adapter', 'node_http')
  await h.model.propose()
  assert.deepEqual(h.calls[1].opts.body, { template_id: 'ts-node-golden', name: 'Invoices', answers, options: { http_adapter: 'node_http' }, remember_options: true })
  await h.model.accept()
  assert.equal(h.model.get().proposal.proposal_id, 'p1')
  assert.match(JSON.stringify(h.model.get().output), /failed staged ci/)
  await h.model.discard()
  assert.equal(h.model.get().proposal, null)
  assert.deepEqual(h.calls.map(c => c.path), ['/scaffold/match', '/scaffold/propose', '/scaffold/accept', '/scaffold/discard'])
})

test('successful acceptance clears proposal; pre-move errors preserve output and staging', async () => {
  const error = Object.assign(new Error('check failed'), { body: { stderr: 'tool missing', created_dirs: [] } })
  const h = fixture([{ proposal_id: 'p' }, error, { ok: true, created_dirs: ['/created'] }])
  h.model.edit({ name: 'Example' }); h.model.choose(template)
  await h.model.propose(); await h.model.accept()
  assert.equal(h.model.get().proposal.proposal_id, 'p')
  assert.deepEqual(h.model.get().output.created_dirs, [])
  await h.model.accept()
  assert.equal(h.model.get().proposal, null)
  assert.deepEqual(h.model.get().output.created_dirs, ['/created'])
})

test('partial creation blocks retry and discard without erasing preserved paths', async t => {
  const error = Object.assign(new Error('registration failed'), { body: { detail: { created_dirs: ['/partial'], accepted_repos: [] } } })
  const tsMatch = { matches: [{ template_id: 'ts-node-golden', name: 'TypeScript', options: { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } } }], preferred: 'none', catalog: catalog() }
  const h = fixture([
    tsMatch,
    tsMatch,
    { proposal_id: 'p', tree: [{ name: 'inventory-api', dest: '/partial', files: ['AGENTS.md'] }] },
    error
  ])
  const render = renderHarness(t, WorkspacePage, { ctx: h.ctx })
  runEffectsOnce(t)
  await byDomId(render(), 'start-project').props.onClick()
  await typeProjectName(render(), 'inventory-api')
  await chooseRow(render(), 'template:ts-node-golden')
  await byDomId(render(), 'accept-project').props.onClick()
  assert.match(JSON.stringify(render()), /Some files were created before something went wrong\. They were left in place/)
  assert.equal(byDomId(render(), 'accept-project').props.disabled, true)
  const callsBeforeRetry = h.calls.length
  await byDomId(render(), 'accept-project').props.onClick()
  assert.equal(h.calls.length, callsBeforeRetry)
})

test('connection and profile changes fail closed before further requests', async t => {
  const previous = host.state
  let profile = 'first'
  host.state = { profile: { get: () => profile } }
  t.after(() => { host.state = previous })
  const h = fixture([{ projects: [], coverage: 'verified' }])
  profile = 'second'
  await h.model.load()
  assert.equal(h.calls.length, 0)
  assert.match(h.model.get().error, /profile changed/)
})

test('rapid requests deduplicate; disposed requests cannot publish results', async () => {
  let finish
  const h = fixture([() => new Promise(resolve => { finish = resolve })])
  const pending = h.model.load()
  await h.model.load()
  assert.equal(h.calls.length, 1)
  h.dispose(); finish({ projects: [{ name: 'stale', path: '/stale', registered: true }], coverage: 'verified' }); await pending
  assert.deepEqual(h.model.get().projects, [])
  await h.model.load(); assert.equal(h.calls.length, 1)
})

test('settings read before sequenced save, no hooks or lint requests', async () => {
  const h = fixture([{ value: { rules: [] }, seq: 17 }, { seq: 18 }, { seq: 18, value: { rules: [{ id: 'lint', label: 'Lint', mode: 'both', enabled: true }] } }])
  await h.model.saveSettings(); assert.equal(h.calls.length, 0)
  await h.model.loadSettings()
  h.model.settings({ rules: [{ id: 'lint', label: 'Lint', mode: 'both', enabled: true }] })
  await h.model.saveSettings()
  assert.equal(h.calls[1].opts.body.seq, 18)
  assert.equal(h.model.get().seq, 18)
  assert.deepEqual(h.calls.map(c => c.path), ['/ui-state?key=settings', '/ui-state', '/ui-state?key=settings'])
})

test('V10 settings Lint rules tab Enable all / Clear updates rules without backend requests', t => {
  const h = fixture()
  const render = renderHarness(t, SettingsView, { model: h.model, state: h.model.get() })
  byDomId(render(), 'lint-tab').props.onClick()
  button(render(), 'Clear').props.onClick()
  assert.ok(nodes(render(), n => n.type === 'input' && n.props.type === 'checkbox').every(c => !c.props.checked))
  button(render(), 'Enable all').props.onClick()
  assert.ok(nodes(render(), n => n.type === 'input' && n.props.type === 'checkbox').every(c => c.props.checked))
  assert.equal(h.calls.length, 0)
})

test('workspace exposes one mode, keeps adopted inspector, selects only registered projects', async t => {
  const h = fixture([{ projects: [{ name: 'Copy', path: '/copy', registered: true }, { name: 'Unknown', path: '/unknown', registered: false }] }])
  const render = renderHarness(t, WorkspacePage, { ctx: h.ctx })
  await button(render(), 'Refresh projects').props.onClick()
  const unknownBtn = nodes(render(), n => n.props?.['data-project'] === 'Unknown')[0]
  assert.equal(unknownBtn.props.disabled, true)
  const copyBtn = nodes(render(), n => n.props?.['data-project'] === 'Copy')[0]
  copyBtn.props.onClick()
  const lint = nodes(render(), n => n.type === ManualLintSection)[0]
  assert.equal(lint.props.project, '/copy')
  assert.equal(lint.key, '/copy')
  const originalNavigate = host.navigate
  t.after(() => { host.navigate = originalNavigate })
  let route
  host.navigate = path => { route = path }
  byDomId(render(), 'start-project').props.onClick()
  assert.ok(byDomId(render(), 'new-project-dialog'))
  assert.equal(route, undefined, 'Start project opens modal without navigating to /defuzz/new')
  byDomId(render(), 'settings-button').props.onClick()
  assert.equal(route, '/defuzz/settings')
  assert.deepEqual(h.calls.map(c => c.path), ['/workspace/projects', '/scaffold/projects-root'])
})

test('lint handoff submits once, uses scoped timers, and never re-runs lint', async t => {
  const original = { ...host }
  const rpc = []
  const timers = new Set()
  host.getGateway = () => ({ request: async (method, params) => {
    rpc.push({ method, params })
    if (method === 'session.create') return { session_id: 's', stored_session_id: 'stored' }
    if (method === 'prompt.submit') return { admission_id: 'admission' }
    if (method === 'prompt.receipt') return { status: 'terminal', outcome: 'completed' }
    return {}
  } })
  host.activeConnectionId = () => 'local'
  t.after(() => { for (const timer of timers) clearTimeout(timer); for (const key of Object.keys(host)) delete host[key]; Object.assign(host, original) })
  const h = fixture([{ ok: false, findings: [{ file: 'a.py', line: 1, rule: 'F401', message: 'unused import' }] }])
  h.ctx.setTimeout = (fn, ms) => { const timer = setTimeout(fn, ms); timers.add(timer); return () => { clearTimeout(timer); timers.delete(timer) } }
  const render = renderHarness(t, ManualLintSection, { ctx: h.ctx, project: '/copy', mode: 'pre' })
  await button(render(), 'Run lint').props.onClick()
  await button(render(), 'Fix with Hermes').props.onClick()
  await button(render(), 'Fix with Hermes').props.onClick()
  assert.equal(rpc.filter(call => call.method === 'prompt.submit').length, 1)
  assert.equal(rpc.find(call => call.method === 'session.create').params.cwd, '/copy')
  assert.equal(h.calls.length, 1, 'handoff settlement must never auto-run lint')
  assert.equal(h.calls[0].opts.body.mode, 'pre')
  assert.equal(timers.size, 0)
})

test('canonical registration paths and scoped preview use backend conventions', async () => {
  const h = fixture([{ projects: [{ name: 'Copy', canonical_path: '/copy' }], coverage: 'verified' }, { content: '[redacted]' }])
  await h.model.load()
  h.model.select('/outside'); assert.equal(h.model.get().selected, '')
  h.model.select('/copy'); await h.model.preview('src/a b.py')
  assert.equal(h.calls[1].path, '/workspace/file?project=%2Fcopy&path=src%2Fa%20b.py')
  assert.equal(h.model.get().preview.content, '[redacted]')
})

test('stale settings readback fails visibly rather than claiming saved', async () => {
  const h = fixture([{ seq: 10, value: { rules: [] } }, { seq: 10, value: { rules: [] } }])
  await h.model.loadSettings(); await h.model.saveSettings()
  assert.match(h.model.get().error, /changed elsewhere/)
  assert.equal(h.model.get().seq, 10)
})

test('footer audit scope is disclosed before any invocation and fails closed when scope fails', async t => {
  for (const payload of [new Error('offline'), {}, { scope_disclosure: {} }]) {
    const h = fixture([payload])
    const render = renderHarness(t, WorkspacePage, { ctx: h.ctx })
    await byDomId(render(), 'audit-full-button').props.onClick()
    const modal = byDomId(render(), 'audit-review-dialog')
    assert.equal(byDomId(modal, 'audit-review-consent').props.disabled, true)
    assert.equal(byDomId(modal, 'audit-review-run').props.disabled, true)
    await byDomId(modal, 'audit-review-run').props.onClick()
    assert.deepEqual(h.calls.map(c => c.path), ['/audit/scope'])
  }
})

test('footer audit is manual, narrow and proposals-only, unknown coverage retained', async t => {
  const h = fixture([
    { projects: [{ name: 'Copy', path: '/copy', registered: true }], coverage: 'verified' },
    { scope_disclosure: 'Server scope' },
    { run_id: 'r', status: 'completed' },
    { run_id: 'r', status: 'completed' },
    { coverage: 'could_not_verify', proposals: [{ id: 'p', selected_by_default: false }] }
  ])
  const render = renderHarness(t, WorkspacePage, { ctx: h.ctx })
  assert.equal(h.calls.length, 0)
  await button(render(), 'Refresh projects').props.onClick()
  nodes(render(), n => n.props?.['data-project'] === 'Copy')[0].props.onClick()
  await byDomId(render(), 'audit-full-button').props.onClick()
  const modal = byDomId(render(), 'audit-review-dialog')
  byDomId(modal, 'audit-review-consent').props.onChange({ target: { checked: true } })
  await byDomId(render(), 'audit-review-run').props.onClick()
  assert.deepEqual(h.calls[2], { path: '/audit/start', opts: { method: 'POST', body: { selected_projects: ['/copy'] } } })
  const text = JSON.stringify(render())
  assert.match(text, /This audit cannot tell whether working code is correct\./)
  assert.match(text, /could_not_verify/)
  assert.match(text, /selected_by_default/)
  assert.deepEqual(h.calls.map(c => c.path), ['/workspace/projects', '/audit/scope', '/audit/start', '/audit/status?run_id=r', '/audit/report?run_id=r', '/audit/summary?run_id=r'])
})

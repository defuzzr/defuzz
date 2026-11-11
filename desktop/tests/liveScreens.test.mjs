import test from 'node:test'
import assert from 'node:assert/strict'
import * as ui from '../plugin.js'
import { catalog, chooseRow, runEffectsOnce, typeProjectName } from './choiceList.mjs'

const nodes = (node, predicate) => !node || typeof node !== 'object' ? [] : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
const button = (tree, label) => nodes(tree, n => n.type === 'Button' && [n.props.children].flat().join('') === label)[0]

test('routes, one sidebar entry and palette commands stay in step (no /defuzz/audit, /defuzz/new or /defuzz/pro)', () => {
  const entries = []
  ui.default.register({ register: entry => entries.push(entry) })
  const routes = entries.filter(e => e.area === 'routes')
  assert.equal(routes.length, 4)
  assert.equal(routes.some(r => ['/defuzz/audit', '/defuzz/new', '/defuzz/pro'].includes(r.data.path)), false)
  for (const route of routes) assert.equal(route.render().type, ui.WorkspacePage)
  const sidebar = entries.filter(e => e.area === 'sidebar')
  assert.deepEqual(sidebar.map(e => [e.data.path, e.data.label]), [['/defuzz', 'Defuzz']])
  for (const entry of entries.filter(e => e.area === 'palette')) assert.ok(routes.some(r => r.data.path === entry.data.path))
})

test('Settings tools section discloses real state without render requests and without AuditPaneView', () => {
  const h = fixture(), model = ui.createLiveModel(h.ctx)
  const tools = ui.ComputerToolsSection({ model, state: model.get(), project: '', projectState: [] })
  assert.match(JSON.stringify(tools), /Choose a project on the main page/)
  assert.match(JSON.stringify(tools), /TOOLS.lock contents \(read only, nothing is run\)/)
  assert.ok(button(tools, 'Review setup confirmation'))
  assert.equal(button(tools, 'Review setup confirmation').props.disabled, true)
  assert.equal(ui.AuditPaneView, undefined)
  assert.equal(h.calls.length, 0)
})

test('Settings tools section installed readback preserves null and mismatch evidence', () => {
  const model = ui.createLiveModel(fixture().ctx)
  const items = [
    { name: 'biome', expected_version: '2.6.6', installed_version: '1.0.0', executable_path: '/bin/biome', status: 'mismatch' },
    { name: 'go', expected_version: '1.27.3', installed_version: null, executable_path: null, status: 'missing' },
  ]
  const tree = ui.ComputerToolsSection({ model, state: { ...model.get(), tools: { items } }, project: '', projectState: [] })
  const outputs = nodes(tree, n => typeof n.props?.children === 'string' && n.props.children.includes('installed_version'))
  const readback = JSON.parse(outputs.at(-1).props.children)
  assert.deepEqual(readback, items)
})

test('seeded rules inherit tool severity', () => {
  const model = ui.createWorkspaceModel(fixture().ctx)
  for (const rule of model.get().settings.rules) assert.equal(Object.hasOwn(rule, 'severity'), false)
})

test('V10 Lint rules tab checkbox toggle updates rules without adding custom severity', t => {
  const slots = []; let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  let state = { settings: { rules: [] } }
  const model = { get: () => state, settings: settings => { state = { settings } } }
  const render = () => { cursor = 0; return ui.SettingsView({ model, state }) }
  nodes(render(), n => n.props?.id === 'lint-tab')[0].props.onClick()
  const checkbox = nodes(render(), n => n.type === 'input' && n.props?.type === 'checkbox')[0]
  checkbox.props.onChange({ target: { checked: false } })
  assert.equal(state.settings.rules[0].id, 'biome')
  assert.equal(state.settings.rules[0].enabled, false)
  assert.equal(Object.hasOwn(state.settings.rules[0], 'severity'), false)
})

test('workspace rule settings autosave valid tool IDs with severity and visible status', async () => {
  const h = fixture()
  let saved = { seq: 4, value: { rules: [] } }
  h.ctx.rest = async (path, options) => {
    h.calls.push({ path, options })
    if (options?.body) saved = { seq: options.body.seq, value: options.body.value }
    return saved
  }
  const model = ui.createWorkspaceModel(h.ctx)
  await model.loadSettings()
  model.settings({ rules: [{ id: 'ruff:F401', enabled: false, mode: 'post', severity: 'warning' }] })
  assert.equal(model.get().settingsSaveState, 'pending')
  await h.tick()
  assert.equal(model.get().settingsSaveState, 'saved')
  assert.equal(saved.seq, 5)
  assert.equal(saved.value.rules[0].id, 'ruff:F401')
  assert.equal(h.calls.at(-1).path, '/ui-state?key=settings')
  assert.equal(ui.validRuleId, undefined)
})

test('registration coverage never turns unknown rows into registered projects', async () => {
  const model = ui.createWorkspaceModel({ onDispose() {}, rest: async () => ({ coverage: 'could_not_verify', projects: [{ canonical_path: '/unknown' }] }) })
  await model.load()
  model.select('/unknown')
  assert.equal(model.get().selected, '')
  assert.equal(model.get().projectsLoaded, true)
  assert.equal(model.get().projects[0].registrationStatus, 'could_not_verify')
})

test('Start project modal surfaces per-repo registration failure and manual fallback distinctly from creation', async t => {
  const slots = []; let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  runEffectsOnce(t)
  const replies = [
    { proposal_id: 'p1', tree: [{ name: 'inventory-api', dest: '/copy', files: ['AGENTS.md'] }] },
    { status: 'created', repos: [{ path: '/copy', registration: 'skipped', registration_result: { registered: false, reason: 'API unavailable' } }] },
    { coverage: 'verified', projects: [] }
  ]
  const ctx = { onDispose() {}, rest: async path => {
    if (String(path).startsWith('/scaffold/projects-root')) return { path: '/home/user/Tools', source: 'setting', valid: true, default_path: '/home/user/Tools', message: '' }
    if (path === '/scaffold/match' || path === '/scaffold/discard') return { matches: [], preferred: 'none', status: 'discarded', catalog: catalog() }
    return replies.shift()
  } }
  const render = () => { cursor = 0; return ui.WorkspacePage({ ctx }) }
  await nodes(render(), n => n.props?.id === 'start-project')[0].props.onClick()
  await typeProjectName(render(), 'inventory-api')
  await chooseRow(render(), 'template:ts-node-golden')
  await nodes(render(), n => n.props?.id === 'accept-project')[0].props.onClick()
  const text = JSON.stringify(render())
  assert.match(text, /The project was created but not added to Hermes\. Add it yourself:/)
  assert.match(text, /API unavailable/)
})

test('Start project modal manual registration arguments preserve quotes and newlines as JSON', async t => {
  const slots = []; let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  runEffectsOnce(t)
  const repo = { path: '/copy/"quoted"\nfolder', registration_name: 'A "name"\n', registration: 'failed', registration_result: { registered: false, reason: 'API "down"\n' } }
  const replies = [
    { proposal_id: 'p2', tree: [{ name: 'inventory-api', dest: repo.path, files: ['AGENTS.md'] }] },
    { status: 'created', repos: [repo] },
    { coverage: 'verified', projects: [] }
  ]
  const ctx = { onDispose() {}, rest: async path => {
    if (String(path).startsWith('/scaffold/projects-root')) return { path: '/home/user/Tools', source: 'setting', valid: true, default_path: '/home/user/Tools', message: '' }
    if (path === '/scaffold/match' || path === '/scaffold/discard') return { matches: [], preferred: 'none', status: 'discarded', catalog: catalog() }
    return replies.shift()
  } }
  const render = () => { cursor = 0; return ui.WorkspacePage({ ctx }) }
  await nodes(render(), n => n.props?.id === 'start-project')[0].props.onClick()
  await typeProjectName(render(), 'inventory-api')
  await chooseRow(render(), 'template:ts-node-golden')
  await nodes(render(), n => n.props?.id === 'accept-project')[0].props.onClick()
  const tree = render()
  const message = nodes(tree, n => typeof n.props?.children === 'string' && n.props.children.includes('desktop_project '))[0]?.props.children
  assert.ok(message)
  const args = message.split('desktop_project ')[1].replace(/\.$/, '')
  assert.deepEqual(JSON.parse(args), { action: 'create', name: repo.registration_name, path: repo.path })
  assert.ok(message.includes(JSON.stringify(repo.registration_result.reason)))
  assert.ok(message.includes(JSON.stringify(repo.path)))
})

test('Settings tools section reads installed version status without a project or lock', async () => {
  const calls = []
  const ctx = { onDispose() {}, async rest(path) { calls.push(path); return path === '/tools/status' ? { items: [{ name: 'ruff', version: 'manifest-only', installed_version: 'actual-0.9' }] } : {} } }
  const model = ui.createLiveModel(ctx)
  await model.loadPro()
  assert.deepEqual(calls, ['/tools/status', '/setup/status'])
  const tree = ui.ComputerToolsSection({ model, state: model.get(), project: '' })
  assert.match(JSON.stringify(tree), /actual-0.9/)
  assert.match(JSON.stringify(tree), /Installed tool versions/)
})

test('manual lint provides explicit PRE POST BOTH selector and versions disclosure', () => {
  const h = fixture()
  const tree = ui.ManualLintSection({ ctx: h.ctx, project: '/copy' })
  const select = nodes(tree, n => n.props?.['aria-label'] === 'Run lint group')[0]
  assert.ok(select)
  assert.deepEqual(select.props.children.map(n => n.props.value), ['pre', 'post', 'both'])
  assert.match(JSON.stringify(tree), /Tool versions/)
  assert.equal(h.calls.length, 0)
})

test('tool setup is explicit, uses confirm true, and reads status after mutation', async () => {
  const calls = []
  const model = ui.createLiveModel({ onDispose() {}, async rest(path, options) { calls.push({ path, options }); return { lazy_installs_allowed: true, plan: ['review me'], state: 'running' } } })
  assert.equal(typeof model.setup, 'function')
  await model.setup()
  assert.equal(calls.length, 0, 'cannot install before reading disclosure')
  await model.loadPro()
  await model.setup()
  assert.deepEqual(calls[2], { path: '/setup', options: { method: 'POST', body: { confirm: true } } })
  assert.equal(calls[3].path, '/setup/status')
  await model.setup(true)
  assert.equal(calls[4].path, '/setup/cancel')
  assert.equal(calls[5].path, '/setup/status')
})

test('tool status remount ignores old responses and never continues old reads', async () => {
  let resolve
  const calls = []
  const model = ui.createLiveModel({ onDispose() {}, rest(path) { calls.push(path); return calls.length === 1 ? new Promise(done => { resolve = done }) : Promise.resolve({}) } })
  const pending = model.loadPro('/copy')
  assert.equal(model.get().busy, true)
  model.dispose(); model.mount()
  resolve({ items: [] })
  await pending
  assert.equal(model.get().tools, null)
  assert.equal(model.get().busy, false)
  assert.equal(calls.length, 1)
})

test('tool status errors are per-resource; refresh clears stale snapshots', async () => {
  let fail = false
  const model = ui.createLiveModel({ onDispose() {}, async rest() { if (fail) throw new Error('offline'); return { version: '1', plan: ['old'], lazy_installs_allowed: true } } })
  await model.loadPro('/copy')
  fail = true
  await model.loadPro('/copy')
  assert.equal(model.get().busy, false)
  assert.equal(model.get().tools, null)
  assert.equal(model.get().setup, null)
  assert.equal(Object.keys(model.get().resourceErrors).length, 4)
  assert.match(JSON.stringify(ui.ComputerToolsSection({ model, state: model.get(), project: '/copy' })), /offline/)
})

test('projects loading, empty and errors remain distinct', async () => {
  let finish
  const model = ui.createWorkspaceModel({ onDispose() {}, rest: () => new Promise(resolve => { finish = resolve }) })
  const pending = model.load()
  assert.equal(model.get().busy, true)
  assert.equal(model.get().projectsLoaded, undefined)
  finish({ projects: [], coverage: 'verified' }); await pending
  assert.equal(model.get().projectsLoaded, true)
  assert.equal(model.get().busy, false)
  assert.deepEqual(model.get().projects, [])
  const failed = ui.createWorkspaceModel({ onDispose() {}, rest: async () => { throw new Error('registration unavailable') } })
  await failed.load()
  assert.match(failed.get().error, /registration unavailable/)
  assert.equal(failed.get().projectsLoaded, undefined)
})

test('workspace route renders V10 SettingsView (without Componentize card) with the tools section, and the inspector as reachable screens', () => {
  const ctx = fixture().ctx
  const settings = ui.WorkspacePage({ ctx, initialScreen: 'settings' })
  const settingsView = nodes(settings, n => n.type === ui.SettingsView)[0]
  assert.ok(settingsView)
  assert.equal(ui.ComponentizeSettingsView, undefined)
  assert.equal(nodes(ui.SettingsView(settingsView.props), n => n.type === ui.ComputerToolsSection).length, 1)
  assert.equal(ui.ProView, undefined)
  const adopt = ui.WorkspacePage({ ctx, initialScreen: 'adopt' })
  assert.equal(nodes(adopt, n => n.type === ui.AdoptBeforeAfterPage).length, 1)
  assert.ok(nodes(adopt, n => n.props?.id === 'start-project')[0])
  assert.ok(nodes(adopt, n => n.props?.id === 'settings-button')[0])
  assert.ok(nodes(adopt, n => n.props?.id === 'inspector-back-button')[0])
})

test('manual group selection reaches the lint POST and versions use the tools endpoint', async t => {
  const slots = []; let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  const calls = []
  const ctx = { onDispose() {}, async rest(path, options) { calls.push({ path, options }); return path === '/tools/status' ? { items: [{ name: 'ruff', version: '0.1', state: 'installed' }] } : { findings: [], state: 'done' } } }
  const render = () => { cursor = 0; return ui.ManualLintSection({ ctx, project: '/copy' }) }
  nodes(render(), n => n.props?.['aria-label'] === 'Run lint group')[0].props.onChange({ target: { value: 'post' } })
  await button(render(), 'Run lint').props.onClick()
  assert.deepEqual(calls[0].options.body, { project: '/copy', mode: 'post' })
  await button(render(), 'Refresh tool versions').props.onClick()
  assert.equal(calls[1].path, '/tools/status')
  assert.match(JSON.stringify(render()), /0.1/)
})

function fixture() {
  const calls = [], timers = new Set()
  let settings = { enabled_on_adopt: true, run_survey_on_new: false, cli_path_override: null }
  const ctx = {
    onDispose() {}, setTimeout(fn) { timers.add(fn); return () => timers.delete(fn) },
    async rest(path, options) {
      calls.push({ path, options })
      if (path === '/componentize/settings') {
        if (options?.method === 'PUT') settings = options.body
        return { ...settings }
      }
      return { detected: false, last_survey: null }
    }
  }
  return { ctx, calls, timers, tick: async () => { const jobs = [...timers]; timers.clear(); for (const fn of jobs) await fn() } }
}

test('tool status reads tools/setup/lock and raw project state; trust pins displayed hash then rereads', async () => {
  const calls = []
  const ctx = { onDispose() {}, async rest(path, options) {
    calls.push({ path, options })
    if (path.startsWith('/tools-lock?')) return { lock: '/copy/TOOLS.lock', trust: { tools_lock_hash: 'abc', status: 'unknown' } }
    return { state: 'idle' }
  } }
  const model = ui.createLiveModel(ctx)
  assert.equal(typeof model.loadPro, 'function')
  await model.loadPro('/copy')
  assert.deepEqual(calls.map(c => c.path), ['/tools/status', '/setup/status', '/tools-lock?project=%2Fcopy', '/workspace/file?project=%2Fcopy&path=TOOLS.lock'])
  assert.equal(model.get().lock.trust.status, 'unknown')
  await model.trustLock('/copy')
  assert.deepEqual(calls[4], { path: '/tools-lock/trust', options: { method: 'POST', body: { project: '/copy', expected_hash: 'abc', confirm: true } } })
  assert.equal(calls[5].path, '/tools-lock?project=%2Fcopy')
})

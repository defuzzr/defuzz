import test from 'node:test'
import assert from 'node:assert/strict'
import * as ui from '../plugin.js'
import { host } from '@hermes/plugin-sdk'

const nodes = (node, predicate = () => true) => !node || typeof node !== 'object' ? [] : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
const textOf = node => [node?.props?.children].flat().map(c => typeof c === 'string' ? c : c && typeof c === 'object' ? textOf(c) : '').join('')
const button = (tree, label) => nodes(tree, n => n.type === 'Button' && textOf(n) === label)[0]
const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]

function slotHarness(t) {
  const slots = []; let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  return render => () => { cursor = 0; return render() }
}

function navSpy(t) {
  const original = host.navigate, routes = []
  host.navigate = path => routes.push(path)
  t.after(() => { host.navigate = original })
  return routes
}

const quietCtx = () => ({ onDispose() {}, rest: async () => ({}) })

test('one sidebar entry named Defuzz; three palette commands; routes keep deep links; no Pro anywhere', () => {
  const entries = []
  ui.default.register({ register: entry => entries.push(entry) })
  const sidebar = entries.filter(e => e.area === 'sidebar')
  assert.equal(sidebar.length, 1)
  assert.equal(sidebar[0].data.label, 'Defuzz')
  assert.equal(sidebar[0].data.path, '/defuzz')
  const palette = entries.filter(e => e.area === 'palette')
  assert.deepEqual(palette.map(p => p.data.label), ['Project Defuzz: Open', 'Project Defuzz: Settings', 'Project Defuzz: Adopted copy inspector'])
  assert.deepEqual(palette.map(p => p.data.path), ['/defuzz', '/defuzz/settings', '/defuzz/inspector'])
  const routes = entries.filter(e => e.area === 'routes')
  assert.deepEqual(routes.map(r => r.data.path).sort(), ['/defuzz', '/defuzz/inspector', '/defuzz/projects', '/defuzz/settings'])
  for (const route of routes) assert.equal(route.render().type, ui.WorkspacePage)
  for (const p of palette) assert.ok(routes.some(r => r.data.path === p.data.path), `palette ${p.data.label} has a route`)
  assert.equal(new Set(entries.map(e => e.id)).size, entries.length, 'registration ids are unique')
  assert.equal(entries.some(e => /\/pro$/.test(e.data?.path || '') || /\bPro\b/.test(e.data?.label || '')), false)
  assert.equal(ui.WORKSPACE_SCREENS.some(s => s.screen === 'pro'), false)
  assert.equal(ui.ProView, undefined, 'the Pro screen is gone')
})

test('main page reaches Settings and the Adopted copy inspector with labelled buttons, and gets back', t => {
  const routes = navSpy(t)
  const render = slotHarness(t)(() => ui.WorkspacePage({ ctx: quietCtx() }))
  const main = render()
  assert.ok(nodes(main, n => n.props?.id === 'workspace')[0], 'opens on the main page')
  const settingsBtn = byDomId(main, 'settings-button')
  const inspectorBtn = byDomId(main, 'inspector-button')
  for (const control of [settingsBtn, inspectorBtn]) {
    assert.equal(control?.type, 'Button', 'a real button, so it is keyboard reachable')
    assert.ok(control.props['aria-label'])
    assert.ok(textOf(control).trim(), 'visible text')
    assert.notEqual(control.props.disabled, true)
  }
  assert.equal(inspectorBtn.props['aria-label'], 'Adopted copy inspector')

  inspectorBtn.props.onClick()
  assert.equal(routes.at(-1), '/defuzz/inspector')
  const adopt = render()
  assert.equal(nodes(adopt, n => n.type === ui.AdoptBeforeAfterPage).length, 1)
  assert.equal(nodes(adopt, n => n.props?.id === 'workspace')[0], undefined)
  const back = byDomId(adopt, 'inspector-back-button')
  assert.equal(back?.type, 'Button')
  assert.equal(back.props['aria-label'], 'Back to workspace')
  back.props.onClick()
  assert.equal(routes.at(-1), '/defuzz')
  assert.ok(nodes(render(), n => n.props?.id === 'workspace')[0], 'back on the main page')

  byDomId(render(), 'settings-button').props.onClick()
  assert.equal(routes.at(-1), '/defuzz/settings')
  const settings = render()
  assert.ok(nodes(settings, n => n.type === ui.SettingsView)[0])
  byDomId(settings, 'inspector-button').props.onClick()
  assert.equal(routes.at(-1), '/defuzz/inspector')
  byDomId(render(), 'inspector-button').props.onClick()
  assert.equal(routes.at(-1), '/defuzz', 'the inspector button toggles back to the main page')
})

test('no screen shows the word Pro', t => {
  navSpy(t)
  for (const screen of ['main', 'settings', 'adopt']) {
    const render = slotHarness(t)(() => ui.WorkspacePage({ ctx: quietCtx(), initialScreen: screen }))
    const page = render()
    assert.doesNotMatch(JSON.stringify(page), /\bPro\b/, `screen ${screen}`)
    if (screen === 'settings') {
      const props = nodes(page, n => n.type === ui.SettingsView)[0].props
      const settingsTree = ui.SettingsView(props)
      assert.doesNotMatch(JSON.stringify(settingsTree), /\bPro\b/)
      const tools = nodes(settingsTree, n => n.type === ui.ComputerToolsSection)[0]
      assert.doesNotMatch(JSON.stringify(ui.ComputerToolsSection(tools.props)), /\bPro\b|diagnostic|advanced/i)
    }
  }
  assert.doesNotMatch(JSON.stringify(ui.ManualLintSection({ ctx: quietCtx(), project: '/copy' })), /\bPro\b/)
})

test('Settings holds Tools on this computer with the live tool model and the selected project', t => {
  navSpy(t)
  const render = slotHarness(t)(() => ui.WorkspacePage({ ctx: quietCtx(), initialScreen: 'settings' }))
  const page = render()
  const props = nodes(page, n => n.type === ui.SettingsView)[0].props
  assert.equal(typeof props.live?.loadPro, 'function')
  assert.equal(typeof props.live?.setup, 'function')
  assert.equal(typeof props.live?.trustLock, 'function')
  const tools = nodes(ui.SettingsView(props), n => n.type === ui.ComputerToolsSection)[0]
  assert.ok(tools, 'Settings renders the tools section')
  assert.equal(tools.props.model, props.live)
  assert.equal(tools.props.project, props.project)
})

test('Tools on this computer: nothing loads on render; refresh reads status; setup needs the plan, then review, then confirm', async t => {
  const render = slotHarness(t)
  const calls = []
  const ctx = { onDispose() {}, async rest(path, options) {
    calls.push({ path, options })
    if (path === '/tools/status') return { lazy_installs_allowed: true, plan: ['ruff 0.9 (12 MB)'], items: [] }
    return { state: 'idle' }
  } }
  const model = ui.createLiveModel(ctx)
  const view = render(() => ui.ComputerToolsSection({ ctx, model, state: model.get(), project: '', projectState: [] }))
  let tree = view()
  assert.equal(calls.length, 0, 'no request on render')
  assert.match(JSON.stringify(tree), /Tools on this computer/)
  assert.equal(nodes(tree, n => n.props?.['data-testid'] === 'settings-computer-tools')[0]?.props['data-color-scheme'], 'no-red-green')
  assert.equal(button(tree, 'Review setup confirmation').props.disabled, true, 'no setup before the plan is shown')
  assert.equal(nodes(tree, n => n.props?.['aria-label'] === 'Confirm tool setup').length, 0)
  await button(tree, 'Check tools now').props.onClick()
  assert.deepEqual(calls.map(c => c.path), ['/tools/status', '/setup/status'])
  tree = view()
  assert.match(JSON.stringify(tree), /ruff 0.9 \(12 MB\)/, 'the plan is disclosed')
  assert.equal(button(tree, 'Confirm download and setup'), undefined, 'no confirm button before review')
  button(tree, 'Review setup confirmation').props.onClick()
  tree = view()
  assert.ok(nodes(tree, n => n.props?.['aria-label'] === 'Confirm tool setup')[0])
  await button(tree, 'Confirm download and setup').props.onClick()
  assert.deepEqual(calls[2], { path: '/setup', options: { method: 'POST', body: { confirm: true } } })
  assert.equal(calls[3].path, '/setup/status')
  tree = view()
  assert.equal(button(tree, 'Confirm download and setup'), undefined, 'a fresh confirmation is needed next time')
  button(tree, 'Review setup confirmation').props.onClick()
  button(view(), 'Cancel setup confirmation').props.onClick()
  assert.equal(button(view(), 'Confirm download and setup'), undefined)
  assert.equal(calls.length, 4)
})

test('Tools on this computer: trust shows the hash first, sends that exact hash, and asks again each time', async t => {
  const render = slotHarness(t)
  const calls = []
  const ctx = { onDispose() {}, async rest(path, options) {
    calls.push({ path, options })
    if (path.startsWith('/tools-lock?')) return { lock: '/copy/TOOLS.lock', trust: { tools_lock_hash: 'abc123', status: 'unknown' } }
    if (path.startsWith('/workspace/file')) return { content: 'ruff = "0.9"' }
    return { state: 'idle' }
  } }
  const model = ui.createLiveModel(ctx)
  const view = render(() => ui.ComputerToolsSection({ ctx, model, state: model.get(), project: '/copy', projectState: [] }))
  assert.equal(button(view(), 'Review trust confirmation').props.disabled, true, 'no trust before the lock is read')
  await model.loadPro('/copy')
  let tree = view()
  assert.match(JSON.stringify(tree), /ruff = \\"0.9\\"/, 'lock bytes are shown')
  assert.equal(button(tree, 'Trust displayed hash'), undefined)
  button(tree, 'Review trust confirmation').props.onClick()
  tree = view()
  const group = nodes(tree, n => n.props?.['aria-label'] === 'Confirm lock trust')[0]
  assert.match(JSON.stringify(group), /abc123/, 'hash is shown inside the confirmation')
  await button(tree, 'Trust displayed hash').props.onClick()
  assert.deepEqual(calls.at(-2), { path: '/tools-lock/trust', options: { method: 'POST', body: { project: '/copy', expected_hash: 'abc123', confirm: true } } })
  assert.equal(calls.at(-1).path, '/tools-lock?project=%2Fcopy')
  assert.equal(button(view(), 'Trust displayed hash'), undefined, 'a fresh confirmation is needed next time')
  const other = render(() => ui.ComputerToolsSection({ ctx, model, state: model.get(), project: '/other', projectState: [] }))
  assert.equal(button(other(), 'Review trust confirmation').props.disabled, true, 'a lock read for another project cannot be trusted')
  assert.match(JSON.stringify(ui.ComputerToolsSection({ ctx, model, state: model.get(), project: '', projectState: [] })), /Choose a project on the main page/)
})

test('first run: Settings starts with every default set', t => {
  const model = ui.createWorkspaceModel(quietCtx())
  const rules = model.get().settings.rules
  assert.ok(rules.length > 0 && rules.every(r => r.enabled === true && ['pre', 'post', 'both'].includes(r.mode)))
  const render = slotHarness(t)(() => ui.SettingsView({ ctx: quietCtx(), model, state: model.get() }))
  const tree = render()
  assert.equal(byDomId(tree, 'auditor-tab').props['aria-pressed'], true, 'opens on a tab')
  byDomId(tree, 'lint-tab').props.onClick()
  const boxes = nodes(render(), n => n.type === 'input' && n.props?.type === 'checkbox')
  assert.ok(boxes.length > 0 && boxes.every(b => b.props.checked === true), 'every lint tool starts on')
})

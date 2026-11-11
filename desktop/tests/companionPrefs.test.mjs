import test from 'node:test'
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'

const nodes = (node, predicate = () => true) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
const byId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const textOf = node =>
  !node
    ? ''
    : typeof node === 'string' || typeof node === 'number'
      ? String(node)
      : [node.props?.children].flat().map(textOf).join('')
const button = (tree, label) => nodes(tree, n => (n.type === 'Button' || n.type === 'button') && textOf(n) === label)[0]

const DEFAULTS = { enabled_on_adopt: true, run_survey_on_new: false, cli_path_override: null }
const TOOL_PATH = '/opt/tools/componentize'

function backend({ stored = { ...DEFAULTS }, failLoad = null, putError = null, status = { detected: true, version: '1.2.0', source: 'hermes', last_survey: null } } = {}) {
  const calls = []
  const ctx = {
    onDispose() {},
    async rest(path, options) {
      calls.push({ path, options })
      if (path === '/componentize/settings') {
        if (options?.method === 'PUT') {
          if (putError) throw putError
          stored = { ...options.body }
          return { ...stored }
        }
        if (failLoad) throw failLoad
        return { ...stored }
      }
      if (path === '/componentize/status') return status
      throw new Error('unexpected path ' + path)
    }
  }
  return { ctx, calls, puts: () => calls.filter(c => c.options?.method === 'PUT'), stored: () => stored }
}

function scoped(t, ctx) {
  const previous = host.state
  let profile = 'one'
  host.state = { profile: { get: () => profile } }
  t.after(() => { host.state = previous })
  return { rest: ui.createScopedRest(ctx), switchProfile: next => { profile = next } }
}

function section(t, ctx, props = {}) {
  const slots = []
  let cursor = 0
  const effects = []
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  globalThis.__adoptTestUseEffect = fn => effects.push(fn)
  t.after(() => { delete globalThis.__adoptTestUseState; delete globalThis.__adoptTestUseEffect })
  const render = () => { cursor = 0; return ui.CompanionPrefsSection({ ctx, ...props }) }
  return { render, effects }
}

test('model: load shows saved values and starts clean', async t => {
  const b = backend({ stored: { enabled_on_adopt: false, run_survey_on_new: true, cli_path_override: TOOL_PATH } })
  const m = ui.createCompanionPrefsModel(scoped(t, b.ctx).rest)
  assert.equal(m.get().phase, 'idle')
  await m.load()
  const s = m.get()
  assert.equal(s.phase, 'ready')
  assert.deepEqual(s.draft, { enabled_on_adopt: false, run_survey_on_new: true, cli_path_override: TOOL_PATH })
  assert.equal(s.dirty, false)
  assert.deepEqual(b.calls.map(c => [c.path, c.options?.method]), [['/componentize/settings', undefined]])
})

test('model: defaults from the route show as checked / unchecked / empty path', async t => {
  const b = backend()
  const m = ui.createCompanionPrefsModel(scoped(t, b.ctx).rest)
  await m.load()
  assert.deepEqual(m.get().draft, { enabled_on_adopt: true, run_survey_on_new: false, cli_path_override: '' })
})

test('model: edits change the draft only; no request before Save; Save sends exactly three typed keys, empty path -> null', async t => {
  const b = backend({ stored: { ...DEFAULTS, cli_path_override: TOOL_PATH } })
  const m = ui.createCompanionPrefsModel(scoped(t, b.ctx).rest)
  await m.load()
  m.edit({ enabled_on_adopt: false })
  m.edit({ run_survey_on_new: true })
  m.edit({ cli_path_override: '   ' })
  assert.equal(m.get().dirty, true)
  assert.equal(b.calls.length, 1, 'editing never sends a request')
  await m.save()
  const [put] = b.puts()
  assert.ok(put)
  assert.deepEqual(Object.keys(put.options.body).sort(), ['cli_path_override', 'enabled_on_adopt', 'run_survey_on_new'])
  assert.deepEqual(put.options.body, { enabled_on_adopt: false, run_survey_on_new: true, cli_path_override: null })
  assert.equal(m.get().saveState, 'saved')
  assert.equal(m.get().dirty, false)
  assert.deepEqual(m.get().saved, { enabled_on_adopt: false, run_survey_on_new: true, cli_path_override: null })

  m.edit({ cli_path_override: TOOL_PATH })
  await m.save()
  assert.equal(b.puts()[1].options.body.cli_path_override, TOOL_PATH)
  assert.equal(typeof b.puts()[1].options.body.enabled_on_adopt, 'boolean')
})

test('model: Revert restores the saved values without a request', async t => {
  const b = backend()
  const m = ui.createCompanionPrefsModel(scoped(t, b.ctx).rest)
  await m.load()
  m.edit({ enabled_on_adopt: false, cli_path_override: TOOL_PATH })
  m.revert()
  assert.deepEqual(m.get().draft, { enabled_on_adopt: true, run_survey_on_new: false, cli_path_override: '' })
  assert.equal(m.get().dirty, false)
  assert.equal(b.calls.length, 1)
})

test('model: a 400 from the route shows the backend message and keeps the draft', async t => {
  const err = new Error('400: {"error":"cli_path_override must be a nonempty executable path or null"}')
  const b = backend({ putError: err })
  const m = ui.createCompanionPrefsModel(scoped(t, b.ctx).rest)
  await m.load()
  m.edit({ cli_path_override: 'bad\u0000path' })
  await m.save()
  const s = m.get()
  assert.equal(s.saveState, 'error')
  assert.equal(s.error, 'cli_path_override must be a nonempty executable path or null')
  assert.equal(s.draft.cli_path_override, 'bad\u0000path')
  assert.equal(s.dirty, true)
  assert.deepEqual(s.saved, DEFAULTS)
})

test('model: an error object returned (not thrown) is also shown', async t => {
  const b = backend()
  b.ctx.rest = async (path, options) => options?.method === 'PUT' ? { error: 'enabled_on_adopt must be a boolean' } : { ...DEFAULTS }
  const m = ui.createCompanionPrefsModel(scoped(t, b.ctx).rest)
  await m.load()
  m.edit({ enabled_on_adopt: false })
  await m.save()
  assert.equal(m.get().saveState, 'error')
  assert.equal(m.get().error, 'enabled_on_adopt must be a boolean')
  assert.equal(m.get().dirty, true)
})

test('model: load failure (thrown, unavailable shape, bad shape) gives load-error; Try again recovers', async t => {
  const b = backend({ failLoad: new Error('500: {"error":"componentize settings unavailable"}') })
  const m = ui.createCompanionPrefsModel(scoped(t, b.ctx).rest)
  await m.load()
  assert.equal(m.get().phase, 'load-error')
  assert.equal(m.get().loadError, 'componentize settings unavailable')
  await m.save()
  assert.equal(b.puts().length, 0, 'nothing can be saved while not loaded')

  const bad = ui.createCompanionPrefsModel(async () => ({ enabled_on_adopt: 'yes', run_survey_on_new: false, cli_path_override: null }))
  await bad.load()
  assert.equal(bad.get().phase, 'load-error')

  const unavailable = ui.createCompanionPrefsModel(async () => ({ error: 'componentize settings unavailable' }))
  await unavailable.load()
  assert.equal(unavailable.get().loadError, 'componentize settings unavailable')

  let fail = true
  const flaky = ui.createCompanionPrefsModel(async () => { if (fail) throw new Error('offline'); return { ...DEFAULTS } })
  await flaky.load()
  assert.equal(flaky.get().phase, 'load-error')
  fail = false
  await flaky.load()
  assert.equal(flaky.get().phase, 'ready')
})

test('model: switching profile while dirty does not PUT and keeps the draft', async t => {
  const b = backend()
  const s = scoped(t, b.ctx)
  const m = ui.createCompanionPrefsModel(s.rest)
  await m.load()
  m.edit({ run_survey_on_new: true })
  s.switchProfile('two')
  await m.save()
  assert.equal(b.puts().length, 0)
  assert.equal(m.get().saveState, 'error')
  assert.match(m.get().error, /profile changed/i)
  assert.equal(m.get().draft.run_survey_on_new, true)
})

test('model: Check for the command shows the status route result', async t => {
  const b = backend()
  const m = ui.createCompanionPrefsModel(scoped(t, b.ctx).rest)
  await m.load()
  await m.checkCommand()
  assert.equal(b.calls.at(-1).path, '/componentize/status')
  assert.match(m.get().commandLine, /found/i)
  assert.match(m.get().commandLine, /1\.2\.0/)
  const missing = ui.createCompanionPrefsModel(async path => path === '/componentize/status' ? { detected: false, version: null, source: 'absent', last_survey: null } : { ...DEFAULTS })
  await missing.load()
  await missing.checkCommand()
  assert.match(missing.get().commandLine, /not found/i)
})

test('section: renders title, labelled controls, help text, loads on mount, edits and saves via buttons', async t => {
  const b = backend()
  const h = section(t, b.ctx)
  let tree = h.render()
  assert.equal(b.calls.length, 0, 'render sends no request')
  assert.equal(textOf(nodes(tree, n => n.type === 'h2')[0]), 'Project kits (companion plugin)')
  for (const fn of h.effects.splice(0)) await fn()
  await new Promise(resolve => setImmediate(resolve))
  tree = h.render()
  const adopt = byId(tree, 'companion-enabled-on-adopt')
  const survey = byId(tree, 'companion-run-survey-on-new')
  const path = byId(tree, 'companion-cli-path')
  assert.equal(adopt.props.checked, true)
  assert.equal(survey.props.checked, false)
  assert.equal(path.props.value, '')
  for (const id of ['companion-enabled-on-adopt', 'companion-run-survey-on-new', 'companion-cli-path']) {
    const label = nodes(tree, n => n.type === 'label' && n.props.htmlFor === id)[0]
    assert.ok(label, `label for ${id}`)
    assert.ok(byId(tree, byId(tree, id).props['aria-describedby'].split(' ')[0]), `help for ${id}`)
  }
  assert.match(textOf(nodes(tree, n => n.type === 'label' && n.props.htmlFor === 'companion-enabled-on-adopt')[0]), /Use the companion plugin when adopting a project/)
  assert.match(textOf(nodes(tree, n => n.type === 'label' && n.props.htmlFor === 'companion-run-survey-on-new')[0]), /Run the companion's survey when a project is created/)
  assert.match(textOf(nodes(tree, n => n.type === 'label' && n.props.htmlFor === 'companion-cli-path')[0]), /Path to the componentize command \(optional\)/)
  assert.equal(button(tree, 'Save').props.disabled, true, 'Save disabled while clean')

  adopt.props.onChange({ target: { checked: false } })
  survey.props.onChange({ target: { checked: true } })
  path.props.onChange({ target: { value: TOOL_PATH } })
  tree = h.render()
  assert.equal(byId(tree, 'companion-enabled-on-adopt').props.checked, false)
  assert.equal(byId(tree, 'companion-cli-path').props.value, TOOL_PATH)
  assert.match(textOf(byId(tree, 'companion-prefs-status')), /Unsaved changes/)
  assert.equal(b.puts().length, 0)
  await button(tree, 'Save').props.onClick()
  tree = h.render()
  assert.deepEqual(b.puts()[0].options.body, { enabled_on_adopt: false, run_survey_on_new: true, cli_path_override: TOOL_PATH })
  assert.match(textOf(byId(tree, 'companion-prefs-status')), /Saved/)
  assert.equal(byId(tree, 'companion-prefs-status').props.role, 'status')
})

test('section: 400 error is linked to the path field; Revert restores', async t => {
  const b = backend({ putError: new Error('400: {"error":"cli_path_override must be a nonempty executable path or null"}') })
  const h = section(t, b.ctx)
  h.render()
  for (const fn of h.effects.splice(0)) await fn()
  await new Promise(resolve => setImmediate(resolve))
  byId(h.render(), 'companion-cli-path').props.onChange({ target: { value: 'x' } })
  await button(h.render(), 'Save').props.onClick()
  let tree = h.render()
  const errorNode = byId(tree, 'companion-prefs-error')
  assert.equal(textOf(errorNode), 'cli_path_override must be a nonempty executable path or null')
  assert.equal(errorNode.props.role, 'alert')
  assert.match(byId(tree, 'companion-cli-path').props['aria-describedby'], /companion-prefs-error/)
  assert.equal(byId(tree, 'companion-cli-path').props.value, 'x')
  button(tree, 'Revert').props.onClick()
  tree = h.render()
  assert.equal(byId(tree, 'companion-cli-path').props.value, '')
  assert.equal(byId(tree, 'companion-prefs-error'), undefined)
})

test('section: load failure shows a plain error, disables controls, Try again reloads', async t => {
  let fail = true
  const calls = []
  const ctx = { onDispose() {}, async rest(path, options) { calls.push({ path, options }); if (fail) throw new Error('offline'); return { ...DEFAULTS } } }
  const h = section(t, ctx)
  h.render()
  for (const fn of h.effects.splice(0)) await fn()
  await new Promise(resolve => setImmediate(resolve))
  let tree = h.render()
  assert.match(textOf(byId(tree, 'companion-prefs-load-error')), /could not be loaded/i)
  for (const id of ['companion-enabled-on-adopt', 'companion-run-survey-on-new', 'companion-cli-path']) assert.equal(byId(tree, id).props.disabled, true)
  assert.equal(button(tree, 'Save').props.disabled, true)
  fail = false
  await button(tree, 'Try again').props.onClick()
  tree = h.render()
  assert.equal(byId(tree, 'companion-prefs-load-error'), undefined)
  assert.equal(byId(tree, 'companion-enabled-on-adopt').props.disabled, false)
  assert.equal(calls.filter(c => c.options?.method === 'PUT').length, 0)
})

test('section: kits-missing line shows only when the page already knows kits are unavailable', t => {
  const b = backend()
  let tree = section(t, b.ctx, { kitsUnavailable: true }).render()
  assert.equal(textOf(byId(tree, 'companion-kits-missing')), 'Kits need the defuzz-componentize plugin.')
  tree = section(t, b.ctx, { kitsUnavailable: false }).render()
  assert.equal(byId(tree, 'companion-kits-missing'), undefined)
  assert.equal(b.calls.length, 0)
})

test('SettingsView mounts the companion section with the kits notice from state, without requests', t => {
  const slots = []; let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  const calls = []
  const model = ui.createWorkspaceModel({ onDispose() {}, async rest(...args) { calls.push(args) } })
  const rest = async () => ({})
  const state = { ...model.get(), catalog: { entries: [], suggested: [], notice: 'Kits need the defuzz-componentize plugin. Install it, then run `hermes defuzz kits`.' } }
  const tree = ui.SettingsView({ model, state, project: 'p', scopedRest: rest })
  const el = nodes(tree, n => n.type === ui.CompanionPrefsSection)[0]
  assert.ok(el)
  assert.equal(el.props.kitsUnavailable, true)
  assert.equal(el.props.rest, rest)
  const plain = ui.SettingsView({ model, state: model.get(), project: 'p' })
  assert.equal(nodes(plain, n => n.type === ui.CompanionPrefsSection)[0].props.kitsUnavailable, false)
  assert.equal(calls.length, 0)
  assert.equal(ui.ComponentizeSettingsView, undefined)
})

test('WorkspacePage passes its scoped rest to SettingsView', () => {
  const ctx = { onDispose() {}, async rest() { return {} } }
  const page = ui.WorkspacePage({ ctx, initialScreen: 'settings' })
  const view = nodes(page, n => n.type === ui.SettingsView)[0]
  assert.equal(typeof view.props.scopedRest, 'function')
  assert.equal(typeof view.props.scopedRest.check, 'function')
})

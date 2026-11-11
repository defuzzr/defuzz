import test from 'node:test'
import assert from 'node:assert/strict'
import * as ui from '../plugin.js'
import { host } from '@hermes/plugin-sdk'

const nodes = node => !node || typeof node !== 'object' ? [] : [node, ...[node.props?.children].flat().flatMap(nodes)]
const labeled = (tree, label) => nodes(tree).find(n => n.props?.['aria-label'] === label)
const byDomId = (tree, id) => nodes(tree).find(n => n.props?.id === id)
const button = (tree, label) => nodes(tree).find(n => n.type === 'Button' && [n.props.children].flat().join('') === label)

test('createLiveModel removes unreachable Componentize methods while keeping the Settings tool status', () => {
  const model = ui.createLiveModel({ onDispose() {}, async rest() { return {} } })
  assert.equal(model.loadComponentize, undefined)
  assert.equal(model.editComponentize, undefined)
  assert.equal(model.saveComponentize, undefined)
  assert.equal(typeof model.loadPro, 'function')
  assert.equal(typeof model.setup, 'function')
  assert.equal(typeof model.trustLock, 'function')
})

test('in-page navigation uses V10 top bar Settings and modal Start project without legacy nav or audit route', t => {
  const original = host.navigate, paths = []
  host.navigate = path => paths.push(path)
  t.after(() => { host.navigate = original })
  const tree = ui.WorkspacePage({ ctx: {} })
  assert.equal(labeled(tree, 'Project workspace'), undefined, 'legacy nav removed in V10')
  assert.equal(button(tree, 'Audit'), undefined, 'Audit nav removed in V10')
  byDomId(tree, 'settings-button').props.onClick()
  assert.equal(paths.at(-1), '/defuzz/settings')
  const settingsPage = ui.WorkspacePage({ ctx: {}, initialScreen: 'settings' })
  const settingsView = nodes(settingsPage).find(n => n.type === ui.SettingsView)
  const renderedSettings = settingsView.type(settingsView.props)
  byDomId(renderedSettings, 'back-button').props.onClick()
  assert.equal(paths.at(-1), '/defuzz')
})

test('busy workspace disables V10 lint bulk actions, save checks, and divider resize', t => {
  const model = ui.createWorkspaceModel({})
  const state = { ...model.get(), busy: true }
  const slots = []
  let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)

  const renderSettings = () => { cursor = 0; return ui.SettingsView({ model, state }) }
  byDomId(renderSettings(), 'lint-tab').props.onClick()
  const lintSettings = renderSettings()
  for (const label of ['Enable all', 'Clear', 'Save checks']) {
    assert.equal(button(lintSettings, label).props.disabled, true)
  }

  let first = true
  globalThis.__adoptTestUseState = init => {
    if (first) { first = false; return [state, () => {}] }
    return [typeof init === 'function' ? init() : init, () => {}]
  }
  const page = ui.WorkspacePage({ ctx: {} })
  const divider = byDomId(page, 'pane-divider')
  divider.props.onKeyDown({ key: 'ArrowLeft', preventDefault() {} })
  assert.equal(model.get().settings.split, undefined, 'busy workspace ignores divider keydown')
})

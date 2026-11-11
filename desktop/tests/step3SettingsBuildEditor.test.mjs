import test from 'node:test'
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'
import { SettingsView, createWorkspaceModel } from '../plugin.js'

const nodes = (node, predicate) => !node || typeof node !== 'object' ? [] : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
const byId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)[0]
const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const button = (tree, label) => nodes(tree, n => n.type === 'Button' && [n.props.children].flat().join('') === label)[0]

function harness(t, project) {
  const calls = [], slots = []
  let cursor = 0
  const model = createWorkspaceModel({ onDispose() {}, async rest(...args) { calls.push(args) } })
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  return { calls, model, render() { cursor = 0; return SettingsView({ model, state: model.get(), project }) } }
}

test('V10 settings header has Project settings, Auditor (7 scripts), Lint rules (12 tools), and ← Workspace without legacy * Settings MENU or [RETURN]', t => {
  const h = harness(t, 'invoice-tracker')
  const tree = h.render()
  assert.equal(ui.ComponentizeSettingsView, undefined)
  assert.equal(byId(tree, 'settings-menu-title'), undefined)
  assert.equal(byId(tree, 'project-build-editor'), undefined)
  assert.equal(byDomId(tree, 'settings').props['data-project-name'], 'invoice-tracker')
  assert.match(JSON.stringify(byDomId(tree, 'auditor-tab')), /Auditor.*7 scripts/)
  assert.match(JSON.stringify(byDomId(tree, 'lint-tab')), /Lint rules.*12 tools/)

  const previous = host.navigate
  let destination
  host.navigate = path => { destination = path }
  t.after(() => { host.navigate = previous })
  const back = byDomId(tree, 'back-button')
  assert.equal(back.props.children, '← Workspace')
  back.props.onClick()
  assert.equal(destination, '/defuzz')
  assert.equal(h.calls.length, 0)
})

test('V10 Lint rules tab switches languages, toggles tool checkboxes, and preserves other language rules', t => {
  const h = harness(t, '/copy')
  byDomId(h.render(), 'lint-tab').props.onClick()
  let tree = h.render()
  assert.ok(byDomId(tree, 'lint-panel'))

  const before = structuredClone(h.model.get().settings.rules)
  const shellcheck = before.find(rule => rule.id === 'shellcheck')
  assert.ok(shellcheck)

  button(tree, 'Python').props.onClick()
  tree = h.render()
  const checkboxes = nodes(byDomId(tree, 'lint-panel'), n => n.type === 'input' && n.props.type === 'checkbox')
  assert.equal(checkboxes[0].props['aria-label'], 'Enable Ruff')
  checkboxes[0].props.onChange({ target: { checked: false } })
  assert.equal(h.model.get().settings.rules.find(r => r.id === 'ruff').enabled, false)
  assert.deepEqual(h.model.get().settings.rules.find(r => r.id === 'shellcheck'), shellcheck)
  assert.equal(h.calls.length, 0)
})

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { host } from '@hermes/plugin-sdk'
import { WorkspacePage } from '../plugin.js'

const nodes = node => !node || typeof node !== 'object' ? [] : [node, ...[node.props?.children].flat().flatMap(nodes)]
const labeled = (tree, label) => nodes(tree).find(n => n.props?.['aria-label'] === label)
const identified = (tree, id) => nodes(tree).find(n => n.props?.['data-testid'] === id)
const byDomId = (tree, id) => nodes(tree).find(n => n.props?.id === id)
const button = (tree, label) => nodes(tree).find(n => n.type === 'Button' && [n.props.children].flat().join('') === label)
function harness(t, ctx = {}) {
  const slots = []; let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  return () => { cursor = 0; return WorkspacePage({ ctx }) }
}

test('V10 workspace replaces embedded kernel popup with direct file viewer and disables divider resize while busy', async t => {
  let finish
  const render = harness(t, { rest: () => new Promise(resolve => { finish = resolve }) })
  assert.equal(identified(render(), 'embedded-kernel-popup'), undefined)
  assert.equal(byDomId(render(), 'pane-divider').props['aria-valuenow'], 58)
  const pending = button(render(), 'Refresh projects').props.onClick()
  byDomId(render(), 'pane-divider').props.onKeyDown({ key: 'ArrowLeft', preventDefault() {} })
  assert.equal(byDomId(render(), 'pane-divider').props['aria-valuenow'], 58, 'busy workspace disables divider resize')
  finish({ projects: [{ name: 'Copy', path: '/copy', registered: true, locked_hashes: { 'AGENTS.md': 'h1' } }] }); await pending
  nodes(render()).find(n => n.props?.['data-project'] === 'Copy').props.onClick()
  const preview = nodes(byDomId(render(), 'tree')).find(n => n.props?.['data-path'] === 'AGENTS.md').props.onClick()
  finish({ content: '# Preview in V10 viewer' }); await preview
  assert.match(JSON.stringify(byDomId(render(), 'editor')), /Preview in V10 viewer/)
})

test('V10 workspace uses theme colors without forbidden globals, diff colors, or rgba literals', () => {
  const source = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')
  assert.doesNotMatch(source.replace(/const\s+MODAL_SCRIM\s*=\s*\{[^}]*\}/g, ''), /window\.|document\.|localStorage|__HERMES_PLUGIN_SDK__|fetchJSON|rgba\(/i)
  const page = source.slice(source.indexOf('export function WorkspacePage'), source.indexOf('export const WORKSPACE_SCREENS'))
  assert.doesNotMatch(page, /['"](?:red|green|lime|crimson|#(?:f00|0f0|ff0000|00ff00|008000|dc2626|ef4444|22c55e|16a34a))['"]/i)
  assert.match(page, /var\(--ui-accent\)/)
  assert.match(page, /var\(--ui-stroke-secondary\)/)
})

test('V10 workspace has 7px draggable/keyboard divider defaulting to 58% and adjusts only on user input', t => {
  const render = harness(t)
  const workspace = identified(render(), 'project-workspace-box')
  assert.ok(workspace)
  assert.equal(workspace.props['data-color-scheme'], 'no-red-green')
  const divider = byDomId(workspace, 'pane-divider')
  assert.equal(divider?.props.role, 'separator')
  assert.equal(divider?.props['aria-valuenow'], 58)
  const grid = nodes(workspace).find(n => n.props?.className === 'columns')
  assert.equal(grid.props.style.gridTemplateColumns, 'minmax(0, 58%) 7px minmax(0, 1fr)')
  const mockTarget = { parentElement: { getBoundingClientRect: () => ({ width: 1000 }) } }
  divider.props.onPointerDown({ button: 0, pointerId: 1, clientX: 500, currentTarget: mockTarget, preventDefault() {} })
  byDomId(render(), 'pane-divider').props.onPointerMove({ pointerId: 1, clientX: 370, currentTarget: mockTarget })
  byDomId(render(), 'pane-divider').props.onPointerUp({ pointerId: 1, currentTarget: mockTarget })
  assert.equal(byDomId(render(), 'pane-divider').props['aria-valuenow'], 45)
  assert.equal(nodes(render()).find(n => n.props?.className === 'columns').props.style.gridTemplateColumns, 'minmax(0, 45%) 7px minmax(0, 1fr)')
})

test('V10 top bar has locked banner, Start project modal trigger, Settings button, and no legacy station banner or nav bar', t => {
  const original = host.navigate, routes = []
  host.navigate = route => routes.push(route)
  t.after(() => { host.navigate = original })
  for (const screen of ['main', 'settings', 'adopt']) {
    const tree = WorkspacePage({ ctx: {}, initialScreen: screen })
    assert.equal(identified(tree, 'defuzz-station-banner'), undefined)
    assert.ok(identified(tree, 'v10-locked-banner'))
    assert.ok(byDomId(tree, 'start-project'))
    const settingsBtn = byDomId(tree, 'settings-button')
    assert.ok(settingsBtn)
    settingsBtn.props.onClick()
    assert.equal(routes.at(-1), screen === 'settings' ? '/defuzz' : '/defuzz/settings')
    assert.equal(labeled(tree, 'Project workspace'), undefined)
    assert.equal(button(tree, 'Audit'), undefined)
  }
})

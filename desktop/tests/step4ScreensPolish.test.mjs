import test from 'node:test'
import assert from 'node:assert/strict'
import * as ui from '../plugin.js'

const nodes = node => !node || typeof node !== 'object' ? [] : [node, ...[node.props?.children].flat().flatMap(nodes)]
const byId = (tree, id) => nodes(tree).find(n => n.props?.['data-testid'] === id)
const fixture = () => {
  const calls = []
  return { calls, ctx: { onDispose() {}, rest(...args) {
    calls.push(args)
    if (String(args[0]).startsWith('/scaffold/projects-root')) {
      return { path: '/home/user/Tools', source: 'setting', valid: true, default_path: '/home/user/Tools', message: '' }
    }
    throw new Error('Unexpected render request')
  } } }
}

test('Start project modal uses non-diff theme styling without render requests and without inline workspace accept buttons', t => {
  const { ctx, calls } = fixture()
  const slots = []; let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  const render = () => { cursor = 0; return ui.WorkspacePage({ ctx }) }
  assert.equal(ui.StartProjectView, undefined)
  const mainTree = render()
  assert.equal(nodes(mainTree).some(n => n.type === 'Button' && /Check & accept|Decline & discard|Accept & create/.test([n.props?.children].flat().join(''))), false)
  nodes(mainTree).find(n => n.props?.id === 'start-project').props.onClick()
  const modalTree = render()
  assert.ok(byId(modalTree, 'new-project-modal'))
  assert.deepEqual(calls.map(c => c[0]), ['/scaffold/projects-root'])
})

test('Settings tools cards preserve installed evidence without AuditPaneView', () => {
  const { ctx, calls } = fixture(), model = ui.createLiveModel(ctx)
  const items = [{ name: 'ruff', expected_version: '1', installed_version: null, executable_path: null, status: 'missing' }]
  const tree = ui.ComputerToolsSection({ model, state: { ...model.get(), tools: { items } }, project: '', projectState: [] })
  assert.equal(byId(tree, 'settings-computer-tools')?.props['data-color-scheme'], 'no-red-green')
  const outputs = nodes(tree).filter(n => typeof n.props?.children === 'string' && n.props.children.includes('installed_version'))
  assert.deepEqual(JSON.parse(outputs.at(-1).props.children), items)
  assert.equal(ui.AuditPaneView, undefined)
  assert.equal(nodes(tree).filter(n => n.type === 'section' && n.props.style?.borderLeft).length, 6)
  assert.deepEqual(calls, [])
})

test('adopt inspector has a station accent without loading on render', () => {
  const { ctx, calls } = fixture()
  const tree = ui.AdoptBeforeAfterPage({ ctx })
  const page = byId(tree, 'adopt-inspector-page')
  assert.equal(page?.props['data-color-scheme'], 'no-red-green')
  assert.ok(page.props.children[0].props.style.borderLeft)
  assert.deepEqual(calls, [])
})

test('screen-owned color literals use var(--ui-*) tokens outside the git diff palette', () => {
  for (const view of [ui.WorkspacePage, ui.SettingsView, ui.ComputerToolsSection, ui.AdoptBeforeAfterPage]) {
    // Modal dimming lives in the shared MODAL_SCRIM, outside these views.
    const source = view.toString()
    assert.doesNotMatch(source, /(?:color|background|border\w*):\s*['"](?:red|green|#[0-9a-f]+|rgba?\([^)]*\)|[^'"]*var\(--[^)]*(?:red|green|success|danger))/i)
  }
})

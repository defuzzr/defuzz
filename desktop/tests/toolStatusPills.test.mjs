import test from 'node:test'
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import { ComputerToolsSection } from '../plugin.js'

const nodes = (node, predicate = () => true) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
const byTestId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)[0]
const allTestId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)
const textOf = node =>
  !node ? '' : typeof node === 'string' || typeof node === 'number'
    ? String(node)
    : [node.props?.children].flat().map(textOf).join('')

function mount(t, state, model = {}) {
  const slots = []
  let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => { delete globalThis.__adoptTestUseState })
  return {
    render(extra = {}) {
      cursor = 0
      return ComputerToolsSection({ model, state: { ...state, ...extra }, project: '/p', projectState: {} })
    }
  }
}

const state = {
  busy: false,
  proLoaded: true,
  error: '',
  resourceErrors: {},
  tools: {
    items: [
      { name: 'ruff', expected_version: '0.15.22', installed_version: '0.15.24', executable_path: '/usr/local/bin/ruff', status: 'installed' },
      { name: 'shellcheck', expected_version: '0.11.0', installed_version: null, executable_path: null, status: 'missing', error: 'not on PATH' }
    ],
    plan: { steps: [{ tool: 'ruff', download: 'ruff-0.15.24' }], total_bytes: 12_345 },
    lazy_installs_allowed: true
  },
  setup: null
}

function primeRefs(tree) {
  for (const pill of allTestId(tree, 'tool-pill')) {
    const fake = { focusCalls: 0, focus() { this.focusCalls += 1 } }
    pill.props.ref?.(fake)
    pill.__ref = fake
  }
}

test('tool pills show names only in an auto-fit grid and hide the raw /tools/status JSON', t => {
  const ui = mount(t, state)
  const tree = ui.render()

  const grid = byTestId(tree, 'tool-status-grid')
  assert.ok(grid, 'pill grid exists')
  assert.equal(grid.props.style.display, 'grid')
  assert.match(grid.props.style.gridTemplateColumns, /auto-fit/)
  assert.match(grid.props.style.gridTemplateColumns, /minmax\(150px, 1fr\)/, 'cells fill the available width side by side')

  const pills = allTestId(tree, 'tool-pill')
  assert.deepEqual(pills.map(p => p.props['data-tool']), ['ruff', 'shellcheck'])
  assert.deepEqual(pills.map(textOf), ['ruff', 'shellcheck'], 'pill text is the tool name only')

  const sectionText = textOf(tree)
  assert.doesNotMatch(sectionText, /"items"\s*:/, 'raw tools payload is not expanded')
  assert.doesNotMatch(sectionText, /installed_version/, 'no expanded installed-version JSON')
  assert.equal((sectionText.match(/shellcheck/g) || []).length, 1, 'the name appears once, not in a duplicate dump')

  const plan = byTestId(tree, 'tool-setup-plan')
  assert.ok(plan, 'setup plan is still reachable')
  assert.equal(plan.type, 'details')
  assert.equal(plan.props.open, undefined, 'plan stays explicitly collapsed')
  assert.match(textOf(plan), /Setup plan and total size/)
})

test('opening a pill shows a compact popup above it with versions, path, status and error', t => {
  const ui = mount(t, state)
  let tree = ui.render()
  primeRefs(tree)

  allTestId(tree, 'tool-pill')[1].props.onClick()
  tree = ui.render()

  const popups = allTestId(tree, 'tool-status-popup')
  assert.equal(popups.length, 1, 'one popup at a time')
  const popup = popups[0]
  assert.equal(popup.props['data-tool'], 'shellcheck')
  assert.equal(popup.props.role, 'dialog')
  const popupText = textOf(popup)
  assert.match(popupText, /Expected version: 0\.11\.0/)
  assert.match(popupText, /Installed version: unknown/)
  assert.match(popupText, /Executable: unknown/)
  assert.match(popupText, /Status: missing/)
  assert.match(popupText, /Error: not on PATH/)

  assert.equal(popup.props.style.position, 'absolute')
  assert.equal(popup.props.style.bottom, 'calc(100% + 6px)')
  assert.equal(popup.props.style.top, undefined, 'popup opens above the pill')
  assert.equal(popup.props.style.background, 'var(--ui-bg-elevated, #1f2428)', 'opaque raised surface')

  const cell = popup.props && nodes(tree, n => Array.isArray(n.props?.children) && n.props.children.includes(popup))[0]
  assert.equal(cell.props.style.position, 'relative', 'popup is anchored to its own pill cell')

  allTestId(tree, 'tool-pill')[0].props.onClick()
  tree = ui.render()
  const switched = allTestId(tree, 'tool-status-popup')
  assert.equal(switched.length, 1)
  assert.equal(switched[0].props['data-tool'], 'ruff', 'opening another pill closes the first')
})

test('explicit X and Escape close the popup and restore focus to the pill; no request is made', t => {
  const calls = []
  const model = { loadPro: () => calls.push('loadPro'), setup: () => calls.push('setup') }
  const ui = mount(t, state, model)
  let tree = ui.render()
  primeRefs(tree)
  const ruff = allTestId(tree, 'tool-pill')[0]

  ruff.props.onClick()
  tree = ui.render()
  primeRefs(tree)
  const opener = allTestId(tree, 'tool-pill')[0]
  const close = byTestId(tree, 'close-tool-status')
  assert.ok(close, 'popup has an explicit X close control')
  assert.match(close.props['aria-label'], /Close tool status ruff/)
  close.props.onClick()
  tree = ui.render()
  assert.equal(allTestId(tree, 'tool-status-popup').length, 0, 'X closes the popup')
  assert.equal(opener.__ref.focusCalls, 1, 'focus returns to the opener')

  primeRefs(tree)
  allTestId(tree, 'tool-pill')[0].props.onClick()
  tree = ui.render()
  primeRefs(tree)
  const focusedOpener = allTestId(tree, 'tool-pill')[0]
  const cell = nodes(tree, n => n.props?.onKeyDown && n.props?.style?.position === 'relative')[0]
  cell.props.onKeyDown({ key: 'Escape', preventDefault() {} })
  tree = ui.render()
  assert.equal(allTestId(tree, 'tool-status-popup').length, 0, 'Escape closes the popup')
  assert.equal(focusedOpener.__ref.focusCalls, 1, 'Escape returns focus to the opener')

  assert.deepEqual(calls, [], 'interacting with pills never installs or runs anything')
})

test('no tool rows is stated plainly, not as an empty success', t => {
  const ui = mount(t, { ...state, tools: { items: [], plan: null } })
  const tree = ui.render()
  assert.equal(allTestId(tree, 'tool-pill').length, 0)
  assert.match(textOf(tree), /No tool rows returned; absence is not a pass\./)
})

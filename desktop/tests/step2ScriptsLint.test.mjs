import test from 'node:test'
import assert from 'node:assert/strict'
import * as ui from '../plugin.js'
import { host } from '@hermes/plugin-sdk'

const nodes = node => !node || typeof node !== 'object' ? [] : [node, ...[node.props?.children].flat().flatMap(nodes)]
const id = (tree, name) => nodes(tree).find(n => n.props?.['data-testid'] === name)
const byDomId = (tree, name) => nodes(tree).find(n => n.props?.id === name)
const button = (tree, label) => nodes(tree).find(n => n.type === 'Button' && [n.props.children].flat().join('') === label)

function mountPage(t, replies = []) {
  const slots = [], calls = [], disposals = []
  let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => { delete globalThis.__adoptTestUseState })
  const ctx = {
    onDispose(fn) { disposals.push(fn) },
    async rest(url, opts) {
      calls.push({ url, opts })
      const reply = replies.shift()
      if (reply instanceof Error) throw reply
      return typeof reply === 'function' ? reply() : (reply ?? {})
    }
  }
  return {
    calls,
    ctx,
    dispose() { disposals.forEach(fn => fn()) },
    render() { cursor = 0; return ui.WorkspacePage({ ctx }) }
  }
}

test('StationScriptsSection is removed and V10 footer LINT ▶ / CHECKS ▶ replace legacy * SCRIPTS', async t => {
  assert.equal(ui.StationScriptsSection, undefined)
  const h = mountPage(t, [
    { coverage: 'verified', projects: [{ name: 'Copy', path: '/copy', registered: true }] },
    { state: 'running', job_id: 'a/b' },
    { state: 'done', result: { ok: true, findings: [] } },
    { items: [{ name: 'ruff', version: '0.9' }] },
    { lock: '/copy/TOOLS.lock', rows: [] }
  ])
  let tree = h.render()
  assert.equal(JSON.stringify(tree).includes('* SCRIPTS'), false)
  assert.equal(id(tree, 'footer-lint-play').props.disabled, true, 'LINT ▶ disabled before selecting project')

  await button(tree, 'Refresh projects').props.onClick()
  nodes(h.render()).find(n => n.props?.['data-project'] === 'Copy').props.onClick()
  tree = h.render()
  assert.equal(id(tree, 'footer-lint-play').props.disabled, false)

  await id(tree, 'footer-lint-play').props.onClick()
  assert.deepEqual(h.calls[1], { url: '/lint', opts: { method: 'POST', body: { project: '/copy', mode: 'both' } } })
  await id(h.render(), 'footer-lint-play').props.onClick()
  assert.equal(h.calls[2].url, '/lint/a%2Fb')

  await id(h.render(), 'footer-checks-play').props.onClick()
  assert.equal(h.calls[3].url, '/tools/status')
  assert.equal(h.calls[4].url, '/tools-lock?project=%2Fcopy')
})

test('connection or profile switch before footer LINT ▶ or CHECKS ▶ fails closed', async t => {
  const originalConnection = host.activeConnectionId, originalState = host.state
  let connection = 'one', profile = 'one'
  host.activeConnectionId = () => connection
  host.state = { profile: { get: () => profile } }
  t.after(() => { host.activeConnectionId = originalConnection; host.state = originalState })

  const h = mountPage(t, [{ coverage: 'verified', projects: [{ name: 'Copy', path: '/copy', registered: true }] }])
  await button(h.render(), 'Refresh projects').props.onClick()
  nodes(h.render()).find(n => n.props?.['data-project'] === 'Copy').props.onClick()

  connection = 'two'
  await id(h.render(), 'footer-lint-play').props.onClick()
  assert.equal(h.calls.length, 1, 'no /lint call after connection change')
  assert.match(byDomId(h.render(), 'status').props.children, /Connection or profile changed/)

  connection = 'one'
  profile = 'two'
  await id(h.render(), 'footer-checks-play').props.onClick()
  assert.equal(h.calls.length, 1, 'no /tools/status call after profile change')
})

test('manual lint has themed non-diff card styling', () => {
  const tree = ui.ManualLintSection({ ctx: {}, project: '/copy' })
  assert.equal(tree.props['data-color-scheme'], 'no-red-green')
  assert.match(tree.props.style.border, /var\(--ui-stroke-secondary\)/)
})

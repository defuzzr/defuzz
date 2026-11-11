import test from 'node:test'
import assert from 'node:assert/strict'
import { WorkspacePage } from '../plugin.js'

const nodes = (node, predicate) => !node || typeof node !== 'object' ? [] : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
const byId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)[0]
const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const textOf = node => !node ? '' : typeof node === 'string' || typeof node === 'number' ? String(node) : [node.props?.children].flat().map(textOf).join('')

const REPORT = { coverage: 'verified', findings: [{ id: 'raw-finding-id' }], proposals: [] }
const SUMMARY_TEXT = 'Defuzz audit summary\nFindings: 0 warnings.\nIt is fine to stop here and come back to this later.\n'

// Routes REST by path; `summary` may be a value, an Error, or a function returning a promise.
function fixture(summaryFor) {
  const calls = []
  let runs = 0
  const ctx = { onDispose() {}, async rest(path, opts) {
    calls.push({ path, opts })
    if (path === '/audit/scope') return { scope_disclosure: 'Server scope' }
    if (path === '/audit/start') { runs += 1; return { run_id: `run-${runs}`, status: 'completed' } }
    const runId = decodeURIComponent(path.split('run_id=')[1] || '')
    if (path.startsWith('/audit/status')) return { run_id: runId, status: 'completed' }
    if (path.startsWith('/audit/report')) return { ...REPORT, run: runId }
    if (path.startsWith('/audit/summary')) {
      const reply = summaryFor(runId)
      if (reply instanceof Error) throw reply
      return typeof reply === 'function' ? reply() : reply
    }
    return {}
  } }
  return { ctx, calls }
}

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

async function runAudit(render) {
  await byDomId(render(), 'audit-full-button').props.onClick()
  byDomId(byDomId(render(), 'audit-review-dialog'), 'audit-review-consent').props.onChange({ target: { checked: true } })
  return byDomId(render(), 'audit-review-run').props.onClick()
}

test('completed audit shows the plain summary above, raw JSON behind a toggle', async t => {
  const h = fixture(runId => ({ run_id: runId, status: 'completed', text: SUMMARY_TEXT, summary: {} }))
  const render = renderHarness(t, WorkspacePage, { ctx: h.ctx })
  await runAudit(render)
  assert.ok(h.calls.some(c => c.path === '/audit/summary?run_id=run-1'))
  let footer = byId(render(), 'footer-audit-output')
  assert.equal(textOf(byId(footer, 'audit-summary')), SUMMARY_TEXT)
  assert.equal(byId(footer, 'audit-summary').type, 'pre')
  assert.doesNotMatch(textOf(footer), /raw-finding-id/)
  const toggle = byId(footer, 'audit-summary-toggle')
  assert.equal(textOf(toggle), 'Show raw report')

  toggle.props.onClick()
  footer = byId(render(), 'footer-audit-output')
  assert.equal(byId(footer, 'audit-summary'), undefined)
  assert.match(textOf(footer), /raw-finding-id/)
  assert.equal(textOf(byId(footer, 'audit-summary-toggle')), 'Show summary')

  byId(footer, 'audit-summary-toggle').props.onClick()
  footer = byId(render(), 'footer-audit-output')
  assert.equal(textOf(byId(footer, 'audit-summary')), SUMMARY_TEXT)
})

test('failing /audit/summary keeps the JSON view and adds no error', async t => {
  const h = fixture(() => new Error('SUMMARY OFFLINE'))
  const render = renderHarness(t, WorkspacePage, { ctx: h.ctx })
  await runAudit(render)
  const tree = render()
  const footer = byId(tree, 'footer-audit-output')
  assert.match(textOf(footer), /raw-finding-id/)
  assert.equal(byId(footer, 'audit-summary'), undefined)
  assert.equal(byId(footer, 'audit-summary-toggle'), undefined)
  assert.equal(byId(footer, 'footer-audit-error'), undefined)
  assert.doesNotMatch(JSON.stringify(tree), /SUMMARY OFFLINE/)
  assert.match(textOf(byId(tree, 'audit-status-notice')), /^Full audit finished\.$/)
})

test('a stale run\'s late summary is ignored', async t => {
  let releaseFirst
  const first = new Promise(resolve => { releaseFirst = resolve })
  const h = fixture(runId => runId === 'run-1' ? () => first : { text: 'Summary for run two\n' })
  const render = renderHarness(t, WorkspacePage, { ctx: h.ctx })
  const pending = runAudit(render)
  await new Promise(resolve => setTimeout(resolve, 0))
  assert.ok(h.calls.some(c => c.path === '/audit/summary?run_id=run-1'))
  await runAudit(render)
  releaseFirst({ text: 'STALE SUMMARY FOR RUN ONE\n' })
  await pending
  const footer = byId(render(), 'footer-audit-output')
  assert.equal(textOf(byId(footer, 'audit-summary')), 'Summary for run two\n')
  assert.doesNotMatch(JSON.stringify(render()), /STALE SUMMARY/)
})

test('summary text is rendered as plain text children', async t => {
  const hostile = '<script>alert(1)</script> & <b>bold</b>\n'
  const h = fixture(() => ({ text: hostile }))
  const render = renderHarness(t, WorkspacePage, { ctx: h.ctx })
  await runAudit(render)
  const pre = byId(render(), 'audit-summary')
  assert.equal(pre.props.children, hostile)
  assert.equal(pre.props.dangerouslySetInnerHTML, undefined)
  assert.equal(nodes(pre, n => n.type === 'script').length, 0)
})

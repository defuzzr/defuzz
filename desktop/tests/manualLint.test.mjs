import test from 'node:test'
import assert from 'node:assert/strict'
import plugin, * as ui from '../plugin.js'

function nodes(node, predicate) {
  if (!node || typeof node !== 'object') return []
  return [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(n => nodes(n, predicate))]
}
function harness(t, replies) {
  const slots = []
  let cursor = 0
  const calls = []
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  const ctx = { rest: async (url, opts) => {
    calls.push({ url, opts })
    const reply = replies.shift()
    if (reply instanceof Error) throw reply
    return typeof reply === 'function' ? reply() : reply
  } }
  t.after(() => { delete globalThis.__adoptTestUseState })
  return { calls, ctx, render(project = '/chosen copy', mode = 'both') { cursor = 0; return ui.ManualLintSection({ ctx, project, mode }) } }
}
test('manual lint displays generated-lock skips in its JSON report', async t => {
  const report = { ok: true, findings: [], skipped_generated: ['nested/pnpm-lock.yaml', 'Cargo.lock'] }
  const h = harness(t, [{ state: 'done', result: report }])
  await button(h.render()).props.onClick()
  const rendered = JSON.parse(nodes(h.render(), n => n.type === 'pre')[0].props.children)
  assert.deepEqual(rendered.result.skipped_generated, report.skipped_generated)
})

const button = tree => nodes(tree, n => n.type === 'Button')[0]

test('late saved lint mode updates the run unless the user explicitly selects a mode', async t => {
  const h = harness(t, [{ state: 'done' }, { state: 'done' }])
  const select = tree => nodes(tree, n => n.type === 'select')[0]
  assert.equal(select(h.render()).props.value, 'both')

  // The same mounted project receives its asynchronously loaded preference.
  const loaded = h.render('/chosen copy', 'post')
  assert.equal(h.calls.length, 0, 'loading preferences must not run lint')
  assert.equal(select(loaded).props.value, 'post')
  await button(loaded).props.onClick()
  assert.equal(h.calls[0].opts.body.mode, 'post')

  select(h.render('/chosen copy', 'post')).props.onChange({ target: { value: 'pre' } })
  assert.equal(select(h.render('/chosen copy', 'post')).props.value, 'pre')
  const refreshed = h.render('/chosen copy', 'both')
  assert.equal(select(refreshed).props.value, 'pre', 'preference refresh must preserve explicit choice')
  await button(refreshed).props.onClick()
  assert.equal(h.calls[1].opts.body.mode, 'pre')
})

test('running jobs are checked explicitly, never restarted, and rapid clicks are deduplicated', async t => {
  let finish
  const h = harness(t, [() => new Promise(resolve => { finish = resolve }), { state: 'running', job_id: 'a/b' }, { state: 'done', result: { ok: true, findings: [] } }])
  const click = button(h.render()).props.onClick
  const pending = click()
  await click()
  assert.equal(h.calls.length, 1)
  assert.equal(button(h.render()).props.disabled, true)
  finish({ state: 'running', job_id: 'a/b' })
  await pending
  assert.equal(button(h.render()).props.children, 'Check lint status')
  assert.equal(h.calls.length, 1, 'render does not poll')
  await button(h.render()).props.onClick()
  await button(h.render()).props.onClick()
  assert.deepEqual(h.calls.slice(1).map(c => c.url), ['/lint/a%2Fb', '/lint/a%2Fb'])
  assert.equal(button(h.render()).props.children, 'Run lint')
  assert.match(nodes(h.render(), n => n.type === 'pre')[0].props.children, /"ok": true/)
})

test('registered page wires lint to the granted folder, not report metadata', async t => {
  const h = harness(t, [{ lock: null }])
  const entries = []
  let pageState
  globalThis.__adoptTestUseState = init => {
    pageState ??= init
    return [pageState, next => { pageState = typeof next === 'function' ? next(pageState) : next }]
  }
  h.ctx.register = entry => entries.push(entry)
  h.ctx.files = {
    requestFolder: async () => ({ ok: true, folder: { id: 'grant', name: 'Copy', path: '/chosen copy' } }),
    readText: async (_, path) => path === '.adopt/report.json'
      ? { ok: true, text: JSON.stringify({ copy_root: '/untrusted metadata' }) }
      : { ok: false, error: 'not-found' }
  }
  plugin.register(h.ctx)
  assert.equal(entries.find(e => e.id === 'page').render().type, ui.WorkspacePage)
  const page = { type: ui.AdoptBeforeAfterPage, props: { ctx: h.ctx } }
  await nodes(page.type(page.props), n => n.type === 'Button')[0].props.onClick()
  const lint = nodes(page.type(page.props), n => n.type === ui.ManualLintSection)[0]
  assert.ok(lint, 'registered page must include manual lint section')
  assert.equal(lint.props.project, '/chosen copy')
  assert.equal(lint.key, '/chosen copy', 'project switch remounts job/result state')
  assert.equal(h.calls.filter(c => c.url.endsWith('/lint')).length, 0)
})

test('missing project disables execution and setup/drift errors remain visible without retries', async t => {
  const h = harness(t, [new Error('409 setup_pending'), new Error('409 tools_drift')])
  assert.equal(button(h.render('')).props.disabled, true)
  await button(h.render('')).props.onClick()
  assert.equal(h.calls.length, 0)
  await button(h.render()).props.onClick()
  assert.match(nodes(h.render(), n => n.props?.role === 'status')[0].props.children, /setup_pending/)
  assert.equal(button(h.render()).props.disabled, false)
  await button(h.render()).props.onClick()
  assert.match(nodes(h.render(), n => n.props?.role === 'status')[0].props.children, /tools_drift/)
  assert.equal(h.calls.length, 2)
})

test('status transport errors preserve the job and failed jobs display their error', async t => {
  const h = harness(t, [{ state: 'running', job_id: 'job' }, new Error('offline'), { state: 'failed', error: 'lint crashed' }])
  await button(h.render()).props.onClick()
  await button(h.render()).props.onClick()
  assert.equal(button(h.render()).props.children, 'Check lint status')
  assert.match(nodes(h.render(), n => n.props?.role === 'status')[0].props.children, /offline/)
  await button(h.render()).props.onClick()
  assert.match(nodes(h.render(), n => n.type === 'pre')[0].props.children, /lint crashed/)
  assert.equal(h.calls.filter(c => c.opts?.method === 'POST').length, 1)
  assert.equal(button(h.render()).props.children, 'Run lint')
})

test('manual lint renders without requests, clicks once, and displays findings', async t => {
  assert.equal(typeof ui.ManualLintSection, 'function', 'manual lint UI must exist')
  const report = { ok: false, findings: [{ file: 'src/a.py', line: 2, message: '<unsafe>' }] }
  const h = harness(t, [report])
  const tree = h.render()
  assert.equal(h.calls.length, 0)
  assert.equal(button(tree).props.children, 'Run lint')
  await button(tree).props.onClick()
  assert.deepEqual(h.calls, [{ url: '/lint', opts: {
    method: 'POST', body: { project: '/chosen copy', mode: 'both' }
  } }])
  assert.match(nodes(h.render(), n => n.type === 'pre')[0].props.children, /src\/a.py/)
  assert.match(nodes(h.render(), n => n.type === 'pre')[0].props.children, /<unsafe>/)
})

// The poll answers exactly as the real routes send them (tests/test_startpoll_contract_roundtrip.py
// asserts these shapes against the real server): a failed check and a failure after the move are
// 409 with the route's whole detail object, never a 500 with a reduced one.
import test from 'node:test'
import assert from 'node:assert/strict'
import * as ui from '../plugin.js'
import { byDomId, matchReply, mountHarness, nodes, pick, textOf, tick } from './dialogHarness.mjs'

const NAME = 'my-tool'
const PID = 'p1'
const POLL = `/scaffold/accept/${PID}`
const PATH = `/srv/projects/${NAME}`
const STEP = "Running the project's first check"
const running = { status: 'running', proposal_id: PID, step: STEP, elapsed_s: 21 }
const started = { ...running, poll: POLL }
const checkFailed = { error: 'Check command python -m pytest failed with exit code 1 in my-tool', output: 'E   assert 1 == 2',
  keep_staging: true, created_dirs: [], accepted_repos: [] }
const afterMove = { error: `Could not save the new project in the project list. The project folder ${PATH} was created and kept. Look at it, and delete it if you do not want it, before you try again.`,
  output: '', keep_staging: false, created_dirs: [PATH], accepted_repos: [] }
const httpError = (status, detail) => Object.assign(new Error(`${status}: ${JSON.stringify({ detail })}`), { body: { detail } })

function server ({ first = started, polls = [running] } = {}) {
  let poll = 0
  const answer = value => typeof value === 'function' ? value() : value
  return async (path, opts) => {
    if (path === '/scaffold/match') return matchReply()
    if (path === '/scaffold/propose') return { proposal_id: PID, template_id: opts.body.template_id, tree: [{ name: opts.body.name, dest: PATH, files: ['AGENTS.md'] }] }
    if (path === '/scaffold/accept') return answer(first)
    if (path === POLL) return answer(polls[Math.min(poll++, polls.length - 1)])
    if (path === '/workspace/projects') return { coverage: 'verified', projects: [] }
    if (path === '/scaffold/discard') return { status: 'discarded' }
    return {}
  }
}

const settle = async () => { for (let i = 0; i < 8; i++) await tick() }
const poll = async (h, n = 1) => { for (let i = 0; i < n; i++) { await h.fireTimers(e => e.ms === ui.SCAFFOLD_POLL_INTERVAL_MS); await settle() } }
const alerts = tree => nodes(tree, n => n.props?.role === 'alert').map(textOf)
const callsTo = (h, path) => h.calls.filter(c => c.path === path)

async function finish (t, srv, polls = 2) {
  const h = mountHarness(t, srv)
  await h.open()
  await byDomId(h.modal(), 'new-project-name').props.onChange({ target: { value: NAME } })
  const modal = await pick(h, 'template:python-golden')
  const pending = byDomId(modal, 'accept-project').props.onClick()
  await settle()
  await poll(h, polls)
  await pending
  const shown = h.modal()
  return { h, view: { alerts: alerts(shown), what: textOf(nodes(shown, n => n.props?.['aria-label'] === 'What happened')[0]), create: byDomId(shown, 'accept-project').props.disabled } }
}

test('real shapes: a failed check (409, whole detail) reads like the same failed POST, and Create works again', async t => {
  const fresh = await finish(t, server({ polls: [running, { status: 'failed', proposal_id: PID, http_status: 409, detail: checkFailed, partial: false }] }))
  const old = await finish(t, server({ first: () => { throw httpError(409, checkFailed) } }), 0)
  assert.deepEqual(fresh.view, old.view)
  assert.equal(fresh.view.create, false, 'nothing was created: Create is allowed again')
  assert.equal(callsTo(fresh.h, '/scaffold/accept').length, 1, 'the page never sends the accept again by itself')
})

test('real shapes: a failure after the move (409, partial) shows the partial text and blocks Create', async t => {
  const fresh = await finish(t, server({ polls: [running, { status: 'failed', proposal_id: PID, http_status: 409, detail: afterMove, partial: true }] }))
  const old = await finish(t, server({ first: () => { throw httpError(409, afterMove) } }), 0)
  assert.deepEqual(fresh.view, old.view)
  assert.ok(fresh.view.alerts.some(a => a.startsWith('Some files were created before something went wrong.')))
  assert.equal(fresh.view.create, true, 'the folder exists: Create stays disabled')
  assert.equal(callsTo(fresh.h, '/scaffold/accept').length, 1)
})

// Start, then poll: a server that is still creating the project after its short inline
// wait answers POST /scaffold/accept with 202 {status: 'running', poll, step, elapsed_s}.
// The dialog then asks GET <poll> every 1.5 s, shows the step and the time so far, offers
// Cancel, and on a final answer behaves exactly as it does for a finished POST.
// All timers are the harness's fake ones: nothing here waits for real time.
import test from 'node:test'
import assert from 'node:assert/strict'
import * as ui from '../plugin.js'
import { byDomId, matchReply, mountHarness, nodes, pick, textOf, tick } from './dialogHarness.mjs'

const NAME = 'my-tool'
const PID = 'p1'
const POLL = `/scaffold/accept/${PID}`
const created = { name: NAME, path: `/srv/projects/${NAME}`, registered: true }
const RESULT = { status: 'created', repos: [{ name: NAME, path: created.path, registration: 'registered', registration_result: { registered: true } }] }
const STEP = "Running the project's first check"
const STILL = 'The project is still being created. It will appear in the project list when it is ready.'
const CANCELLED = 'Creation was cancelled. Nothing was created.'
const TOO_LATE = 'It is too late to cancel: the project is being finished.'
const TOO_LONG = 'This is taking much longer than expected. Check the project list before you try again.'
const httpError = (status, detail) => new Error(`${status}: ${JSON.stringify({ detail })}`)
const running = (extra = {}) => ({ status: 'running', proposal_id: PID, step: STEP, elapsed_s: 21, ...extra })
const started = (extra = {}) => ({ ...running(extra), poll: POLL })

// first: reply to POST accept (a value, or a function that returns or throws).
// polls: replies to GET <poll>, one per poll (the last repeats); a function may throw.
// cancel: reply to POST /scaffold/cancel; projects: the project list per reload.
function server({ first = started(), polls = [running()], cancel = { status: 'cancelled', proposal_id: PID }, projects = [[]] } = {}) {
  let poll = 0, loads = 0
  const answer = (value, ...args) => typeof value === 'function' ? value(...args) : value
  return async (path, opts) => {
    if (path === '/scaffold/match') return matchReply()
    if (path === '/scaffold/propose') return { proposal_id: PID, template_id: opts.body.template_id, tree: [{ name: opts.body.name, dest: created.path, files: ['AGENTS.md'] }] }
    if (path === '/scaffold/accept') return answer(first, opts)
    if (path === POLL) return answer(polls[Math.min(poll++, polls.length - 1)], opts)
    if (path === '/scaffold/cancel') return answer(cancel, opts)
    if (path === '/workspace/projects') return { coverage: 'verified', projects: typeof projects === 'function' ? projects() : projects[Math.min(loads++, projects.length - 1)] }
    if (path === '/scaffold/discard') return { status: 'discarded' }
    return {}
  }
}

const callsTo = (h, path) => h.calls.filter(c => c.path === path)
const pollTimers = h => h.timers.filter(e => e.live && (e.ms === ui.SCAFFOLD_POLL_INTERVAL_MS || e.ms === ui.SCAFFOLD_POLL_LIMIT_MS))
const progress = h => textOf(byDomId(h.modal(), 'new-project-progress'))
const settle = async () => { for (let i = 0; i < 8; i++) await tick() }
const poll = async (h, n = 1) => { for (let i = 0; i < n; i++) { await h.fireTimers(e => e.ms === ui.SCAFFOLD_POLL_INTERVAL_MS); await settle() } }
const alerts = tree => nodes(tree, n => n.props?.role === 'alert').map(textOf)

// Presses Create; returns the click's promise, which ends only when creation ends.
async function startCreate(h) {
  await h.open()
  await byDomId(h.modal(), 'new-project-name').props.onChange({ target: { value: NAME } })
  const modal = await pick(h, 'template:python-golden')
  const pending = byDomId(modal, 'accept-project').props.onClick()
  await settle()
  return [pending] // wrapped: an async function returning the promise itself would wait for it
}

test('start-poll: the limits are named constants', () => {
  assert.equal(ui.SCAFFOLD_ACCEPT_TIMEOUT_MS, 75000, 'the first request keeps the long limit an old server needs')
  assert.equal(ui.SCAFFOLD_POLL_INTERVAL_MS, 1500)
  assert.equal(ui.SCAFFOLD_POLL_TIMEOUT_MS, 10000)
  assert.equal(ui.SCAFFOLD_POLL_LIMIT_MS, 15 * 60 * 1000)
})

test('start-poll: the time so far is plain words', () => {
  assert.equal(ui.createElapsedText(0), 'less than a minute')
  assert.equal(ui.createElapsedText(59.9), 'less than a minute')
  assert.equal(ui.createElapsedText(60), '1 minute')
  assert.equal(ui.createElapsedText(185), '3 minutes')
  assert.equal(ui.createElapsedText('x'), 'less than a minute')
  assert.equal(ui.createElapsedText(-5), 'less than a minute')
})

test('start-poll: after a 202 the dialog polls every 1.5 s with a short limit, shows the step, and finishes exactly like a finished POST', async t => {
  const h = mountHarness(t, server({ polls: [running({ elapsed_s: 23 }), running({ step: 'Registering the project', elapsed_s: 75 }), { status: 'done', proposal_id: PID, result: RESULT }], projects: [[], [created]] }))
  const [pending] = await startCreate(h)
  assert.equal(callsTo(h, '/scaffold/accept').length, 1)
  assert.equal(callsTo(h, '/scaffold/accept')[0].opts.timeoutMs, 75000)
  assert.equal(h.timers.filter(e => e.live && e.ms === 1500).length, 1, 'one poll is scheduled, 1.5 s later')
  assert.equal(h.timers.filter(e => e.live && e.ms === 900000).length, 1, 'and one overall limit')
  let region = byDomId(h.modal(), 'new-project-progress')
  assert.equal(region.props.role, 'status', 'the existing live region carries the progress')
  assert.equal(textOf(region), `${STEP} (less than a minute so far).`)
  assert.equal(byDomId(h.modal(), 'accept-project').props.disabled, true, 'Create stays disabled')
  await poll(h)
  const get = callsTo(h, POLL)
  assert.equal(get.length, 1)
  assert.equal(get[0].opts.method, undefined, 'polling is a GET')
  assert.equal(get[0].opts.timeoutMs, 10000, 'each poll has its own short limit')
  assert.equal(progress(h), `${STEP} (less than a minute so far).`)
  await poll(h)
  assert.equal(progress(h), 'Registering the project (1 minute so far).')
  await poll(h)
  await pending
  const tree = h.render()
  assert.equal(byDomId(tree, 'new-project-dialog'), undefined, 'success closes the dialog')
  assert.equal(textOf(nodes(tree, n => n.props?.['data-testid'] === 'audit-status-notice')[0]), `Project ${NAME} created (created).`)
  assert.equal(callsTo(h, '/scaffold/accept').length, 1, 'exactly one POST accept')
  assert.equal(callsTo(h, POLL).length, 3)
  assert.equal(pollTimers(h).length, 0, 'polling stops on the final answer')
  assert.equal(callsTo(h, '/scaffold/discard').length, 0)
})

test('start-poll: "done" gives the same notice and list reloads as an old server that answered at once', async t => {
  const run = async srv => {
    const h = mountHarness(t, srv)
    const [pending] = await startCreate(h)
    await poll(h, 2)
    await pending
    return { notice: textOf(nodes(h.render(), n => n.props?.['data-testid'] === 'audit-status-notice')[0]), loads: callsTo(h, '/workspace/projects').length }
  }
  const fresh = await run(server({ polls: [running(), { status: 'done', proposal_id: PID, result: RESULT }] }))
  const old = await run(server({ first: RESULT }))
  assert.deepEqual(fresh, old)
})

test('start-poll: "failed" shows exactly what an old server\'s failed POST shows', async t => {
  const run = async srv => {
    const h = mountHarness(t, srv)
    const [pending] = await startCreate(h)
    await poll(h, 2)
    await pending
    const modal = h.modal()
    return { alerts: alerts(modal), what: textOf(nodes(modal, n => n.props?.['aria-label'] === 'What happened')[0]), create: byDomId(modal, 'accept-project').props.disabled, progress: byDomId(modal, 'new-project-progress') }
  }
  const fresh = await run(server({ polls: [running(), { status: 'failed', proposal_id: PID, http_status: 500, detail: 'The check of the new project failed.', partial: false }] }))
  const old = await run(server({ first: () => { throw httpError(500, 'The check of the new project failed.') } }))
  assert.deepEqual(fresh, old)
  assert.ok(fresh.alerts.some(a => a.includes('The check of the new project failed.')))
})

test('start-poll: "failed" with a known detail goes through the same plain sentences (busy, consumed)', async t => {
  const busy = mountHarness(t, server({ polls: [{ status: 'failed', proposal_id: PID, http_status: 409, detail: 'Proposal is busy or requires inspection after partial creation', partial: false }] }))
  let [pending] = await startCreate(busy)
  await poll(busy); await pending
  assert.ok(textOf(busy.modal()).includes('This project is still being created. Wait a moment, then check the project list.'))
  assert.equal(textOf(busy.modal()).includes('Proposal is busy'), false)

  const gone = mountHarness(t, server({ polls: [{ status: 'failed', proposal_id: PID, http_status: 404, detail: 'Unknown or consumed proposal_id', partial: false }], projects: [[]] }))
  ;[pending] = await startCreate(gone)
  await poll(gone); await pending
  assert.ok(textOf(gone.modal()).includes('That request is no longer available. Choose the project type again.'))
})

test('start-poll: "failed" with partial true shows the existing partial-creation text', async t => {
  const h = mountHarness(t, server({ polls: [{ status: 'failed', proposal_id: PID, http_status: 500, detail: { error: 'registration failed', created_dirs: [created.path] }, partial: true }] }))
  const [pending] = await startCreate(h)
  await poll(h); await pending
  const modal = h.modal()
  assert.ok(alerts(modal).includes('Some files were created before something went wrong. They were left in place (listed below); nothing will be deleted.'))
  assert.equal(pollTimers(h).length, 0)

  const flagOnly = mountHarness(t, server({ polls: [{ status: 'failed', proposal_id: PID, http_status: 500, detail: 'Registration failed.', partial: true }] }))
  const [p2] = await startCreate(flagOnly)
  await poll(flagOnly); await p2
  assert.ok(alerts(flagOnly.modal()).some(a => a.startsWith('Some files were created before something went wrong.')), 'the flag alone is enough')
})

test('start-poll: "cancelled" returns the dialog to before Create, with one plain sentence', async t => {
  const h = mountHarness(t, server({ polls: [running(), { status: 'cancelled', proposal_id: PID }] }))
  const [pending] = await startCreate(h)
  await poll(h, 2)
  await pending
  const modal = h.modal()
  assert.ok(modal, 'the dialog stays open')
  assert.equal(progress(h), CANCELLED)
  assert.deepEqual(alerts(modal), [], 'no failure is shown')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, false, 'Create can be pressed again')
  assert.equal(byDomId(modal, 'cancel-project').props.disabled, false)
  assert.equal(byDomId(modal, 'new-project-name').props.value, NAME, 'what the user typed is kept')
  assert.equal(pollTimers(h).length, 0)
  assert.equal(callsTo(h, '/scaffold/discard').length, 0)
})

test('start-poll: Cancel during a job sends /scaffold/cancel; "cancelled" stops polling at once', async t => {
  const h = mountHarness(t, server())
  const [pending] = await startCreate(h)
  let cancelBtn = byDomId(h.modal(), 'cancel-project')
  assert.equal(textOf(cancelBtn), 'Cancel', 'the existing Cancel button, same label')
  assert.equal(cancelBtn.props.disabled, false, 'it can be pressed while the job runs')
  await cancelBtn.props.onClick()
  await settle(); await pending
  const sent = callsTo(h, '/scaffold/cancel')
  assert.equal(sent.length, 1)
  assert.equal(sent[0].opts.method, 'POST')
  assert.deepEqual(sent[0].opts.body, { proposal_id: PID })
  assert.ok(h.modal(), 'Cancel stops the job, it does not close the dialog')
  assert.equal(progress(h), CANCELLED)
  assert.equal(pollTimers(h).length, 0)
  await h.fireTimers(); await settle()
  assert.equal(callsTo(h, POLL).length, 0, 'no poll after the final state')
  assert.equal(callsTo(h, '/scaffold/accept').length, 1)
})

test('start-poll: Cancel answered "too late" says so plainly and keeps polling to the end', async t => {
  const h = mountHarness(t, server({ cancel: { status: 'running', proposal_id: PID, cancel: 'too_late' }, polls: [running({ step: 'Registering the project' }), { status: 'done', proposal_id: PID, result: RESULT }] }))
  const [pending] = await startCreate(h)
  await byDomId(h.modal(), 'cancel-project').props.onClick()
  await settle()
  assert.ok(progress(h).includes(TOO_LATE))
  assert.doesNotMatch(progress(h), /fail/i)
  // Cancel stays enabled (disabling the pressed button would drop keyboard focus); a second press sends nothing.
  assert.equal(byDomId(h.modal(), 'cancel-project').props.disabled, false)
  await byDomId(h.modal(), 'cancel-project').props.onClick(); await settle()
  assert.equal(callsTo(h, '/scaffold/cancel').length, 1, 'pressing Cancel again changes nothing')
  await poll(h)
  assert.ok(progress(h).startsWith('Registering the project'))
  assert.ok(progress(h).includes(TOO_LATE), 'the sentence stays while polling continues')
  await poll(h); await pending
  assert.equal(h.modal(), undefined, 'the job finished normally')
  assert.equal(callsTo(h, '/scaffold/cancel').length, 1)
})

test('start-poll: before the 202 arrives Cancel and Close stay disabled as today', async t => {
  let release
  const h = mountHarness(t, server({ first: () => new Promise(resolve => { release = resolve }) }))
  const [pending] = await startCreate(h)
  assert.equal(byDomId(h.modal(), 'cancel-project').props.disabled, true)
  assert.equal(nodes(h.modal(), n => n.props?.['aria-label'] === 'Close project setup')[0].props.disabled, true)
  release(started()); await settle()
  assert.equal(byDomId(h.modal(), 'cancel-project').props.disabled, false)
  await byDomId(h.modal(), 'cancel-project').props.onClick(); await settle(); await pending
})

test('start-poll: a dropped or timed-out poll is "still working"; after 5 in a row the still-being-created sentence shows, polling goes on', async t => {
  const drop = () => { throw new Error('Timed out connecting to Hermes backend after 10000ms') }
  const h = mountHarness(t, server({ polls: [drop, () => { throw httpError(502, 'Bad gateway') }, drop, drop, drop, running({ elapsed_s: 130 }), { status: 'done', proposal_id: PID, result: RESULT }] }))
  const [pending] = await startCreate(h)
  await poll(h, 4)
  assert.equal(progress(h), `${STEP} (less than a minute so far).`, 'four failed polls change nothing')
  await poll(h)
  assert.equal(progress(h), STILL)
  assert.deepEqual(alerts(h.modal()), [], 'never "failed" while the server may still be working')
  assert.equal(pollTimers(h).filter(e => e.ms === 1500).length, 1, 'polling continues')
  await poll(h)
  assert.equal(progress(h), `${STEP} (2 minutes so far).`, 'a good answer shows the step again')
  await poll(h); await pending
  assert.equal(h.modal(), undefined)
  assert.equal(callsTo(h, POLL).length, 7)
})

test('start-poll: a poll answered with an unexpected shape counts as a failed poll', async t => {
  const h = mountHarness(t, server({ polls: [{ status: 'strange' }, 'nonsense', null, { status: 'running' }, { status: 'done', proposal_id: PID, result: RESULT }] }))
  const [pending] = await startCreate(h)
  await poll(h, 3)
  assert.equal(progress(h), `${STEP} (less than a minute so far).`)
  await poll(h, 2); await pending
  assert.equal(h.modal(), undefined)
})

test('start-poll: a poll answered "unknown or consumed" ends like a consumed POST (list checked)', async t => {
  let gone = false
  const h = mountHarness(t, server({ polls: [() => { gone = true; throw httpError(404, 'Unknown or consumed proposal_id') }], projects: () => gone ? [created] : [] }))
  const [pending] = await startCreate(h)
  await poll(h); await pending
  assert.equal(h.modal(), undefined, 'the project is in the list: success')
  assert.equal(pollTimers(h).length, 0)
})

test('start-poll: after 15 minutes polling stops with one plain sentence and the list is reloaded', async t => {
  const h = mountHarness(t, server({ projects: [[]] }))
  const [pending] = await startCreate(h)
  await poll(h, 3)
  const loads = callsTo(h, '/workspace/projects').length
  await h.fireTimers(e => e.ms === 900000); await settle(); await pending
  assert.ok(callsTo(h, '/workspace/projects').length > loads, 'the list is reloaded')
  assert.ok(textOf(h.modal()).includes(TOO_LONG))
  assert.equal(progress(h), '', 'no progress is shown any more')
  assert.equal(pollTimers(h).length, 0)
  const polls = callsTo(h, POLL).length
  await h.fireTimers(); await settle()
  assert.equal(callsTo(h, POLL).length, polls, 'no poll after the stop')
  assert.equal(callsTo(h, '/scaffold/discard').length, 0, 'the server may still be using the proposal')
})

test('start-poll: after 15 minutes a project that is already listed is a success', async t => {
  let listed = false
  const h = mountHarness(t, server({ projects: () => listed ? [created] : [] }))
  const [pending] = await startCreate(h)
  listed = true
  await h.fireTimers(e => e.ms === 900000); await settle(); await pending
  assert.equal(h.modal(), undefined)
})

test('start-poll: closing the dialog while a job runs does not cancel it, says so once, and stops the timers', async t => {
  for (const how of ['close', 'escape']) {
    const h = mountHarness(t, server())
    const [pending] = await startCreate(h)
    await poll(h)
    const modal = h.modal()
    if (how === 'close') {
      const close = nodes(modal, n => n.props?.['aria-label'] === 'Close project setup')[0]
      assert.equal(close.props.disabled, false)
      await close.props.onClick()
    } else await modal.props.onKeyDown({ key: 'Escape', preventDefault() {} })
    await settle(); await pending
    const tree = h.render()
    assert.equal(byDomId(tree, 'new-project-dialog'), undefined, `${how}: the dialog closes`)
    assert.equal(textOf(nodes(tree, n => n.props?.['data-testid'] === 'audit-status-notice')[0]), ui.CREATE_CLOSED_RUNNING_TEXT)
    assert.equal(callsTo(h, '/scaffold/cancel').length, 0, `${how}: no cancel`)
    assert.equal(callsTo(h, '/scaffold/discard').length, 0, `${how}: no discard`)
    assert.equal(pollTimers(h).length, 0, `${how}: no timer left`)
    const polls = callsTo(h, POLL).length
    await h.fireTimers(); await settle()
    assert.equal(callsTo(h, POLL).length, polls, `${how}: no poll after close`)
    assert.equal(callsTo(h, '/scaffold/accept').length, 1)
  }
})

test('start-poll: unmounting the page while a job runs stops polling and sends nothing', async t => {
  const h = mountHarness(t, server())
  const [pending] = await startCreate(h)
  await poll(h)
  const before = h.calls.length
  h.unmount()
  await settle(); await pending
  assert.equal(pollTimers(h).length, 0, 'no timer left')
  await h.fireTimers(); await settle()
  assert.deepEqual(h.calls.slice(before).map(c => c.path), [], 'no poll, no cancel, no discard')
})

test('start-poll: a poll in flight when the dialog closes is ignored', async t => {
  let release
  const h = mountHarness(t, server({ polls: [() => new Promise(resolve => { release = resolve })] }))
  const [pending] = await startCreate(h)
  h.fireTimers(e => e.ms === 1500)
  await settle()
  await nodes(h.modal(), n => n.props?.['aria-label'] === 'Close project setup')[0].props.onClick()
  await settle(); await pending
  release({ status: 'done', proposal_id: PID, result: RESULT }); await settle()
  assert.equal(pollTimers(h).length, 0)
  assert.equal(textOf(nodes(h.render(), n => n.props?.['data-testid'] === 'audit-status-notice')[0]), ui.CREATE_CLOSED_RUNNING_TEXT)
})

test('start-poll: a hostile step string is shown escaped', async t => {
  const hostile = 'Run\u202echeck\u0007\u2066x\u2069\nnow\u0000'
  const h = mountHarness(t, server({ first: started({ step: hostile }) }))
  const [pending] = await startCreate(h)
  const shown = progress(h)
  assert.doesNotMatch(shown, /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/, 'no control or bidi character reaches the page')
  assert.equal(shown, 'Run\\u202echeck\\x07\\u2066x\\u2069 now\\x00 (less than a minute so far).')
  await byDomId(h.modal(), 'cancel-project').props.onClick(); await settle(); await pending
})

test('start-poll: a missing or non-text step falls back to a plain phrase', async t => {
  const h = mountHarness(t, server({ first: started({ step: 42 }) }))
  const [pending] = await startCreate(h)
  assert.equal(progress(h), 'Creating the project (less than a minute so far).')
  await byDomId(h.modal(), 'cancel-project').props.onClick(); await settle(); await pending
})

test('start-poll: one POST accept per Create press; pressing Create again during a job sends nothing', async t => {
  const h = mountHarness(t, server({ polls: [running(), running(), { status: 'cancelled', proposal_id: PID }] }))
  const [pending] = await startCreate(h)
  const create = byDomId(h.modal(), 'accept-project')
  assert.equal(create.props.disabled, true)
  await create.props.onClick()
  await poll(h)
  await byDomId(h.modal(), 'accept-project').props.onClick()
  assert.equal(callsTo(h, '/scaffold/accept').length, 1, 'no second POST while the job runs')
  await poll(h, 2); await pending
  assert.equal(callsTo(h, '/scaffold/accept').length, 1)
  // After the cancel the proposal is ready again: a new press is a new single POST.
  const again = byDomId(h.modal(), 'accept-project').props.onClick()
  await settle()
  assert.equal(callsTo(h, '/scaffold/accept').length, 2)
  assert.equal(callsTo(h, '/scaffold/propose').length, 1, 'the same proposal is used')
  assert.equal(progress(h), `${STEP} (less than a minute so far).`, 'the cancelled sentence is gone')
  await byDomId(h.modal(), 'cancel-project').props.onClick(); await settle(); await again
})

test('start-poll: a running answer to the POST uses our own poll address, never another one', async t => {
  const h = mountHarness(t, server({ first: started({ poll: '/elsewhere/steal' }) }))
  const [pending] = await startCreate(h)
  await poll(h)
  assert.equal(callsTo(h, '/elsewhere/steal').length, 0)
  assert.equal(callsTo(h, POLL).length, 1)
  await byDomId(h.modal(), 'cancel-project').props.onClick(); await settle(); await pending
})

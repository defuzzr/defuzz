// Creating a project can take longer than the host's default 30 s request limit (the
// server's accept step runs the template's own check, with its own 60 s deadline). The
// page asks for a longer limit, says what is happening while it waits, and never reports
// a failure when the answer was only lost: it checks the project list instead.
import test from 'node:test'
import assert from 'node:assert/strict'
import { byDomId, matchReply, mountHarness, nodes, pick, textOf, tick } from './dialogHarness.mjs'

const NAME = 'my-tool'
const created = { name: NAME, path: `/srv/projects/${NAME}`, registered: true }
const PROGRESS = 'Creating the project and running its first check. This can take about a minute.'
const STILL = 'The project is still being created. It will appear in the project list when it is ready.'
const httpError = (status, detail) => new Error(`${status}: ${JSON.stringify({ detail })}`)

// accept: a function (opts, attempt) returning the reply or throwing; projects: list per reload.
function server({ accept, propose, projects = [[]] } = {}) {
  let acceptAttempt = 0, loads = 0
  return async (path, opts) => {
    if (path === '/scaffold/match') return matchReply()
    if (path === '/scaffold/propose') {
      if (propose) return propose(opts)
      return { proposal_id: 'p1', template_id: opts.body.template_id, tree: [{ name: opts.body.name, dest: `/srv/projects/${opts.body.name}`, files: ['AGENTS.md'] }] }
    }
    if (path === '/scaffold/accept') return accept(opts, ++acceptAttempt)
    if (path === '/workspace/projects') return { coverage: 'verified', projects: projects[Math.min(loads++, projects.length - 1)] }
    if (path === '/scaffold/discard') return { status: 'discarded' }
    return {}
  }
}

async function createPython(h) {
  await h.open()
  await byDomId(h.modal(), 'new-project-name').props.onChange({ target: { value: NAME } })
  const modal = await pick(h, 'template:python-golden')
  return byDomId(modal, 'accept-project').props.onClick()
}
const callsTo = (h, path) => h.calls.filter(c => c.path === path)
const noRawServerText = (tree, ...raw) => {
  const text = textOf(tree)
  for (const r of raw) assert.equal(text.includes(r), false, `"${r}" is not shown`)
  assert.equal(nodes(tree, n => n.props?.['aria-label'] === 'What happened').length, 0, 'no raw reply area')
}

test('create timeout: accept asks for a 75 s limit, longer than the server deadline; propose asks for 15 s', async t => {
  const h = mountHarness(t, server({ accept: () => ({ status: 'created', repos: [{ name: NAME, path: created.path, registration: 'registered', registration_result: { registered: true } }] }) }))
  await createPython(h)
  assert.equal(callsTo(h, '/scaffold/propose')[0].opts.timeoutMs, 15000)
  assert.equal(callsTo(h, '/scaffold/accept')[0].opts.timeoutMs, 75000)
  assert.deepEqual(callsTo(h, '/scaffold/accept')[0].opts.body, { proposal_id: 'p1', confirm: true }, 'what Create sends is unchanged')
  // An old server never answers 202: the page never polls and starts no poll timer.
  assert.equal(h.calls.filter(c => c.path.startsWith('/scaffold/accept/')).length, 0)
  assert.equal(h.calls.filter(c => c.path === '/scaffold/cancel').length, 0)
  assert.equal(h.timers.filter(e => e.live && (e.ms === 1500 || e.ms === 900000)).length, 0)
})

test('create timeout: a kit accept asks for the long limit too', async t => {
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/kits/video-production') return { kit: { id: 'video-production', summary: 'Folders.' }, tree: ['footage/'] }
    if (path === '/scaffold/propose') return { proposal_id: 'pk', kind: 'kit', kit_id: opts.body.kit_id, slug: opts.body.name, tree: [{ name: opts.body.name, dest: `/srv/projects/${opts.body.name}`, files: ['footage/'] }] }
    if (path === '/scaffold/accept') return { status: 'created', kind: 'kit', placement: 'on', dest: created.path, repos: [] }
    return server({ accept: () => ({}) })(path, opts)
  })
  await h.open()
  await byDomId(h.modal(), 'new-project-name').props.onChange({ target: { value: NAME } })
  await byDomId(await pick(h, 'kit:video-production'), 'accept-project').props.onClick()
  assert.equal(callsTo(h, '/scaffold/accept')[0].opts.timeoutMs, 75000)
  assert.ok(callsTo(h, '/scaffold/propose')[0].opts.timeoutMs >= 15000)
})

test('create timeout: while accept runs the dialog says so, Create is disabled and the dialog cannot be closed', async t => {
  let release
  const h = mountHarness(t, server({
    accept: () => new Promise(resolve => { release = () => resolve({ status: 'created', repos: [{ name: NAME, path: created.path, registration: 'registered', registration_result: { registered: true } }] }) }),
    projects: [[], [created]]
  }))
  const pending = createPython(h)
  await tick(); await tick()
  let modal = h.modal()
  const progress = byDomId(modal, 'new-project-progress')
  assert.equal(textOf(progress), PROGRESS)
  assert.equal(progress.props.role, 'status')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true)
  await nodes(modal, n => n.props?.['aria-label'] === 'Close project setup')[0].props.onClick()
  await modal.props.onKeyDown({ key: 'Escape', preventDefault() {} })
  assert.ok(h.modal(), 'the dialog stays open while the project is being created')
  release(); await pending
  modal = h.modal()
  assert.equal(modal, undefined, 'a normal success closes the dialog')
})

test('create timeout: an accept with no answer says the project is still being created, reloads the list, and turns into success when the project appears', async t => {
  const h = mountHarness(t, server({
    accept: () => { throw new Error('Timed out connecting to Hermes backend after 75000ms') },
    projects: [[], [created]]
  }))
  await createPython(h)
  await tick()
  let modal = h.modal()
  assert.ok(modal, 'the dialog stays open')
  assert.equal(textOf(byDomId(modal, 'new-project-progress')), STILL)
  assert.doesNotMatch(textOf(modal), /fail|Timed out/i, 'it does not say creation failed')
  noRawServerText(modal)
  const loadsNow = callsTo(h, '/workspace/projects').length
  assert.ok(loadsNow >= 1, 'the project list is reloaded at once')
  const recheck = h.timers.filter(e => e.live && e.ms === 5000)
  assert.equal(recheck.length, 1, 'and once more after a short delay')
  await h.fireTimers(e => e.ms === 5000)
  await tick()
  assert.equal(callsTo(h, '/workspace/projects').length, loadsNow + 1 + 1, 'the delayed reload, then the reload after success')
  const tree = h.render()
  assert.equal(byDomId(tree, 'new-project-dialog'), undefined, 'success closes the dialog')
  assert.equal(textOf(nodes(tree, n => n.props?.['data-testid'] === 'audit-status-notice')[0]), `Project ${NAME} created.`)
})

test('create timeout: a dropped connection whose project is already listed is a success at once', async t => {
  const h = mountHarness(t, server({
    accept: () => { const e = new Error('socket hang up'); e.code = 'ECONNRESET'; throw e },
    projects: [[created]]
  }))
  await createPython(h)
  await tick()
  assert.equal(h.modal(), undefined)
  assert.equal(h.timers.filter(e => e.live && e.ms === 5000).length, 0, 'no delayed check is needed')
})

test('create timeout: 409 "still running" on accept is one plain sentence', async t => {
  const h = mountHarness(t, server({ accept: () => { throw httpError(409, 'Proposal is busy or requires inspection after partial creation') } }))
  await createPython(h)
  const modal = h.modal()
  assert.ok(textOf(modal).includes('This project is still being created. Wait a moment, then check the project list.'))
  noRawServerText(modal, 'Proposal is busy', '409')
})

test('create timeout: 404 consumed proposal reloads the list; a listed project is a success, otherwise one plain sentence', async t => {
  const gone = mountHarness(t, server({ accept: () => { throw httpError(404, 'Unknown or consumed proposal_id') }, projects: [[]] }))
  await createPython(gone)
  let modal = gone.modal()
  assert.ok(callsTo(gone, '/workspace/projects').length >= 1, 'the list is checked')
  assert.ok(textOf(modal).includes('That request is no longer available. Choose the project type again.'))
  noRawServerText(modal, 'Unknown or consumed', '404')

  const done = mountHarness(t, server({ accept: () => { throw httpError(404, 'Unknown or consumed proposal_id') }, projects: [[created]] }))
  await createPython(done)
  assert.equal(done.modal(), undefined, 'the project exists: success')
})

test('create timeout: 400 "Destination already exists" on propose is one plain sentence', async t => {
  const h = mountHarness(t, server({ propose: () => { throw httpError(400, `Destination already exists: /srv/projects/${NAME}`) }, accept: () => ({}) }))
  await createPython(h)
  const modal = h.modal()
  assert.ok(textOf(modal).includes('A project with this name already exists. Choose another name or open the existing one.'))
  noRawServerText(modal, 'Destination already exists', '/srv/projects/my-tool/')
  assert.equal(callsTo(h, '/scaffold/accept').length, 0)
})

test('create timeout: a real server error still shows as a failure and does not pretend the project is coming', async t => {
  const h = mountHarness(t, server({ accept: () => { throw httpError(500, 'Internal check runner crashed') } }))
  await createPython(h)
  const modal = h.modal()
  assert.ok(nodes(modal, n => n.props?.role === 'alert' && /Internal check runner crashed/.test(textOf(n))).length >= 1, 'the failure is shown')
  assert.equal(textOf(modal).includes(STILL), false)
  assert.equal(h.timers.filter(e => e.live && e.ms === 5000).length, 0)
})

test('create timeout: a staged check failure (409 with details) is still a failure, not "still being created"', async t => {
  const h = mountHarness(t, server({ accept: () => { throw Object.assign(httpError(409, { error: 'staged check failed', output: 'ci error', created_dirs: [] }), { body: { detail: { error: 'staged check failed', output: 'ci error', created_dirs: [] } } }) } }))
  await createPython(h)
  const modal = h.modal()
  assert.equal(textOf(modal).includes('still being created'), false)
  assert.ok(nodes(modal, n => n.props?.role === 'alert').length >= 1)
})

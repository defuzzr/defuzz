import test from 'node:test'
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'

const nodes = (node, predicate = () => true) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]

const byId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)[0]
const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const textOf = node =>
  !node
    ? ''
    : typeof node === 'string' || typeof node === 'number'
      ? String(node)
      : [node.props?.children].flat().map(textOf).join('')

function mountHarness(t, initialScreen = 'main', replies = []) {
  const instances = new Map(), calls = [], routes = [], cleanups = new Set(), effects = [], intervals = new Map(), timeouts = new Map()
  let slots, cursor, dirty, currentScreen = initialScreen, nextIntervalId = 1, nextTimeoutId = 1
  const previousNavigate = host.navigate
  host.navigate = path => { routes.push(path) }
  globalThis.__adoptTestUseState = init => {
    const own = slots, i = cursor++
    if (!(i in own)) own[i] = typeof init === 'function' ? init() : init
    return [own[i], next => {
      const value = typeof next === 'function' ? next(own[i]) : next
      if (!Object.is(value, own[i])) { own[i] = value; dirty = true }
    }]
  }
  globalThis.__adoptTestUseEffect = (fn, deps) => {
    const own = slots, i = cursor++, old = own[i]
    if (!old || !deps || deps.length !== old.deps?.length || deps.some((dep, j) => !Object.is(dep, old.deps[j]))) {
      const effect = { deps }
      own[i] = effect
      effects.push(() => {
        old?.cleanup?.(); cleanups.delete(old?.cleanup)
        effect.cleanup = fn()
        if (effect.cleanup) cleanups.add(effect.cleanup)
      })
    }
  }
  const disposers = []
  let latestTree = null
  const ctx = {
    onDispose(fn) { disposers.push(fn); return () => {} },
    setTimeout(fn, ms) {
      const id = nextTimeoutId++
      timeouts.set(id, { fn, ms })
      return () => timeouts.delete(id)
    },
    setInterval(fn, ms) {
      const id = nextIntervalId++
      intervals.set(id, { fn, ms })
      return () => intervals.delete(id)
    },
    async rest(path, opts) {
      calls.push({ path, opts })
      // Start-project calls (added by fix 3A) are answered by route so they never consume audit replies.
      if (path === '/scaffold/match') return { matches: [], closest: [], handoff: null }
      if (path === '/scaffold/discard') return { status: 'discarded' }
      if (path === '/scaffold/projects-root' || String(path).startsWith('/scaffold/projects-root?')) {
        return { path: '/home/user/Tools', source: 'setting', valid: true, default_path: '/home/user/Tools', message: '' }
      }
      const reply = replies.shift()
      if (reply instanceof Error) throw reply
      return typeof reply === 'function' ? reply(path, opts) : (reply ?? {})
    }
  }
  function expand(node, path = 'root') {
    if (!node || typeof node !== 'object') return node
    if (typeof node.type === 'function') {
      if (!instances.has(path)) instances.set(path, [])
      slots = instances.get(path); cursor = 0
      return expand(node.type(node.props), path + '.render')
    }
    return { ...node, props: { ...node.props, children: [node.props?.children].flat().map((child, i) => expand(child, path + '.' + i)) } }
  }
  t.after(() => {
    cleanups.forEach(fn => fn?.())
    disposers.forEach(fn => fn?.())
    host.navigate = previousNavigate
    delete globalThis.__adoptTestUseState
    delete globalThis.__adoptTestUseEffect
  })
  return {
    ctx,
    calls,
    routes,
    intervals,
    timeouts,
    get latestTree() { return latestTree },
    isBackgroundInert() {
      if (!latestTree) return false
      return Boolean(byId(latestTree, 'v10-top-bar')?.props?.inert || byDomId(latestTree, 'workspace')?.props?.inert)
    },
    async tickIntervals() {
      for (const entry of [...intervals.values()]) await entry.fn()
    },
    async tickTimeouts() {
      const list = [...timeouts.entries()]
      timeouts.clear()
      for (const [, entry] of list) await entry.fn()
    },
    render(screen = currentScreen) {
      currentScreen = screen
      let tree, passes = 0
      do {
        assert.ok(passes++ < 25, 'render settles')
        dirty = false
        tree = expand({ type: ui.WorkspacePage, props: { ctx, initialScreen: currentScreen } })
        latestTree = tree
        effects.splice(0).forEach(fn => fn())
      } while (dirty)
      return tree
    },
    unmount() {
      cleanups.forEach(fn => fn?.())
      cleanups.clear()
      instances.clear()
    },
    dispose() {
      disposers.forEach(fn => fn?.())
    }
  }
}

test('Fix3B Issue 2: Audit consent dialog never shows fictitious invoice-tracker when no project is selected, and matches submitted selected_projects when none or alpha is selected', async t => {
  const h = mountHarness(t, 'main', [
    { scope_disclosure: 'Live scope disclosure no-project' },
    { run_id: 'run-empty', status: 'completed', report: { coverage: 'could_not_verify', findings: [] } },
    { run_id: 'run-empty', status: 'completed', report: { coverage: 'could_not_verify', findings: [] } },
    { coverage: 'could_not_verify', findings: [] },
    { text: null }, // /audit/summary for run-empty: no text, JSON view stays
    { coverage: 'verified', projects: [{ name: 'alpha', path: 'alpha', registered: true, template_id: 'ts-node-golden' }] },
    { scope_disclosure: 'Live scope disclosure alpha' },
    { run_id: 'run-alpha', status: 'completed', report: { coverage: 'verified', findings: [] } },
    { run_id: 'run-alpha', status: 'completed', report: { coverage: 'verified', findings: [] } },
    { coverage: 'verified', findings: [] }
  ])

  // 1. Fresh workspace (no project selected) -> Quick ▶
  let tree = h.render('main')
  await byDomId(tree, 'audit-quick-button').props.onClick()
  tree = h.render('main')
  let modal = byDomId(tree, 'audit-review-dialog')
  assert.ok(modal, 'Quick audit dialog opens')
  const targetTextEmpty = textOf(byDomId(modal, 'audit-target-project'))
  assert.doesNotMatch(targetTextEmpty, /invoice-tracker/i, 'must not display fictitious invoice-tracker')
  assert.doesNotMatch(textOf(modal), /invoice-tracker/i, 'dialog must contain no fake project name')
  assert.match(targetTextEmpty, /none selected|no project selected/i, 'states clearly that no project is selected and what backend covers')
  assert.match(textOf(modal), /Live scope disclosure no-project/, 'includes live /audit/scope response')

  byDomId(modal, 'audit-review-consent').props.onChange({ target: { checked: true } })
  tree = h.render('main')
  await byDomId(byDomId(tree, 'audit-review-dialog'), 'audit-review-run').props.onClick()
  tree = h.render('main')

  const startEmpty = h.calls.find(c => c.path === '/audit/start')
  assert.ok(startEmpty, '/audit/start called for empty selection')
  assert.deepEqual(startEmpty.opts.body, { selected_projects: [], quick: true }, 'submits selected_projects: [] matching displayed no-project scope')

  // 2. Select project alpha -> Quick ▶ shows alpha and submits ['alpha']
  await nodes(tree, n => n.type === 'Button' && textOf(n) === 'Refresh projects')[0].props.onClick()
  tree = h.render('main')
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'alpha')[0].props.onClick()
  tree = h.render('main')

  await byDomId(tree, 'audit-quick-button').props.onClick()
  tree = h.render('main')
  modal = byDomId(tree, 'audit-review-dialog')
  assert.equal(textOf(byDomId(modal, 'audit-target-project')), 'alpha', 'displays selected project alpha')

  byDomId(modal, 'audit-review-consent').props.onChange({ target: { checked: true } })
  tree = h.render('main')
  await byDomId(byDomId(tree, 'audit-review-dialog'), 'audit-review-run').props.onClick()
  tree = h.render('main')

  const startCalls = h.calls.filter(c => c.path === '/audit/start')
  assert.equal(startCalls.length, 2)
  assert.deepEqual(startCalls[1].opts.body, { selected_projects: ['alpha'], quick: true }, 'submits selected_projects: [\"alpha\"] matching displayed alpha scope')
})

test('Fix3B Issue 3: Audit status and report transport errors remain visible in footer audit output after modal closes, with retry action that re-polls same run_id to completion', async t => {
  const h = mountHarness(t, 'main', [
    // Run 1: /audit/scope ok, /audit/start ok, initial /audit/status rejects 'STATUS OFFLINE'
    { scope_disclosure: 'Live scope disclosure' },
    { run_id: 'run-err-1', status: 'running' },
    new Error('STATUS OFFLINE'),
    // Retry 1: /audit/status succeeds (completed), /audit/report rejects 'REPORT OFFLINE'
    { run_id: 'run-err-1', status: 'completed' },
    new Error('REPORT OFFLINE'),
    // Retry 2: /audit/status succeeds (completed), /audit/report succeeds
    { run_id: 'run-err-1', status: 'completed' },
    { coverage: 'verified', findings: [{ id: 'f-ok', coverage: 'verified' }], proposals: [] }
  ])

  let tree = h.render('main')
  await byDomId(tree, 'audit-full-button').props.onClick()
  tree = h.render('main')
  byDomId(byDomId(tree, 'audit-review-dialog'), 'audit-review-consent').props.onChange({ target: { checked: true } })
  tree = h.render('main')

  await byDomId(byDomId(tree, 'audit-review-dialog'), 'audit-review-run').props.onClick()
  tree = h.render('main')

  assert.equal(byDomId(tree, 'audit-review-dialog'), undefined, 'modal closed after /audit/start')
  let footerAudit = byId(tree, 'footer-audit-output')
  assert.ok(footerAudit, 'footer-audit-output renders when initial /audit/status fails after modal closes')
  assert.match(textOf(footerAudit), /STATUS OFFLINE/, 'footer audit output displays STATUS OFFLINE error')

  let retryBtn = byId(footerAudit, 'audit-retry-button') || byDomId(footerAudit, 'audit-retry-button') || nodes(footerAudit, n => n.type === 'Button' && /retry|refresh/i.test(textOf(n)))[0]
  assert.ok(retryBtn, 'footer audit output provides retry/refresh button for failed status poll')

  // Click retry -> re-polls status for run-err-1, status completes, report fetch fails with REPORT OFFLINE
  await retryBtn.props.onClick()
  tree = h.render('main')
  footerAudit = byId(tree, 'footer-audit-output')
  assert.ok(footerAudit, 'footer-audit-output remains visible when /audit/report fails')
  assert.match(textOf(footerAudit), /REPORT OFFLINE/, 'footer audit output displays REPORT OFFLINE error')
  assert.equal(h.calls.filter(c => c.path === '/audit/status?run_id=run-err-1').length, 2, 'retry re-polled /audit/status for same run_id')
  assert.equal(h.calls.filter(c => c.path === '/audit/report?run_id=run-err-1').length, 1, 'attempted /audit/report for same run_id')

  // Click retry again -> completes both status and report
  retryBtn = byId(footerAudit, 'audit-retry-button') || byDomId(footerAudit, 'audit-retry-button') || nodes(footerAudit, n => n.type === 'Button' && /retry|refresh/i.test(textOf(n)))[0]
  assert.ok(retryBtn, 'retry button still available after report error')
  await retryBtn.props.onClick()
  tree = h.render('main')
  footerAudit = byId(tree, 'footer-audit-output')
  assert.ok(footerAudit, 'footer-audit-output shows completed report')
  assert.doesNotMatch(textOf(footerAudit), /REPORT OFFLINE|STATUS OFFLINE/, 'error cleared after successful retry')
  assert.match(textOf(footerAudit), /f-ok/, 'completed report rendered after retry')
})

test('Fix3B Issue 5: All 3 modals restore opener focus only AFTER close render commits and background inert attribute is removed', async t => {
  const h = mountHarness(t, 'main', [
    { scope_disclosure: 'Live scope' },
    { scope_disclosure: 'Live scope 2' },
    { run_id: 'run-focus', status: 'completed', report: { coverage: 'verified', findings: [] } },
    { run_id: 'run-focus', status: 'completed', report: { coverage: 'verified', findings: [] } },
    { coverage: 'verified', findings: [] }
  ])
  let tree = h.render('main')

  const makeInertAwareOpener = () => {
    const state = { focusedCount: 0, refusedWhileInert: 0 }
    return {
      state,
      el: {
        focus() {
          if (h.isBackgroundInert()) {
            state.refusedWhileInert += 1
            return
          }
          state.focusedCount += 1
        }
      }
    }
  }

  // 1. Start project modal close
  const opener1 = makeInertAwareOpener()
  byDomId(tree, 'start-project').props.onClick({ currentTarget: opener1.el })
  tree = h.render('main')
  assert.equal(h.isBackgroundInert(), true, 'background is inert while Start project modal is open')
  byDomId(byDomId(tree, 'new-project-dialog'), 'cancel-project').props.onClick()
  // Before render commits, opener must not have been focused while inert
  assert.equal(opener1.state.refusedWhileInert, 0, 'Start project modal must not call opener.focus() synchronously while background is still inert')
  tree = h.render('main')
  assert.equal(h.isBackgroundInert(), false, 'background inert removed after close render')
  assert.equal(opener1.state.focusedCount, 1, 'Start project modal restores focus after inert is removed')

  // 2. Audit modal close (Cancel)
  const opener2 = makeInertAwareOpener()
  await byDomId(tree, 'audit-full-button').props.onClick({ currentTarget: opener2.el })
  tree = h.render('main')
  assert.equal(h.isBackgroundInert(), true, 'background is inert while Audit modal is open')
  byDomId(tree, 'audit-review-dialog').props.onKeyDown({ key: 'Escape', preventDefault() {} })
  assert.equal(opener2.state.refusedWhileInert, 0, 'Audit modal must not call opener.focus() synchronously while background is still inert')
  tree = h.render('main')
  assert.equal(h.isBackgroundInert(), false)
  assert.equal(opener2.state.focusedCount, 1, 'Audit modal restores focus after inert is removed')

  // 3. Plugin storage modal close
  const opener3 = makeInertAwareOpener()
  byDomId(tree, 'plugin-storage-button').props.onClick({ currentTarget: opener3.el })
  tree = h.render('main')
  assert.equal(h.isBackgroundInert(), true, 'background is inert while Plugin storage modal is open')
  byDomId(tree, 'plugin-storage-dialog').props.onKeyDown({ key: 'Escape', preventDefault() {} })
  assert.equal(opener3.state.refusedWhileInert, 0, 'Plugin storage modal must not call opener.focus() synchronously while background is still inert')
  tree = h.render('main')
  assert.equal(h.isBackgroundInert(), false)
  assert.equal(opener3.state.focusedCount, 1, 'Plugin storage modal restores focus after inert is removed')

  // 4. Audit modal close via Run audit
  const opener4 = makeInertAwareOpener()
  await byDomId(tree, 'audit-quick-button').props.onClick({ currentTarget: opener4.el })
  tree = h.render('main')
  byDomId(byDomId(tree, 'audit-review-dialog'), 'audit-review-consent').props.onChange({ target: { checked: true } })
  tree = h.render('main')
  await byDomId(byDomId(tree, 'audit-review-dialog'), 'audit-review-run').props.onClick()
  assert.equal(opener4.state.refusedWhileInert, 0, 'Audit Run close must not call opener.focus() while background is still inert')
  tree = h.render('main')
  assert.equal(opener4.state.focusedCount, 1, 'Audit Run close restores focus after inert is removed')
})

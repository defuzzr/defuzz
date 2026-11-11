import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
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
  let slots, cursor, dirty, currentScreen = initialScreen, nextIntervalId = 1, nextTimeoutId = 1, setStateCalls = 0
  const previousNavigate = host.navigate
  host.navigate = path => { routes.push(path) }
  globalThis.__adoptTestUseState = init => {
    const own = slots, i = cursor++
    if (!(i in own)) own[i] = typeof init === 'function' ? init() : init
    return [own[i], next => {
      setStateCalls += 1
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
    get setStateCalls() { return setStateCalls },
    render(screen = currentScreen) {
      currentScreen = screen
      let tree, passes = 0
      do {
        assert.ok(passes++ < 25, 'render settles')
        dirty = false
        tree = expand({ type: ui.WorkspacePage, props: { ctx, initialScreen: currentScreen } })
        effects.splice(0).forEach(fn => fn())
      } while (dirty)
      return tree
    },
    unmount() {
      cleanups.forEach(fn => fn?.())
      cleanups.clear()
      instances.clear()
    }
  }
}

test('Fix3C-1: Footer CHECKS isolates per-project lock evidence across project switches and unmount', async t => {
  let resolveAlphaTools, resolveAlphaLock, resolveUnmountTools
  const h = mountHarness(t, 'main', [
    { coverage: 'verified', projects: [
      { name: 'alpha', path: '/p/alpha', registered: true, template_id: 'ts-node-golden' },
      { name: 'beta', path: '/p/beta', registered: true, template_id: 'python-golden' }
    ] },
    () => new Promise(resolve => { resolveAlphaTools = resolve }),
    () => new Promise(resolve => { resolveAlphaLock = resolve }),
    { items: [{ name: 'ruff', status: 'ok' }] },
    { ok: false, error: 'TOOLS.lock hash mismatch for beta' },
    () => new Promise(resolve => { resolveUnmountTools = resolve })
  ])

  let tree = h.render('main')
  await nodes(tree, n => n.type === 'Button' && textOf(n) === 'Refresh projects')[0].props.onClick()
  tree = h.render('main')

  // Select alpha -> click CHECKS -> hold alpha /tools/status and /tools-lock responses
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'alpha')[0].props.onClick()
  tree = h.render('main')
  const alphaChecksPromise = byId(tree, 'footer-checks-play').props.onClick()
  tree = h.render('main')
  assert.equal(byId(tree, 'footer-checks-play').props.disabled, true, 'CHECKS disabled on alpha while alpha checks in-flight')

  // Switch to beta while alpha /tools/status is still pending
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'beta')[0].props.onClick()
  tree = h.render('main')
  assert.equal(byId(tree, 'footer-checks-play').props.disabled, false, 'CHECKS not disabled on beta while alpha is in-flight')
  assert.equal(byId(tree, 'footer-checks-output'), undefined, 'beta shows no checks output initially')

  // Resolve alpha /tools/status, then verify /tools-lock queries /p/alpha (not current.selected /p/beta!)
  resolveAlphaTools({ items: [{ name: 'biome', installed_version: '2.6.6', status: 'ok' }] })
  for (let i = 0; i < 6 && !resolveAlphaLock; i++) await Promise.resolve()
  assert.equal(typeof resolveAlphaLock, 'function', 'alpha /tools-lock request issued')
  assert.equal(h.calls[2].path, '/tools-lock?project=%2Fp%2Falpha', '/tools-lock must use captured targetProject /p/alpha, not newly selected /p/beta')

  // Resolve alpha /tools-lock while still on beta
  resolveAlphaLock({ lock: '/p/alpha/TOOLS.lock', trust: { status: 'trusted', tools_lock_hash: 'alpha-trusted-hash' }, summary: 'alpha lock verified' })
  await alphaChecksPromise
  tree = h.render('main')

  // Under beta: nothing of alpha is shown and no 'Checks completed.' notice is shown for beta
  assert.equal(byId(tree, 'footer-checks-output'), undefined, 'beta must not display alpha checks result')
  assert.doesNotMatch(JSON.stringify(tree), /alpha-trusted-hash|alpha lock verified/, 'beta DOM must not contain alpha lock evidence')
  assert.equal(byDomId(tree, 'status'), undefined, 'beta must not show Checks completed. notice from alpha')

  // Switch back to alpha -> shows alpha's result
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'alpha')[0].props.onClick()
  tree = h.render('main')
  const alphaOut = byId(tree, 'footer-checks-output')
  assert.ok(alphaOut, 'switching back to alpha shows alpha checks output')
  assert.match(JSON.stringify(alphaOut), /alpha-trusted-hash/, 'alpha checks output contains alpha lock evidence')

  // Switch to beta and run checks where backend returns { ok: false, error: ... } -> reports failure as failure
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'beta')[0].props.onClick()
  tree = h.render('main')
  assert.equal(byId(tree, 'footer-checks-output'), undefined, 'switching back to beta hides alpha checks output')
  await byId(tree, 'footer-checks-play').props.onClick()
  tree = h.render('main')
  const betaNotice = textOf(byDomId(tree, 'status'))
  assert.doesNotMatch(betaNotice, /Checks completed/i, 'failed check payload must not report Checks completed.')
  assert.match(betaNotice, /Checks failed.*TOOLS\.lock hash mismatch for beta/i, 'failed check payload reports failure')

  // Switching project clears transient notice
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'alpha')[0].props.onClick()
  tree = h.render('main')
  assert.equal(byDomId(tree, 'status'), undefined, 'switching project clears transient actionNotice')

  // Unmount mid-request => no state update
  const unmountPromise = byId(tree, 'footer-checks-play').props.onClick()
  assert.equal(typeof resolveUnmountTools, 'function', 'unmount checks request in-flight')
  h.unmount()
  const stateCallsAtUnmount = h.setStateCalls
  resolveUnmountTools({ items: [] })
  await unmountPromise
  assert.equal(h.setStateCalls, stateCallsAtUnmount, 'no state update after unmount')
})

test('Fix3C-2: Dead previewBusy state and unused SettingsView.onOpenNewProject prop are removed', t => {
  const src = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')
  assert.equal(/previewBusy/.test(src), false, 'write-only previewBusy removed from desktop/plugin.js')
  assert.equal(/onOpenNewProject/.test(src), false, 'unused onOpenNewProject removed from desktop/plugin.js')
})

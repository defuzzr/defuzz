import test from 'node:test'
import assert from 'node:assert/strict'
import * as ui from '../plugin.js'
import { host } from '@hermes/plugin-sdk'

const nodes = node => !node || typeof node !== 'object' ? [] : [node, ...[node.props?.children].flat().flatMap(nodes)]
const byId = (tree, id) => nodes(tree).find(n => n.props?.['data-testid'] === id)
const byDomId = (tree, id) => nodes(tree).find(n => n.props?.id === id)

function harness(t) {
  const instances = new Map(), calls = [], routes = [], cleanups = new Set(), effects = []
  let slots, cursor, dirty, initialScreen = 'main'
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
  const ctx = { onDispose() {}, rest(...args) { calls.push(args); throw new Error('Guide must not request backend data') } }
  function expand(node, path = 'root') {
    if (!node || typeof node !== 'object') return node
    if (typeof node.type === 'function') {
      if (!instances.has(path)) instances.set(path, [])
      slots = instances.get(path); cursor = 0
      return expand(node.type(node.props), path + '.render')
    }
    return { ...node, props: { ...node.props, children: [node.props?.children].flat().map((child, i) => expand(child, path + '.' + i)) } }
  }
  t.after(() => { cleanups.forEach(fn => fn?.()); host.navigate = previousNavigate; delete globalThis.__adoptTestUseState; delete globalThis.__adoptTestUseEffect })
  return {
    calls,
    routes,
    render(screen = initialScreen) {
      initialScreen = screen
      let tree, passes = 0
      do {
        assert.ok(passes++ < 20, 'render settles')
        dirty = false
        tree = expand({ type: ui.WorkspacePage, props: { ctx, initialScreen } })
        effects.splice(0).forEach(fn => fn())
      } while (dirty)
      return tree
    }
  }
}

test('legacy 7-step Onboarding tour is removed and replaced by V10 Settings 4-stage Interactive guide without backend requests', t => {
  assert.equal(ui.ONBOARDING_TOUR_STEPS, undefined)
  assert.equal(ui.OnboardingTourBar, undefined)
  const h = harness(t)
  let tree = h.render('main')
  assert.equal(byId(tree, 'onboarding-trigger-btn'), undefined)
  assert.equal(byId(tree, 'onboarding-tour-panel'), undefined)

  // Navigate to Settings and toggle the V10 4-stage Interactive guide
  byDomId(tree, 'settings-button').props.onClick()
  tree = h.render('settings')
  const toggle = byDomId(tree, 'tutorial-toggle')
  assert.equal(toggle.props['aria-expanded'], false)
  toggle.props.onClick()
  tree = h.render('settings')
  assert.equal(byDomId(tree, 'tutorial-toggle').props['aria-expanded'], true)
  const strip = byDomId(tree, 'tutorial-strip')
  assert.ok(strip)
  for (let i = 0; i < 4; i++) {
    byId(strip, `v10-stage-card-${i}`).props.onClick()
    tree = h.render('settings')
    assert.match(JSON.stringify(byDomId(tree, 'spot-badge')), new RegExp(`STAGE ${i + 1} OF 4`))
  }
  // Only the companion-preferences section reads its saved values when Settings opens.
  assert.deepEqual(h.calls.filter(([path, opts]) => !(path === '/componentize/settings' && !opts?.method)), [])
})

test('locked transparent WebP banner is embedded in V10 top bar without legacy station banner', () => {
  assert.match(ui.DEFUZZ_BANNER_DATA_URL || '', /^data:image\/webp;base64,[A-Za-z0-9+/]+=*$/)
  const bytes = Buffer.from(ui.DEFUZZ_BANNER_DATA_URL.split(',')[1], 'base64')
  assert.equal(bytes.toString('ascii', 0, 4), 'RIFF')
  assert.equal(bytes.toString('ascii', 8, 12), 'WEBP')
  const tree = ui.WorkspacePage({ ctx: {} })
  assert.equal(byId(tree, 'defuzz-station-banner'), undefined)
  const image = byId(tree, 'v10-locked-banner')
  assert.equal(image.type, 'img')
  assert.equal(image.props.src, ui.DEFUZZ_BANNER_DATA_URL)
  assert.equal(image.props.className, 'locked-banner')
})

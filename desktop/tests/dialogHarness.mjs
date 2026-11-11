// Shared render harness for tests that drive the New Project dialog through the
// whole WorkspacePage, with a fake server that sees every request the page sends.
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'

export const nodes = (node, predicate = () => true) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
export const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
export const textOf = node =>
  !node
    ? ''
    : typeof node === 'string' || typeof node === 'number'
      ? String(node)
      : [node.props?.children].flat().map(textOf).join('')
export const tick = () => new Promise(resolve => setImmediate(resolve))

export const ENTRIES = [
  { kind: 'template', id: 'python-golden', title: 'Python project', line: 'A Python project with tests.', group: 'code', group_title: 'Code projects' },
  { kind: 'template', id: 'ts-node-golden', title: 'TypeScript service', line: 'A Node service in TypeScript.', group: 'code', group_title: 'Code projects' },
  { kind: 'template', id: 'web-golden', title: 'Static website', line: 'A website built with Vite.', group: 'code', group_title: 'Code projects' },
  { kind: 'kit', id: 'video-production', title: 'Video production', line: 'Folders for a video.', group: 'workspace', group_title: 'Workspaces for files' }
]
export const catalogOf = (overrides = {}) => ({ entries: ENTRIES, suggested: [], notice: '', ...overrides })
export const matchReply = (catalog = catalogOf(), extra = {}) => ({ matches: [], closest: [], handoff: null, kits: [], kit_catalog: [{ kit_id: 'video-production' }], kits_notice: '', preferred: 'none', catalog, ...extra })

export function mountHarness(t, restHandler) {
  const instances = new Map(), calls = [], cleanups = new Set(), effects = []
  let slots, cursor, dirty
  const previousNavigate = host.navigate
  host.navigate = () => {}
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
  const disposers = [], timers = []
  const ctx = {
    onDispose(fn) { disposers.push(fn); return () => {} },
    setTimeout: (fn, ms) => { const entry = { fn, ms, live: true }; timers.push(entry); return () => { entry.live = false } },
    setInterval: () => () => {},
    async rest(path, opts) {
      calls.push({ path, opts })
      if (path === '/scaffold/projects-root') return { path: '/srv/projects', source: 'setting', valid: true, default_path: '/srv/projects', message: '' }
      return restHandler(path, opts, calls)
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
  // Unmounts the page (effect cleanups, then the host's dispose callbacks); safe to call twice.
  const unmount = () => {
    const pending = [...cleanups]; cleanups.clear(); pending.forEach(fn => fn?.())
    disposers.splice(0).forEach(fn => fn?.())
  }
  t.after(() => {
    unmount()
    host.navigate = previousNavigate
    delete globalThis.__adoptTestUseState
    delete globalThis.__adoptTestUseEffect
  })
  const render = () => {
    let tree, passes = 0
    do {
      assert.ok(passes++ < 25, 'render settles')
      dirty = false
      tree = expand({ type: ui.WorkspacePage, props: { ctx, initialScreen: 'main' } })
      effects.splice(0).forEach(fn => fn())
    } while (dirty)
    return tree
  }
  const modal = () => byDomId(render(), 'new-project-dialog')
  const open = async () => { await byDomId(render(), 'start-project').props.onClick(); return modal() }
  const fireTimers = async (filter = () => true) => {
    for (const entry of timers.splice(0)) {
      if (!entry.live) continue
      if (filter(entry)) await entry.fn()
      else timers.push(entry)
    }
  }
  const typeIdea = async idea => {
    await byDomId(modal(), 'project-idea').props.onChange({ target: { value: idea } })
    await fireTimers(e => e.ms === 400)
    return modal()
  }
  return { ctx, calls, render, modal, open, fireTimers, typeIdea, timers, unmount }
}

export const radios = tree => nodes(tree, n => n.type === 'input' && n.props?.type === 'radio')
export const checkedKeys = tree => radios(tree).filter(r => r.props.checked).map(r => r.props.value)
export const radioFor = (tree, key) => radios(tree).find(r => r.props.value === key)
export const pick = async (h, key) => { await radioFor(h.modal(), key).props.onChange({ target: { value: key, checked: true } }); return h.modal() }
export const labelFor = (tree, radio) => nodes(tree, n => n.type === 'label' && n.props?.htmlFor === radio.props.id)
export const rowText = (tree, key) => textOf(labelFor(tree, radioFor(tree, key))[0])
export const matchCalls = h => h.calls.filter(c => c.path === '/scaffold/match')


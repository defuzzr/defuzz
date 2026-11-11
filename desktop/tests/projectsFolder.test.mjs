import test from 'node:test'
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'
import { catalog, checkedChoice, choiceRadios, chooseRow, typeProjectName } from './choiceList.mjs'

const nodes = (node, predicate = () => true) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]

const byId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const byTestId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)[0]
const textOf = node =>
  !node
    ? ''
    : typeof node === 'string' || typeof node === 'number'
      ? String(node)
      : [node.props?.children].flat().map(textOf).join('')
const button = (tree, label) => nodes(tree, n => (n.type === 'Button' || n.type === 'button') && textOf(n) === label)[0]

const DEFAULT_PATH = '/home/user/Tools'
const SAVED_PATH = '/home/user/Workshop'

function rootPayload(overrides = {}) {
  return {
    path: null,
    source: 'unset',
    valid: true,
    default_path: DEFAULT_PATH,
    message: 'No projects folder has been chosen yet.',
    ...overrides
  }
}

function mountHarness(t, { root, candidateFor, failRoot = false, match = { matches: [], preferred: 'none', catalog: catalog() }, holdMatch = false } = {}) {
  const instances = new Map()
  const calls = []
  const rpc = []
  const cleanups = new Set()
  const effects = []
  let slots
  let cursor
  let dirty
  let resolveHeldMatch = () => {}
  let currentRoot = rootPayload(root)
  const previousRequest = host.request
  const previousGetGateway = host.getGateway

  host.request = async (method, params) => {
    rpc.push({ method, params })
    if (method === 'plugins.manage' && params?.action === 'settings') {
      const saved = params.values?.projects_root
      currentRoot = rootPayload({
        path: saved,
        source: 'setting',
        valid: true,
        message: `Projects folder: ${saved} (saved setting)`
      })
      return { ok: true, name: 'defuzz', written: ['projects_root'] }
    }
    throw new Error(`unexpected gateway method ${method}`)
  }
  host.getGateway = () => null

  globalThis.__adoptTestUseState = init => {
    const own = slots
    const i = cursor++
    if (!(i in own)) own[i] = typeof init === 'function' ? init() : init
    return [own[i], next => {
      const value = typeof next === 'function' ? next(own[i]) : next
      if (!Object.is(value, own[i])) {
        own[i] = value
        dirty = true
      }
    }]
  }
  globalThis.__adoptTestUseEffect = (fn, deps) => {
    const own = slots
    const i = cursor++
    const old = own[i]
    if (!old || !deps || deps.length !== old.deps?.length || deps.some((dep, j) => !Object.is(dep, old.deps[j]))) {
      const effect = { deps }
      own[i] = effect
      effects.push(() => {
        old?.cleanup?.()
        cleanups.delete(old?.cleanup)
        effect.cleanup = fn()
        if (effect.cleanup) cleanups.add(effect.cleanup)
      })
    }
  }

  const disposers = []
  const ctx = {
    onDispose(fn) { disposers.push(fn); return () => {} },
    setTimeout: () => () => {},
    setInterval: () => () => {},
    async rest(path, opts) {
      calls.push({ path, opts })
      if (path === '/scaffold/match') {
        if (!holdMatch) return match
        return new Promise(resolve => { resolveHeldMatch = () => resolve(match) })
      }
      if (path === '/scaffold/discard') return { status: 'discarded' }
      if (path === '/workspace/projects') return { coverage: 'verified', projects: [] }
      if (path === '/scaffold/propose') {
        return {
          proposal_id: 'prop-1',
          tree: [{ name: 'inventory-api', dest: `${DEFAULT_PATH}/inventory-api`, files: ['AGENTS.md'] }]
        }
      }
      if (path === '/scaffold/accept') {
        return {
          ok: true,
          status: 'created',
          repos: [{
            name: 'inventory-api',
            path: `${DEFAULT_PATH}/inventory-api`,
            registration: 'registered',
            registration_result: { registered: true }
          }]
        }
      }
      if (path === '/scaffold/projects-root' || path.startsWith('/scaffold/projects-root?')) {
        if (failRoot) throw new Error('backend unreachable')
        const query = path.includes('?') ? new URL(path, 'http://defuzz.local').searchParams : null
        const candidate = query ? query.get('candidate') : null
        const payload = { ...currentRoot }
        if (candidate !== null) {
          payload.candidate = candidateFor
            ? candidateFor(candidate)
            : { valid: true, path: candidate, message: '' }
        }
        return payload
      }
      return {}
    }
  }

  function expand(node, path = 'root') {
    if (!node || typeof node !== 'object') return node
    if (typeof node.type === 'function') {
      if (!instances.has(path)) instances.set(path, [])
      slots = instances.get(path)
      cursor = 0
      return expand(node.type(node.props), path + '.render')
    }
    return {
      ...node,
      props: {
        ...node.props,
        children: [node.props?.children].flat().map((child, i) => expand(child, path + '.' + i))
      }
    }
  }

  t.after(() => {
    cleanups.forEach(fn => fn?.())
    disposers.forEach(fn => fn?.())
    host.request = previousRequest
    host.getGateway = previousGetGateway
    delete globalThis.__adoptTestUseState
    delete globalThis.__adoptTestUseEffect
  })

  return {
    ctx,
    calls,
    rpc,
    setRoot(next) { currentRoot = rootPayload(next) },
    releaseMatch() { resolveHeldMatch() },
    render() {
      let tree
      let passes = 0
      do {
        assert.ok(passes++ < 25, 'render settles')
        dirty = false
        tree = expand({ type: ui.WorkspacePage, props: { ctx, initialScreen: 'main' } })
        effects.splice(0).forEach(fn => fn())
      } while (dirty)
      return tree
    }
  }
}

async function openStart(h) {
  let tree = h.render()
  await byId(tree, 'start-project').props.onClick({ currentTarget: { focus() {} } })
  return h.render()
}

const scaffoldCalls = calls => calls.filter(c => c.path === '/scaffold/propose' || c.path === '/scaffold/accept')

test('unset projects folder asks before any create and sends no scaffold request', async t => {
  const h = mountHarness(t)
  const tree = await openStart(h)
  const dialog = byId(tree, 'projects-folder-dialog')
  assert.ok(dialog, 'folder dialog appears when the projects folder is not chosen')
  assert.equal(textOf(byId(dialog, 'projects-folder-title')), 'Where should your projects go?')
  assert.match(textOf(dialog), /Choose the folder where Defuzz creates new projects\. Only new projects go here; nothing else on your machine is touched, and the folder is created when you create your first project\./)
  assert.equal(byId(dialog, 'projects-folder-input').props.value, DEFAULT_PATH)
  assert.match(textOf(dialog), /Type a full path, or keep the suggestion\./)
  assert.equal(scaffoldCalls(h.calls).length, 0)
  assert.equal(h.rpc.length, 0)
})

test('a refused folder shows the backend message as text and keeps the dialog open', async t => {
  const nasty = 'Refused: <script>alert(1)</script>\u0000\u0007'
  const h = mountHarness(t, {
    candidateFor: () => ({ valid: false, path: null, message: nasty })
  })
  let tree = await openStart(h)
  await button(byId(tree, 'projects-folder-dialog'), 'Use this folder').props.onClick()
  tree = h.render()
  const dialog = byId(tree, 'projects-folder-dialog')
  assert.ok(dialog, 'dialog stays open after a refusal')
  const alert = nodes(dialog, n => n.props?.role === 'alert')[0]
  assert.ok(alert, 'refusal is announced')
  assert.equal(textOf(alert), nasty)
  assert.equal(nodes(dialog, n => n.type === 'script').length, 0)
  assert.equal(alert.type === 'script', false)
  assert.equal(h.rpc.length, 0)
  assert.equal(scaffoldCalls(h.calls).length, 0)
})

test('choosing a folder validates, saves through Hermes, re-reads, then continues the create that was started', async t => {
  const h = mountHarness(t)
  let tree = await openStart(h)
  assert.equal(scaffoldCalls(h.calls).length, 0, 'no scaffold before the folder is chosen')
  const modal = byId(tree, 'new-project-dialog')
  await typeProjectName(modal, 'inventory-api')
  await chooseRow(modal, 'template:python-golden')
  tree = h.render()
  await byId(byId(tree, 'new-project-dialog'), 'accept-project').props.onClick()
  tree = h.render()
  assert.equal(scaffoldCalls(h.calls).length, 0, 'Accept & create waits for the folder')
  assert.ok(byId(tree, 'projects-folder-dialog'))
  await button(byId(tree, 'projects-folder-dialog'), 'Use this folder').props.onClick()
  tree = h.render()

  const rootCalls = h.calls.filter(c => c.path.startsWith('/scaffold/projects-root'))
  assert.ok(rootCalls.some(c => c.path.includes('candidate=')), 'validates through the candidate query')
  assert.equal(h.rpc.length, 1)
  assert.deepEqual(h.rpc[0], {
    method: 'plugins.manage',
    params: { action: 'settings', key: 'defuzz', values: { projects_root: DEFAULT_PATH } }
  })
  const validateAt = h.calls.findIndex(c => c.path.includes('candidate='))
  const rereadAt = h.calls.findIndex((c, i) => i > validateAt && c.path === '/scaffold/projects-root')
  const proposeAt = h.calls.findIndex(c => c.path === '/scaffold/propose')
  assert.ok(validateAt >= 0 && rereadAt > validateAt && proposeAt > rereadAt, 'validate, then re-read, then create')
  assert.ok(h.calls.some(c => c.path === '/scaffold/accept'), 'original create continues after the folder is saved')
  assert.equal(byId(tree, 'projects-folder-dialog'), undefined, 'folder dialog closes after save')
  const propose = h.calls.find(c => c.path === '/scaffold/propose')
  assert.equal(propose.opts.body.template_id, 'python-golden')
})

test('Cancel and Escape save nothing and create nothing', async t => {
  const h = mountHarness(t)
  let tree = await openStart(h)
  const opener = { focus() { opener.focused = (opener.focused || 0) + 1 } }
  await byId(h.render(), 'start-project').props.onClick({ currentTarget: opener })
  tree = h.render()
  button(byId(tree, 'projects-folder-dialog'), 'Cancel').props.onClick()
  tree = h.render()
  assert.equal(byId(tree, 'projects-folder-dialog'), undefined)
  assert.ok(byId(tree, 'new-project-dialog'), 'new-project modal stays as it was')
  assert.equal(h.rpc.length, 0)
  assert.equal(scaffoldCalls(h.calls).length, 0)

  await byId(tree, 'start-project').props.onClick({ currentTarget: opener })
  tree = h.render()
  byId(tree, 'projects-folder-dialog').props.onKeyDown({ key: 'Escape', preventDefault() {} })
  tree = h.render()
  assert.equal(byId(tree, 'projects-folder-dialog'), undefined)
  assert.equal(h.rpc.length, 0)
  assert.equal(scaffoldCalls(h.calls).length, 0)
  assert.ok(opener.focused >= 1, 'Escape returns focus to the element that opened the dialog')
})

test('saved or environment folder is shown read-only and Change opens the same dialog', async t => {
  for (const source of ['setting', 'env']) {
    const h = mountHarness(t, { root: { path: SAVED_PATH, source, message: `Projects folder: ${SAVED_PATH}` } })
    const tree = await openStart(h)
    assert.equal(byId(tree, 'projects-folder-dialog'), undefined, `${source} does not ask again`)
    const line = byId(byId(tree, 'new-project-dialog'), 'projects-folder-current')
    assert.match(textOf(line), new RegExp(`Projects folder: ${SAVED_PATH}`))
    byId(line, 'projects-folder-change').props.onClick({ currentTarget: { focus() {} } })
    const next = h.render()
    const dialog = byId(next, 'projects-folder-dialog')
    assert.ok(dialog, 'Change opens the folder dialog')
    assert.equal(byId(dialog, 'projects-folder-input').props.value, SAVED_PATH)
    assert.match(textOf(dialog), /Existing projects stay where they are; only new projects will be created in this folder\./)
    assert.equal(scaffoldCalls(h.calls).length, 0)
  }
})

test('backend failure disables create and does not guess a folder', async t => {
  const h = mountHarness(t, { failRoot: true })
  const tree = await openStart(h)
  assert.equal(byId(tree, 'projects-folder-dialog'), undefined)
  const modal = byId(tree, 'new-project-dialog')
  assert.match(textOf(modal), /Could not read the projects folder/)
  assert.equal(byId(modal, 'accept-project').props.disabled, true)
  await byId(modal, 'accept-project').props.onClick()
  assert.equal(scaffoldCalls(h.calls).length, 0)
  assert.equal(nodes(modal, n => n.props?.value === DEFAULT_PATH).length, 0)
})

test('folder dialog keeps focus inside, binds its label, and fits a narrow panel', async t => {
  const h = mountHarness(t)
  const opener = { focus() { opener.focused = (opener.focused || 0) + 1 } }
  let tree = h.render()
  await byId(tree, 'start-project').props.onClick({ currentTarget: opener })
  tree = h.render()
  const dialog = byId(tree, 'projects-folder-dialog')
  const input = byId(dialog, 'projects-folder-input')
  const label = nodes(dialog, n => n.type === 'label' && n.props?.htmlFor === 'projects-folder-input')[0]
  assert.ok(label, 'input has a bound label')
  assert.equal(input.props.autoFocus, true)
  assert.equal(input.props['data-initial-focus'], 'true')
  assert.equal(dialog.props.role, 'dialog')
  assert.equal(dialog.props['aria-modal'], 'true')
  assert.match(String(dialog.props.style?.width || ''), /min\(|100%/)
  assert.equal(dialog.props.style?.animation, undefined)
  assert.equal(dialog.props.style?.transition, undefined)

  let firstFocused = 0
  let lastFocused = 0
  const firstEl = { disabled: false, tabIndex: 0, focus() { firstFocused += 1 } }
  const lastEl = { disabled: false, tabIndex: 0, focus() { lastFocused += 1 } }
  dialog.props.onKeyDown({
    key: 'Tab',
    shiftKey: false,
    target: lastEl,
    currentTarget: { querySelectorAll: () => [firstEl, lastEl] },
    preventDefault() {}
  })
  dialog.props.onKeyDown({
    key: 'Tab',
    shiftKey: true,
    target: firstEl,
    currentTarget: { querySelectorAll: () => [firstEl, lastEl] },
    preventDefault() {}
  })
  assert.equal(firstFocused, 1, 'Tab on the last control wraps to the first')
  assert.equal(lastFocused, 1, 'Shift+Tab on the first control wraps to the last')
  assert.equal(byTestId(tree, 'projects-folder-dialog'), undefined)
})

test('opening the new-project modal creates nothing before a row is chosen, while the list loads or after it arrives', async t => {
  const held = mountHarness(t, { root: { path: SAVED_PATH, source: 'setting' }, holdMatch: true })
  let tree = held.render()
  const opening = byId(tree, 'start-project').props.onClick({ currentTarget: { focus() {} } })
  tree = held.render()
  let modal = byId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), '', 'nothing is chosen before the list arrives')
  assert.equal(choiceRadios(modal).length, 0, 'no rows before the server sends the list')
  assert.equal(byId(modal, 'accept-project').props.disabled, true)
  await byId(modal, 'accept-project').props.onClick()
  assert.equal(held.calls.some(c => c.path === '/scaffold/propose'), false, 'Accept before the matcher returns does not create a TypeScript project')
  held.releaseMatch()
  await opening

  const h = mountHarness(t, { root: { path: SAVED_PATH, source: 'setting' } })
  tree = await openStart(h)
  modal = byId(tree, 'new-project-dialog')
  assert.equal(choiceRadios(modal).length > 0, true, 'the list is shown')
  assert.equal(checkedChoice(modal), '', 'the list arriving selects nothing')
  assert.equal(byId(modal, 'accept-project').props.disabled, true)
  await byId(modal, 'accept-project').props.onClick()
  assert.equal(h.calls.some(c => c.path === '/scaffold/propose' && c.opts?.body?.template_id === 'ts-node-golden'), false)

  const idea = byId(modal, 'project-idea')
  idea.props.onChange({ target: { value: '' } })
  tree = h.render()
  modal = byId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), '')
  await byId(modal, 'accept-project').props.onClick()
  assert.equal(scaffoldCalls(h.calls).length, 0, 'empty prompt does not create a project')
})

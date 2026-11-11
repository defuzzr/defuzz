import test from 'node:test'
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'

const nodes = (node, predicate = () => true) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]

const byTestId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)[0]
const allTestId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)
const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const textOf = node =>
  !node
    ? ''
    : typeof node === 'string' || typeof node === 'number'
      ? String(node)
      : [node.props?.children].flat().map(textOf).join('')
const buttonText = (tree, label) => nodes(tree, n => (n.type === 'Button' || n.type === 'button') && textOf(n) === label)[0]

function deferred() {
  let resolve, reject
  const promise = new Promise((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve() }

function mountHarness(t, { routes = {}, requestFolder } = {}) {
  const instances = new Map()
  const calls = []
  const effects = []
  const cleanups = new Set()
  const fileCalls = []
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
    files: {
      async requestFolder() {
        fileCalls.push(['requestFolder'])
        return typeof requestFolder === 'function' ? requestFolder() : null
      },
      async readText(...args) { fileCalls.push(['readText', ...args]); return { ok: false } },
      async list(...args) { fileCalls.push(['list', ...args]); return { ok: false } }
    },
    async rest(path, opts) {
      calls.push({ path, opts })
      const key = String(path).split('?')[0]
      const handler = routes[path] || routes[key]
      if (handler === undefined) return {}
      if (handler instanceof Error) throw handler
      const value = typeof handler === 'function' ? await handler(path, opts) : handler
      if (value instanceof Error) throw value
      return value
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
    fileCalls,
    render() {
      let tree, passes = 0
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

const projectRecord = (name, path, extra = {}) => ({
  raw_path: path,
  canonical_path: path,
  name,
  template_id: 'existing',
  languages: [],
  registered: true,
  ...extra
})

const availableProject = (id, name, path) => ({
  id,
  name,
  slug: name,
  path,
  primary_path: path,
  folders: [{ path, label: null, is_primary: true, exists: true }],
  description: null,
  icon: null,
  color: null,
  board_slug: null
})

async function openDialog(h) {
  const tree = h.render()
  const opener = byTestId(tree, 'open-existing-project-btn') || byDomId(tree, 'open-existing-project')
  assert.ok(opener, 'top toolbar offers Open existing project')
  await opener.props.onClick({ currentTarget: { focus() {} } })
  return h.render()
}

async function refresh(h) {
  const tree = h.render()
  await buttonText(tree, 'Refresh projects').props.onClick()
  return h.render()
}

const POST = path => ({ method: 'POST', body: path })

test('existing-project dialog declares initial focus, wraps Tab, and restores its opener after Escape', async t => {
  const h = mountHarness(t)
  let focused = 'opener'
  const opener = { focus() { focused = 'opener' } }
  const initialTree = h.render()
  await byTestId(initialTree, 'open-existing-project-btn').props.onClick({ currentTarget: opener })
  const tree = h.render()
  const dialog = byTestId(tree, 'open-existing-modal')
  const initial = nodes(dialog, n => n.props?.autoFocus === true && n.props?.['data-initial-focus'] === 'true')
  assert.equal(initial.length, 1, 'one SDK initial-focus target is declared')
  assert.equal(initial[0].props['aria-label'], 'Close open existing project dialog')
  assert.equal(initial[0].props.disabled, false)
  assert.equal(byTestId(tree, 'v10-top-bar').props.inert, true)

  const first = { tabIndex: 0, focus() { focused = 'first' } }
  const disabled = { tabIndex: 0, disabled: true, focus() { assert.fail('disabled control must not receive focus') } }
  const last = { tabIndex: 0, focus() { focused = 'last' } }
  const currentTarget = { querySelectorAll() { return [first, last, disabled] } }
  let prevented = 0
  const preventDefault = () => { prevented++ }
  dialog.props.onKeyDown({ key: 'Tab', target: last, currentTarget, preventDefault })
  assert.equal(focused, 'first', 'Tab wraps from last enabled control')
  dialog.props.onKeyDown({ key: 'Tab', shiftKey: true, target: first, currentTarget, preventDefault })
  assert.equal(focused, 'last', 'Shift+Tab wraps from first enabled control')
  dialog.props.onKeyDown({ key: 'Escape', preventDefault })
  assert.equal(focused, 'last', 'restoration waits until the inert toolbar is rendered active')
  const closed = h.render()
  assert.equal(byTestId(closed, 'open-existing-modal'), undefined)
  assert.equal(byTestId(closed, 'v10-top-bar').props.inert, undefined)
  assert.equal(focused, 'opener')
  assert.equal(prevented, 3)
})

test('existing-project radios have accessible names containing both project name and distinguishing backend path', async t => {
  const projects = [availableProject('one', 'app', '/srv/one/app'), availableProject('two', 'app', '/srv/two/app')]
  const h = mountHarness(t, { routes: { '/workspace/available-projects': { coverage: 'verified', projects } } })
  const tree = await openDialog(h)
  const radios = allTestId(tree, 'existing-project-select')
  assert.equal(radios.length, projects.length)
  const names = radios.map((radio, index) => {
    const name = radio.props['aria-label'] || ''
    assert.ok(name.includes(projects[index].name), 'radio announces the project name')
    assert.ok(name.includes(projects[index].path), 'radio announces the full backend path')
    return name
  })
  assert.equal(new Set(names).size, projects.length, 'same-name projects remain distinguishable')
  radios[1].props.onChange()
  const selected = allTestId(h.render(), 'existing-project-select')
  assert.deepEqual(selected.map(radio => radio.props.checked), [false, true])
})

test('render sends no scan, no open, no lint, and no file reads', t => {
  const h = mountHarness(t)
  h.render()
  assert.equal(h.calls.length, 0, 'mounting never scans Hermes projects')
  assert.equal(h.fileCalls.length, 0, 'mounting never asks for folder grants')
})

test('opening an existing Hermes project verifies the list, selects the canonical path, loads a bounded tree, and audits that same path', async t => {
  const openedPath = '/home/user/Tools/invoice'
  const h = mountHarness(t, {
    routes: {
      '/workspace/available-projects': { coverage: 'verified', projects: [availableProject('hp-1', 'invoice', openedPath)] },
      '/workspace/projects/open': { status: 'opened', project: { path: openedPath, name: 'invoice', slug: 'invoice', template_id: 'existing' } },
      '/workspace/projects': { coverage: 'verified', projects: [projectRecord('invoice', openedPath)], unavailable_projects: [] },
      '/workspace/tree': { files: ['AGENTS.md', 'src/index.ts'], coverage: 'verified', truncated: false, omitted: 0 },
      '/audit/scope': { scope_disclosure: 'Audit scope disclosure text.' },
      '/audit/start': { run_id: 'run-1', status: 'completed' },
      '/audit/status': { status: 'completed', report: { coverage: 'verified' } },
      '/audit/report': { coverage: 'verified', findings: [] },
      '/audit/summary': { text: 'Summary text.', summary: { sections: [] } }
    }
  })

  let tree = await openDialog(h)
  assert.equal(h.calls.filter(c => c.path === '/workspace/available-projects').length, 1, 'list is fetched explicitly once on open')
  assert.equal(h.calls.filter(c => c.path === '/scaffold/match').length, 0, 'dialog does not use the creation picker')
  const dialog = byTestId(tree, 'open-existing-modal')
  assert.ok(dialog)
  const copy = textOf(dialog)
  assert.match(copy, /Opening adds a reference only/)
  assert.match(copy, /Audit is read-only/)
  assert.match(copy, /lint can execute repository code and write files/)
  assert.match(copy, /invoice/)
  assert.match(copy, new RegExp(openedPath.replace(/[/\\]/g, '\\$&')))

  const row = allTestId(dialog, 'existing-project-row')[0]
  assert.equal(row.props['data-path'], openedPath)
  allTestId(row, 'existing-project-select')[0].props.onChange()
  tree = h.render()
  await byTestId(tree, 'open-existing-confirm').props.onClick()
  await flush()
  tree = h.render()

  const post = h.calls.filter(c => c.path === '/workspace/projects/open')[0]
  assert.deepEqual(post.opts, POST({ path: openedPath, hermes_project_id: 'hp-1' }), 'POST carries the exact folder and core project id')
  assert.ok(h.calls.some(c => c.path === '/workspace/projects'), 'the project list is re-read to verify the reference')
  const card = nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] === 'invoice')[0]
  assert.equal(card.props['aria-pressed'], true, 'the canonical opened path is selected')
  assert.ok(h.calls.some(c => c.path === `/workspace/tree?project=${encodeURIComponent(openedPath)}`), 'selection reads the bounded tree')
  assert.ok(nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'AGENTS.md').length > 0)
  assert.ok(nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'src/index.ts').length > 0, 'real file rows come from the tree response')
  assert.equal(byTestId(tree, 'file-listing-unavailable'), undefined)

  await byTestId(tree, 'audit-full-button').props.onClick({ currentTarget: { focus() {} } })
  tree = h.render()
  byTestId(tree, 'audit-review-consent').props.onChange({ target: { checked: true } })
  tree = h.render()
  await byTestId(tree, 'audit-review-run').props.onClick()
  tree = h.render()
  const start = h.calls.filter(c => c.path === '/audit/start')[0]
  assert.deepEqual(start.opts, { method: 'POST', body: { selected_projects: [openedPath] } }, 'audit consent scope keeps the opened path')

  const forbidden = h.calls.filter(c => ['/lint', '/tools/status', '/scaffold/accept', '/componentize/settings', '/workspace/projects/forget'].includes(c.path))
  assert.deepEqual(forbidden, [], 'opening never lints, installs, adopts or forgets')
  assert.equal(h.fileCalls.length, 0, 'opening never reads local files through the picker')
})

test('manual absolute backend path works without a project id, and backend rejection is shown without selecting or claiming success', async t => {
  const manualPath = '/srv/shared/app'
  let rejectOnce = true
  const h = mountHarness(t, {
    routes: {
      '/workspace/available-projects': { coverage: 'verified', projects: [] },
      '/workspace/projects/open': (path, opts) => {
        if (rejectOnce) {
          rejectOnce = false
          throw new Error('400: {"detail":"existing project is not an existing directory"}')
        }
        return { status: 'opened', project: { path: manualPath, name: 'app', template_id: 'existing' } }
      },
      '/workspace/projects': { coverage: 'verified', projects: [projectRecord('app', manualPath)], unavailable_projects: [] },
      '/workspace/tree': { files: ['README.md'], coverage: 'verified', truncated: false, omitted: 0 }
    }
  })

  let tree = await openDialog(h)
  const input = byTestId(tree, 'open-existing-path')
  assert.ok(input, 'manual backend path input exists')
  assert.match(textOf(byTestId(tree, 'open-existing-dialog-hint')), /backend/i)

  input.props.onChange({ target: { value: '/not-absolute' } })
  tree = h.render()
  await byTestId(tree, 'open-existing-confirm').props.onClick()
  await flush()
  tree = h.render()
  assert.equal(h.calls.filter(c => c.path === '/workspace/projects/open').length, 1, 'invalid request is sent for authority validation')
  assert.match(textOf(byTestId(tree, 'open-existing-error')), /not an existing directory/)
  assert.equal(nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] !== undefined).length, 0, 'nothing is selected after a rejection')

  byTestId(tree, 'open-existing-path').props.onChange({ target: { value: manualPath } })
  tree = h.render()
  await byTestId(tree, 'open-existing-confirm').props.onClick()
  await flush()
  tree = h.render()
  const posts = h.calls.filter(c => c.path === '/workspace/projects/open')
  assert.deepEqual(posts[1].opts, POST({ path: manualPath }), 'a manually typed path is sent alone, with no invented project id')
  assert.equal(nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] === 'app')[0].props['aria-pressed'], true)
})

test('unverified discovery is reported honestly and leaves the manual path available', async t => {
  const h = mountHarness(t, {
    routes: {
      '/workspace/available-projects': { coverage: 'could_not_verify', error: 'core projects registry corrupt', projects: [] }
    }
  })
  const tree = await openDialog(h)
  const dialog = byTestId(tree, 'open-existing-modal')
  assert.match(textOf(dialog), /could not verify/i)
  assert.match(textOf(dialog), /core projects registry corrupt/)
  assert.equal(allTestId(dialog, 'existing-project-row').length, 0, 'no rows are claimed from an unverified registry')
  assert.ok(byTestId(tree, 'open-existing-path'), 'manual entry remains possible')
  assert.equal(h.calls.filter(c => c.path === '/workspace/projects/open').length, 0)
})

test('Browse uses only the picked local path, and a cancelled picker changes nothing and reads no files', async t => {
  let picker = null
  const h = mountHarness(t, { requestFolder: () => picker, routes: { '/workspace/available-projects': { coverage: 'verified', projects: [] } } })
  let tree = await openDialog(h)

  await byTestId(tree, 'open-existing-browse').props.onClick()
  tree = h.render()
  assert.equal(h.fileCalls.length, 1, 'one picker request on an explicit Browse click')
  assert.equal(byTestId(tree, 'open-existing-path').props.value, '', 'Cancel leaves the field untouched')
  assert.equal(h.calls.filter(c => c.path === '/workspace/projects/open').length, 0)

  picker = { ok: true, folder: { id: 'grant-123', name: 'app', path: '/home/user/Tools/app' } }
  await byTestId(tree, 'open-existing-browse').props.onClick()
  tree = h.render()
  assert.equal(byTestId(tree, 'open-existing-path').props.value, '/home/user/Tools/app')
  assert.match(textOf(byTestId(tree, 'open-existing-browse-note')), /backend/)
  assert.equal(h.fileCalls.length, 2)
  assert.equal(h.fileCalls.filter(c => c[0] !== 'requestFolder').length, 0, 'the grant is never used to read files')
})

test('tree truncation, coverage and errors are visible; no fabricated rows are shown', async t => {
  const path = '/home/user/Tools/app'
  let treeReply = { files: ['only.ts'], coverage: 'could_not_verify', truncated: true, omitted: 120 }
  const h = mountHarness(t, {
    routes: {
      '/workspace/available-projects': { coverage: 'verified', projects: [availableProject('hp-2', 'app', path)] },
      '/workspace/projects/open': { status: 'opened', project: { path, name: 'app', template_id: 'existing' } },
      '/workspace/projects': { coverage: 'verified', projects: [projectRecord('app', path)], unavailable_projects: [] },
      '/workspace/tree': () => treeReply
    }
  })

  let rendered = await openDialog(h)
  allTestId(byTestId(rendered, 'open-existing-modal'), 'existing-project-select')[0].props.onChange()
  rendered = h.render()
  await byTestId(rendered, 'open-existing-confirm').props.onClick()
  await flush()
  rendered = h.render()
  const notice = textOf(byTestId(rendered, 'project-tree-notice'))
  assert.match(notice, /truncated/i)
  assert.match(notice, /120/)
  assert.match(notice, /could not be verified/i)
  assert.ok(nodes(byDomId(rendered, 'tree'), n => n.props?.['data-path'] === 'only.ts').length > 0)

  treeReply = new Error('400: {"detail":"Project is not registered in the active profile"}')
  await byTestId(rendered, 'tree-reload').props.onClick()
  rendered = h.render()
  assert.match(textOf(byTestId(rendered, 'project-tree-notice')), /Project is not registered/)
  assert.equal(nodes(byDomId(rendered, 'tree'), n => n.props?.['data-path']).length, 0, 'an error never falls back to invented file names')
  assert.match(textOf(byDomId(rendered, 'tree')), /unavailable/i)
})

test('stale tree replies never replace the current project, and switching projects cancels the earlier read', async t => {
  const a = '/home/user/Tools/alpha'
  const b = '/home/user/Tools/beta'
  const da = deferred()
  const db = deferred()
  const h = mountHarness(t, {
    routes: {
      '/workspace/projects': { coverage: 'verified', projects: [projectRecord('alpha', a), projectRecord('beta', b)], unavailable_projects: [] },
      '/workspace/tree': path => (String(path).includes(encodeURIComponent(a)) ? da.promise : db.promise)
    }
  })
  let tree = await refresh(h)
  nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] === 'alpha')[0].props.onClick()
  tree = h.render()
  nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] === 'beta')[0].props.onClick()
  tree = h.render()

  da.resolve({ files: ['stale-alpha.ts'], coverage: 'verified', truncated: false, omitted: 0 })
  await flush()
  tree = h.render()
  assert.equal(nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'stale-alpha.ts').length, 0, 'alpha reply is discarded under beta')

  db.resolve({ files: ['beta.ts'], coverage: 'verified', truncated: false, omitted: 0 })
  await flush()
  tree = h.render()

  assert.ok(nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'beta.ts').length > 0)
  assert.equal(nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'stale-alpha.ts').length, 0)
})

test('lint on an adopted existing project waits for explicit confirmation in the footer and the inspector', async t => {
  const path = '/home/user/Tools/app'
  const h = mountHarness(t, {
    routes: {
      '/workspace/available-projects': { coverage: 'verified', projects: [availableProject('hp-3', 'app', path)] },
      '/workspace/projects/open': { status: 'opened', project: { path, name: 'app', template_id: 'existing' } },
      '/workspace/projects': { coverage: 'verified', projects: [projectRecord('app', path)], unavailable_projects: [] },
      '/workspace/tree': { files: ['README.md'], coverage: 'verified', truncated: false, omitted: 0 },
      '/lint': { state: 'done', ok: true, findings: [] }
    }
  })
  let tree = await openDialog(h)
  allTestId(byTestId(tree, 'open-existing-modal'), 'existing-project-select')[0].props.onChange()
  tree = h.render()
  await byTestId(tree, 'open-existing-confirm').props.onClick()
  await flush()
  tree = h.render()

  await byTestId(tree, 'footer-lint-play').props.onClick()
  tree = h.render()
  assert.equal(h.calls.filter(c => c.path === '/lint').length, 0, 'first footer click explains instead of running')
  assert.match(textOf(byTestId(tree, 'audit-status-notice')), /execute repository code/i)
  await byTestId(tree, 'footer-lint-play').props.onClick()
  tree = h.render()
  assert.deepEqual(h.calls.filter(c => c.path === '/lint')[0].opts, POST({ project: path, mode: 'both' }), 'second footer click runs lint for the selected existing path')

  const manualRun = buttonText(byDomId(tree, 'workspace'), 'Run lint')
  await manualRun.props.onClick()
  tree = h.render()
  assert.equal(h.calls.filter(c => c.path === '/lint').length, 1, 'first inspector click explains instead of running')
  assert.match(textOf(byTestId(tree, 'manual-lint-confirm')), /execute repository code/i)
  await buttonText(byDomId(tree, 'workspace'), 'Confirm and run lint').props.onClick()
  assert.equal(h.calls.filter(c => c.path === '/lint').length, 2, 'confirmed inspector click runs lint')
})

test('no selected project shows an honest empty editor instead of a template placeholder', t => {
  const h = mountHarness(t)
  const tree = h.render()
  assert.match(textOf(byDomId(tree, 'active-project-title')), /No project selected/)
  const editor = textOf(byDomId(tree, 'editor'))
  assert.doesNotMatch(editor, /ts-node-golden/, 'no fabricated template name in the editor')
  assert.match(editor, /Select a file/i)
})

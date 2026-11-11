import test from 'node:test'
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'
import { catalog } from './choiceList.mjs'

const nodes = (node, predicate = () => true) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]

const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const byTestId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)[0]
const allTestId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)
const textOf = node =>
  !node
    ? ''
    : typeof node === 'string' || typeof node === 'number'
      ? String(node)
      : [node.props?.children].flat().map(textOf).join('')

const present = (name, path, extra = {}) => ({ name, path, registered: true, ...extra })
const gone = (name, path, folder_status, extra = {}) => ({ name, path, folder_status, registered: true, ...extra })

function payload(overrides = {}) {
  return {
    coverage: 'verified',
    projects: [
      present('invoice-tracker', '/home/user/Tools/invoice-tracker', { template_id: 'ts-node-golden' }),
      present('py', '/home/user/Tools/py-copy', { language: 'typescript' }),
      present('data-tools', '/home/user/Tools/data-tools', { template_id: 'python-golden' })
    ],
    unavailable_projects: [
      gone('copy', '/home/user/.hermes/cache/scratch/copy-1', 'missing'),
      gone('old-api', '/home/user/Tools/old-api', 'not_directory'),
      gone('elsewhere', '/mnt/offline/elsewhere', 'unavailable')
    ],
    ...overrides
  }
}

function mountHarness(t, { payloads = [payload()], forget } = {}) {
  const instances = new Map()
  const calls = []
  const effects = []
  const cleanups = new Set()
  let slots, cursor, dirty
  let payloadIndex = 0
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
    async rest(path, opts) {
      calls.push({ path, opts })
      if (path === '/workspace/projects') {
        const next = payloads[Math.min(payloadIndex, payloads.length - 1)]
        payloadIndex += 1
        return typeof next === 'function' ? next() : next
      }
      if (path === '/workspace/projects/forget') {
        if (forget) return forget(opts)
        return { status: 'forgotten' }
      }
      if (path === '/scaffold/projects-root' || String(path).startsWith('/scaffold/projects-root?')) {
        return { path: '/home/user/Tools', source: 'setting', valid: true, default_path: '/home/user/Tools', message: '' }
      }
      if (path === '/scaffold/match') return { matches: [], closest: [], catalog: catalog() }
      if (path === '/scaffold/discard') return { status: 'discarded' }
      return {}
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
    async open() {
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

async function refresh(h) {
  const tree = await h.open()
  const button = nodes(tree, n => (n.type === 'Button' || n.type === 'button') && textOf(n) === 'Refresh projects')[0]
  await button.props.onClick()
  return h.open()
}

const forgetCalls = h => h.calls.filter(c => c.path === '/workspace/projects/forget')
const projectCalls = h => h.calls.filter(c => c.path === '/workspace/projects')

test('project strip lists only current directories, names only, and a copy folder is not tagged Python', async t => {
  const h = mountHarness(t)
  const tree = await refresh(h)

  assert.match(textOf(byDomId(tree, 'project-count')), /^3$/, 'count covers only existing directories')
  const strip = byTestId(tree, 'v10-project-strip')
  assert.ok(strip, 'project strip exists')
  const cards = nodes(strip, n => n.props?.['data-project'] !== undefined)
  assert.deepEqual(cards.map(c => c.props['data-project']), ['invoice-tracker', 'py', 'data-tools'])
  assert.deepEqual(cards.map(c => textOf(c)), ['invoice-tracker', 'py', 'data-tools'], 'visible name holds no badge or status text')
  assert.equal(nodes(strip, n => n.props?.className === 'project-symbol').length, 0, 'no language badge rendered in the strip')
  assert.equal(cards[1].props['data-template'], 'ts-node-golden', 'name/path tokens such as "py" do not imply Python')
  assert.equal(cards[2].props['data-template'], 'python-golden', 'template metadata still drives filtering')
  assert.equal(cards[0].props.title, '/home/user/Tools/invoice-tracker', 'full path is available as a title for duplicate names')
})

test('badge classification reads template/language metadata only, never names or paths', () => {
  assert.equal(ui.projectBadgeFor({ name: 'copy', path: '/tmp/py-copy', languages: ['rust'] }).template, 'rust-golden')
  assert.equal(ui.projectBadgeFor({ template_id: 'go-golden' }).template, 'go-golden')
  assert.equal(ui.projectBadgeFor({ template_id: 'web-golden' }).template, 'web-golden')
  assert.equal(ui.projectBadgeFor({ languages: ['c++'] }).template, 'cpp-golden')
  assert.equal(ui.projectBadgeFor({ language: 'c#' }).template, 'dotnet-golden')
  assert.equal(ui.projectBadgeFor({ language: 'python' }).template, 'python-golden')
  assert.equal(ui.projectBadgeFor({ template_id: 'ts-node-golden' }).template, 'ts-node-golden')
  assert.equal(ui.projectBadgeFor({ language: 'typescript' }).template, 'ts-node-golden')
  assert.equal(ui.projectBadgeFor({ languages: ['ts', 'node'] }).template, 'ts-node-golden')
  assert.equal(ui.projectBadgeFor({ stack: 'node' }).template, 'ts-node-golden')
  // Unknown metadata is not evidence of TypeScript. Name/path tokens are user data.
  assert.equal(ui.projectBadgeFor({ name: 'python-copy', path: '/x/python-copy' }).template, 'unknown')
  assert.equal(ui.projectBadgeFor({ name: 'py' }).template, 'unknown')
  assert.equal(ui.projectBadgeFor({ name: 'cargo-copy' }).template, 'unknown')
  assert.equal(ui.projectBadgeFor({ name: 'go-old' }).template, 'unknown')
  assert.equal(ui.projectBadgeFor({ name: 'copy', kind: 'adopted' }).template, 'unknown')
  assert.equal(ui.projectBadgeFor({ name: 'kit', kind: 'kit', adopted: true }).template, 'unknown')
  assert.equal(ui.projectBadgeFor({ languages: ['unknown'] }).template, 'unknown')
  assert.equal(ui.projectBadgeFor({}).template, 'unknown')
  assert.equal(ui.projectBadgeFor({}).badge, '?')
})

test('unknown project metadata stays unknown in the strip instead of inheriting TypeScript', async t => {
  const h = mountHarness(t, { payloads: [payload({
    projects: [
      present('copy', '/home/user/Tools/copy'),
      present('ts-app', '/home/user/Tools/ts-app', { template_id: 'ts-node-golden' })
    ],
    unavailable_projects: []
  })] })
  const tree = await refresh(h)
  const cards = nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] !== undefined)
  assert.deepEqual(cards.map(c => c.props['data-template']), ['unknown', 'ts-node-golden'], 'only explicit TS metadata is TypeScript')
  assert.equal(textOf(cards[0]), 'copy', 'name-only labels are preserved')
})

test('Manage projects shows every record with name, path and folder status, and never counts missing ones as current', async t => {
  const h = mountHarness(t)
  let tree = await refresh(h)

  const toggle = byTestId(tree, 'manage-projects-toggle')
  assert.ok(toggle, 'Manage projects toggle exists')
  assert.equal(byTestId(tree, 'manage-projects-panel'), undefined, 'panel closed by default')
  assert.equal(toggle.props['aria-expanded'], false)
  toggle.props.onClick()
  tree = await h.open()

  const panel = byTestId(tree, 'manage-projects-panel')
  assert.ok(panel, 'panel opens inline')
  const panelText = textOf(panel)
  for (const path of ['/home/user/Tools/invoice-tracker', '/home/user/.hermes/cache/scratch/copy-1', '/home/user/Tools/old-api', '/mnt/offline/elsewhere']) {
    assert.ok(panelText.includes(path), `panel lists ${path}`)
  }
  assert.match(panelText, /missing/)
  assert.match(panelText, /not a directory/)
  assert.match(panelText, /unavailable/)
  const rows = allTestId(panel, 'manage-project-row')
  assert.equal(rows.length, 6, 'all current and unavailable records listed')
  assert.deepEqual(rows.map(r => r.props['data-folder-status']), ['present', 'present', 'present', 'missing', 'not_directory', 'unavailable'])
  assert.match(textOf(byDomId(tree, 'project-count')), /^3$/, 'visible count stays current directories only')
})

test('Forget asks for explicit confirmation, cancel makes no request, confirm persists through a backend reload', async t => {
  const second = payload({
    projects: payload().projects.filter(p => p.name !== 'invoice-tracker'),
    unavailable_projects: payload().unavailable_projects
  })
  const h = mountHarness(t, { payloads: [payload(), second] })
  let tree = await refresh(h)

  const invoice = nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] === 'invoice-tracker')[0]
  invoice.props.onClick()
  tree = await h.open()
  assert.equal(nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] === 'invoice-tracker')[0].props['aria-pressed'], true, 'project selected first')

  byTestId(tree, 'manage-projects-toggle').props.onClick()
  tree = await h.open()
  const panel = byTestId(tree, 'manage-projects-panel')
  const row = allTestId(panel, 'manage-project-row').find(r => r.props['data-path'] === '/home/user/Tools/invoice-tracker')
  allTestId(row, 'forget-project')[0].props.onClick()
  tree = await h.open()

  const confirmPanel = byTestId(tree, 'manage-projects-panel')
  const confirmText = textOf(confirmPanel)
  assert.match(confirmText, /removes it from Defuzz only/)
  assert.match(confirmText, /files untouched/)
  assert.equal(forgetCalls(h).length, 0, 'no request before confirmation')

  byTestId(confirmPanel, 'cancel-forget-project').props.onClick()
  tree = await h.open()
  assert.equal(forgetCalls(h).length, 0, 'cancel sends nothing')
  assert.equal(byTestId(tree, 'manage-projects-panel').props['data-confirming'], undefined, 'confirmation closes')

  const row2 = allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row').find(r => r.props['data-path'] === '/home/user/Tools/invoice-tracker')
  allTestId(row2, 'forget-project')[0].props.onClick()
  tree = await h.open()
  const confirmButton = byTestId(byTestId(tree, 'manage-projects-panel'), 'confirm-forget-project')
  await confirmButton.props.onClick()
  tree = await h.open()

  const sent = forgetCalls(h)
  assert.equal(sent.length, 1)
  assert.equal(sent[0].opts.method, 'POST')
  assert.deepEqual(sent[0].opts.body, { path: '/home/user/Tools/invoice-tracker' })
  assert.equal(projectCalls(h).length, 2, 'backend list reloaded after forgetting')
  assert.equal(nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] === 'invoice-tracker').length, 0, 'forgotten project leaves the strip after refresh')
  assert.equal(textOf(byDomId(tree, 'active-project-title')), 'No project selected', 'selected forgotten project clears, no fake default name')
  assert.match(textOf(byDomId(tree, 'project-count')), /^2$/)

  const refreshButton = nodes(tree, n => (n.type === 'Button' || n.type === 'button') && textOf(n) === 'Refresh projects')[0]
  await refreshButton.props.onClick()
  tree = await h.open()
  assert.equal(nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] === 'invoice-tracker').length, 0, 'a later refresh never resurrects the forgotten record')
})

test('Forget shows busy state while the backend call is in flight', async t => {
  let release
  const h = mountHarness(t, { forget: () => new Promise(resolve => { release = resolve }) })
  let tree = await refresh(h)
  byTestId(tree, 'manage-projects-toggle').props.onClick()
  tree = await h.open()
  const row = allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row').find(r => r.props['data-path'] === '/home/user/Tools/py-copy')
  allTestId(row, 'forget-project')[0].props.onClick()
  tree = await h.open()
  const pending = byTestId(byTestId(tree, 'manage-projects-panel'), 'confirm-forget-project').props.onClick()
  tree = await h.open()

  assert.equal(byTestId(tree, 'manage-projects-toggle').props.disabled, true, 'management is disabled while a forget runs')
  assert.match(textOf(byTestId(tree, 'manage-projects-panel')), /Forgetting…/)
  release({ status: 'forgotten' })
  await pending
  tree = await h.open()
  assert.equal(byTestId(tree, 'manage-projects-toggle').props.disabled, false)
})

test('duplicate project names target the exact path, and a forget error keeps the record with a visible message', async t => {
  const dupes = payload({
    projects: [present('copy', '/home/user/Tools/copy')],
    unavailable_projects: [gone('copy', '/home/user/.hermes/cache/scratch/copy-2', 'missing')]
  })
  const failing = async () => { throw new Error('registry busy, nothing changed') }
  const h = mountHarness(t, { payloads: [dupes], forget: failing })
  let tree = await refresh(h)
  byTestId(tree, 'manage-projects-toggle').props.onClick()
  tree = await h.open()
  const rows = allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row')
  const target = rows.find(r => r.props['data-path'] === '/home/user/.hermes/cache/scratch/copy-2')
  allTestId(target, 'forget-project')[0].props.onClick()
  tree = await h.open()
  await byTestId(byTestId(tree, 'manage-projects-panel'), 'confirm-forget-project').props.onClick()
  tree = await h.open()

  assert.deepEqual(forgetCalls(h).map(c => c.opts.body), [{ path: '/home/user/.hermes/cache/scratch/copy-2' }], 'only the targeted duplicate path is sent')
  assert.equal(projectCalls(h).length, 1, 'no reload after a failed forget')
  assert.match(textOf(nodes(tree, n => n.props?.role === 'status')[0]), /registry busy, nothing changed/)
  assert.equal(allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row').length, 2, 'records stay listed after failure')
})

test('Forget missing confirms and removes only records whose folder is confirmed missing', async t => {
  const after = payload({ unavailable_projects: payload().unavailable_projects.filter(p => p.folder_status !== 'missing') })
  const h = mountHarness(t, { payloads: [payload(), after] })
  let tree = await refresh(h)
  byTestId(tree, 'manage-projects-toggle').props.onClick()
  tree = await h.open()

  const bulk = byTestId(tree, 'forget-missing-projects')
  assert.ok(bulk, 'bulk Forget missing offered')
  assert.match(textOf(bulk), /1/)
  bulk.props.onClick()
  tree = await h.open()
  assert.match(textOf(byTestId(tree, 'manage-projects-panel')), /files untouched/)
  assert.equal(forgetCalls(h).length, 0, 'bulk forget also requires confirmation')
  await byTestId(tree, 'confirm-forget-missing').props.onClick()
  tree = await h.open()

  assert.deepEqual(forgetCalls(h).map(c => c.opts.body), [{ path: '/home/user/.hermes/cache/scratch/copy-1' }], 'not_directory and unavailable are never swept as missing')
  assert.equal(allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row').filter(r => r.props['data-folder-status'] === 'missing').length, 0)
  assert.equal(allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row').length, 5)
})

const openManage = async h => {
  let tree = await h.open()
  byTestId(tree, 'manage-projects-toggle').props.onClick()
  return h.open()
}
const manageRowByPath = (tree, path) =>
  allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row').find(r => r.props['data-path'] === path)
const forgetNotice = tree => textOf(byDomId(tree, 'forget-notice'))
const confirmForget = async (h, path) => {
  let tree = await openManage(h)
  allTestId(manageRowByPath(tree, path), 'forget-project')[0].props.onClick()
  tree = await h.open()
  return byTestId(byTestId(tree, 'manage-projects-panel'), 'confirm-forget-project').props.onClick()
}

test('B1 display names are preserved and only a missing name falls back to the canonical basename', async t => {
  const h = mountHarness(t, { payloads: [{
    coverage: 'verified',
    projects: [
      { name: 'My Display Name', raw_path: '/home/user/Tools/registry-slug', canonical_path: '/home/user/Tools/canonical-folder', registered: true },
      { raw_path: '/home/user/Tools/plain-folder', canonical_path: '/home/user/Tools/plain-folder', registered: true }
    ],
    unavailable_projects: []
  }] })
  const tree = await refresh(h)
  const cards = nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] !== undefined)
  assert.deepEqual(cards.map(textOf), ['My Display Name', 'plain-folder'], 'user-facing names win; basename is only a fallback')
  assert.equal(cards[0].props.title, '/home/user/Tools/canonical-folder', 'title carries the canonical folder, not the registry slug')
  assert.ok(cards[0].props['aria-label'].includes('/home/user/Tools/canonical-folder'), 'accessible name carries the exact folder')

  const manage = await openManage(h)
  const rows = allTestId(byTestId(manage, 'manage-projects-panel'), 'manage-project-row')
  assert.deepEqual(rows.map(r => textOf(nodes(r, n => n.props?.className === 'manage-project-name')[0])), ['My Display Name', 'plain-folder'])
})

test('B4 manage keys and forget posts use the exact stored registration path; selection uses canonical', async t => {
  const raw = {
    coverage: 'verified',
    projects: [
      { name: 'alpha', raw_path: '/home/user/Tools/alpha/', canonical_path: '/home/user/Tools/alpha', registered: true, template_id: 'ts-node-golden' },
      { name: 'alpha duplicate', raw_path: '/home/user/Tools/alpha', canonical_path: '/home/user/Tools/alpha', registered: true, template_id: 'ts-node-golden' },
      { name: 'Py Copy', raw_path: '/home/user/Tools/py-copy', canonical_path: '/home/user/Tools/py-copy', registered: true, language: 'typescript' }
    ],
    unavailable_projects: []
  }
  const after = { coverage: 'verified', projects: [raw.projects[1], raw.projects[2]], unavailable_projects: [] }
  const h = mountHarness(t, { payloads: [raw, after] })
  let tree = await refresh(h)

  const cards = nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] !== undefined)
  assert.deepEqual(cards.map(c => c.props['data-project']), ['alpha', 'Py Copy'], 'one card per canonical folder keeps one display name')
  assert.equal(textOf(byDomId(tree, 'project-count')), '2', 'count follows canonical folders')
  cards[0].props.onClick()
  tree = await h.open()
  const selectedCard = nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] === 'alpha')[0]
  assert.equal(selectedCard.props['aria-pressed'], true, 'selection uses the canonical path shared by both registrations')

  tree = await openManage(h)
  const rows = allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row')
  assert.equal(rows.length, 3, 'distinct stored registrations stay distinct in management')
  assert.deepEqual(rows.map(r => r.props['data-path']).slice(0, 2), ['/home/user/Tools/alpha/', '/home/user/Tools/alpha'], 'storage identity is exact, including the trailing slash')
  const forgetBtn = allTestId(rows[0], 'forget-project')[0]
  assert.ok(forgetBtn.props['aria-label'].includes('/home/user/Tools/alpha/'), 'accessible forget label names the exact registration')
  forgetBtn.props.onClick()
  tree = await h.open()
  await byTestId(byTestId(tree, 'manage-projects-panel'), 'confirm-forget-project').props.onClick()
  tree = await h.open()

  assert.deepEqual(forgetCalls(h).map(c => c.opts.body), [{ path: '/home/user/Tools/alpha/' }], 'posts the exact stored string without trimming')
  assert.match(forgetNotice(tree), /Removed from Defuzz only/, 'the removed registration is confirmed absent')
  const survivingAlpha = nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.title === '/home/user/Tools/alpha')
  assert.equal(survivingAlpha.length, 1, 'the duplicate registration keeps the canonical folder visible')
  assert.equal(survivingAlpha[0].props['aria-pressed'], true, 'selection survives while any registration for that canonical folder remains')
})

test('B3 a successful POST is only reported after a fresh verified reload confirms the registration is absent', async t => {
  const h = mountHarness(t, { payloads: [payload(), payload()] })
  await refresh(h)
  await confirmForget(h, '/home/user/Tools/invoice-tracker')
  const tree = await h.open()

  assert.equal(projectCalls(h).length, 2, 'a fresh list is read after the POST')
  assert.doesNotMatch(forgetNotice(tree), /Removed from Defuzz only/, 'a registration that is still listed is not called removed')
  assert.match(forgetNotice(tree), /still|not removed|remains/i)
  assert.equal(manageRowByPath(tree, '/home/user/Tools/invoice-tracker') !== undefined, true, 'the surviving record stays visible')
})

test('B3 {ok:false,error} is a failure, never a removal claim', async t => {
  const h = mountHarness(t, {
    payloads: [payload(), payload()],
    forget: async () => ({ ok: false, error: 'registry busy, nothing changed' })
  })
  await refresh(h)
  await confirmForget(h, '/home/user/Tools/invoice-tracker')
  const tree = await h.open()

  assert.doesNotMatch(forgetNotice(tree), /Removed from Defuzz only/, 'error response never claims removal')
  assert.match(textOf(nodes(tree, n => n.props?.role === 'status')[0]), /registry busy, nothing changed/)
  assert.equal(manageRowByPath(tree, '/home/user/Tools/invoice-tracker') !== undefined, true, 'record remains')
})

test('B3 an unverified reload never claims removal', async t => {
  const base = payload()
  const unverified = payload({
    coverage: 'could_not_verify',
    projects: base.projects.filter(p => p.name !== 'invoice-tracker')
  })
  const h = mountHarness(t, { payloads: [base, unverified] })
  await refresh(h)
  await confirmForget(h, '/home/user/Tools/invoice-tracker')
  const tree = await h.open()

  assert.doesNotMatch(forgetNotice(tree), /Removed from Defuzz only/, 'unverified coverage is not proof of removal')
  assert.match(forgetNotice(tree), /could not verify|not verified/i)
})

test('B3 a failed reload preserves the error and claims nothing', async t => {
  const h = mountHarness(t, { payloads: [payload(), () => { throw new Error('list unavailable after forget') }] })
  await refresh(h)
  await confirmForget(h, '/home/user/Tools/invoice-tracker')
  const tree = await h.open()

  assert.doesNotMatch(forgetNotice(tree), /Removed from Defuzz only/)
  assert.match(textOf(nodes(tree, n => n.props?.role === 'status')[0]), /list unavailable after forget/)
})

test('B3 a refresh started during the POST cannot make the verified reload skip', async t => {
  let releaseForget, releaseGet
  const stale = payload()
  const fresh = payload({ projects: stale.projects.filter(p => p.name !== 'invoice-tracker') })
  const h = mountHarness(t, {
    payloads: [stale, () => new Promise(resolve => { releaseGet = resolve }), fresh],
    forget: () => new Promise(resolve => { releaseForget = resolve })
  })
  let tree = await refresh(h)
  tree = await openManage(h)
  allTestId(manageRowByPath(tree, '/home/user/Tools/invoice-tracker'), 'forget-project')[0].props.onClick()
  tree = await h.open()
  const pendingForget = byTestId(byTestId(tree, 'manage-projects-panel'), 'confirm-forget-project').props.onClick()
  tree = await h.open()

  const refreshButton = nodes(tree, n => (n.type === 'Button' || n.type === 'button') && textOf(n) === 'Refresh projects')[0]
  const pendingRefresh = refreshButton.props.onClick()
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(projectCalls(h).length, 2, 'the concurrent refresh issues its own read')
  assert.equal(refreshButton.props.disabled, true, 'Refresh is disabled while the forget POST is in flight')

  releaseForget({ status: 'forgotten' })
  await new Promise(resolve => setImmediate(resolve))
  tree = await h.open()
  assert.equal(forgetNotice(tree), '', 'success waits for readback instead of claiming early')
  releaseGet(stale)
  await pendingRefresh
  await pendingForget
  tree = await h.open()

  assert.equal(projectCalls(h).length, 3, 'the verified reload still runs after the overlapping refresh')
  assert.match(forgetNotice(tree), /Removed from Defuzz only/, 'the fresh verified payload confirms the registration is gone')
})

test('B3 rapid direct forget calls are serialized by the model, not only by disabled buttons', async t => {
  let release
  const afterPy = payload({ projects: payload().projects.filter(p => p.name !== 'py') })
  const h = mountHarness(t, { payloads: [payload(), afterPy], forget: () => new Promise(resolve => { release = resolve }) })
  let tree = await refresh(h)
  tree = await openManage(h)
  allTestId(manageRowByPath(tree, '/home/user/Tools/py-copy'), 'forget-project')[0].props.onClick()
  const rendered = await h.open()
  const confirm = byTestId(byTestId(rendered, 'manage-projects-panel'), 'confirm-forget-project')
  const first = confirm.props.onClick()
  const second = confirm.props.onClick()
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(forgetCalls(h).length, 1, 'the second direct call is ignored while the first POST is in flight')
  release({ status: 'forgotten' })
  await Promise.all([first, second])
  const done = await h.open()
  assert.equal(forgetNotice(done), 'Removed from Defuzz only; files untouched.')
})

test('B4 a strip with duplicate canonical folders and a coverage gap is honest about both', async t => {
  const duplicate = {
    coverage: 'verified',
    projects: [
      { name: 'folder', raw_path: '/x/folder', canonical_path: '/x/folder', registered: true },
      { name: 'folder alias', raw_path: '/x/folder/.', canonical_path: '/x/folder', registered: true }
    ],
    unavailable_projects: []
  }
  const h = mountHarness(t, { payloads: [duplicate] })
  const tree = await refresh(h)
  assert.equal(textOf(byDomId(tree, 'project-count')), '1')
  assert.deepEqual(nodes(byTestId(tree, 'v10-project-strip'), n => n.props?.['data-project'] !== undefined).map(c => c.props['data-project']), ['folder'])
})

test('B4 unverified coverage is warned about with the affected registrations listed', async t => {
  const h = mountHarness(t, { payloads: [{
    coverage: 'could_not_verify',
    projects: [
      { name: 'ghost', raw_path: '/x/ghost', canonical_path: '/x/ghost', registered: true },
      { name: 'known', raw_path: '/x/known', canonical_path: '/x/known', registered: true }
    ],
    unavailable_projects: []
  }] })
  let tree = await refresh(h)
  const stripWarning = byTestId(tree, 'projects-coverage-warning')
  assert.ok(stripWarning, 'strip exposes the coverage gap')
  assert.match(textOf(stripWarning), /could not verify/i)

  tree = await openManage(h)
  const warning = byTestId(tree, 'manage-coverage-warning')
  assert.ok(warning, 'management exposes the coverage gap')
  assert.match(textOf(warning), /could not verify|unknown/i)
  assert.match(textOf(warning), /\/x\/ghost/)
  assert.match(textOf(warning), /\/x\/known/)
})

test('B3 bulk forget counts only registrations confirmed absent in the verified reload and keeps errors', async t => {
  const base = payload()
  const twoMissing = payload({
    unavailable_projects: [...base.unavailable_projects, gone('copy-2', '/home/user/.hermes/cache/scratch/copy-2', 'missing')]
  })
  const after = payload({
    unavailable_projects: [gone('copy-2', '/home/user/.hermes/cache/scratch/copy-2', 'missing'), ...base.unavailable_projects.filter(p => p.folder_status !== 'missing')]
  })
  const h = mountHarness(t, {
    payloads: [twoMissing, after],
    forget: async opts => {
      if (opts.body.path.endsWith('copy-2')) throw new Error('registry refused copy-2')
      return { status: 'forgotten' }
    }
  })
  let tree = await refresh(h)
  byTestId(tree, 'manage-projects-toggle').props.onClick()
  tree = await h.open()
  byTestId(tree, 'forget-missing-projects').props.onClick()
  tree = await h.open()
  await byTestId(tree, 'confirm-forget-missing').props.onClick()
  tree = await h.open()

  assert.equal(forgetCalls(h).length, 2, 'both missing registrations are attempted')
  assert.equal(allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row').filter(r => r.props['data-folder-status'] === 'missing').length, 1, 'only copy-1 actually disappeared')
  assert.match(forgetNotice(tree), /1 missing project removed/, 'the count is confirmed absences, not HTTP successes')
  assert.doesNotMatch(forgetNotice(tree), /2 missing projects removed/)
  assert.match(forgetNotice(tree), /\/home\/user\/\.hermes\/cache\/scratch\/copy-2/, 'the non-verified registration is named')
  assert.match(textOf(nodes(tree, n => n.props?.role === 'status')[0]), /registry refused copy-2/, 'the backend error is preserved')
})

test('B3 forget verifies the forced read it made, even when a later Refresh steals the newest-list token', async t => {
  let releaseForget, releaseVerified
  const stale = payload()
  const fresh = payload({ projects: stale.projects.filter(p => p.name !== 'invoice-tracker'), unavailable_projects: stale.unavailable_projects })
  const h = mountHarness(t, {
    payloads: [stale,
      () => new Promise(resolve => { releaseVerified = resolve }),
      fresh],
    forget: () => new Promise(resolve => { releaseForget = resolve })
  })
  let tree = await refresh(h)
  byTestId(tree, 'manage-projects-toggle').props.onClick()
  tree = await h.open()
  const invoiceRow = () => allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row')
    .find(r => r.props['data-path'] === '/home/user/Tools/invoice-tracker')
  allTestId(invoiceRow(), 'forget-project')[0].props.onClick()
  tree = await h.open()
  const pendingForget = byTestId(byTestId(tree, 'manage-projects-panel'), 'confirm-forget-project').props.onClick()
  tree = await h.open()

  releaseForget({ status: 'forgotten', removed: true })
  await new Promise(r => setImmediate(r))
  // The forced verified read is in flight; a later programmatic load takes the newest token.
  const refreshButton = nodes(tree, n => (n.type === 'Button' || n.type === 'button') && textOf(n) === 'Refresh projects')[0]
  const secondLoad = refreshButton.props.onClick()
  await new Promise(r => setImmediate(r))
  releaseVerified(fresh)
  await Promise.all([pendingForget, secondLoad])
  tree = await h.open()

  assert.match(textOf(byDomId(tree, 'forget-notice')), /Removed from Defuzz only/, 'the forced read proves the exact registration is gone')
  assert.doesNotMatch(textOf(byDomId(tree, 'forget-notice')), /still lists/, 'a superseded token must not make the stale mutable list decide the result')
  assert.equal(allTestId(byTestId(tree, 'manage-projects-panel'), 'manage-project-row')
    .some(r => r.props['data-path'] === '/home/user/Tools/invoice-tracker'), false)
  assert.equal(projectCalls(h).length, 3, 'the newest read still applies to the visible list')
})

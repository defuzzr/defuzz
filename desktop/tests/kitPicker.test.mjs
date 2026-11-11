import test from 'node:test'
import assert from 'node:assert/strict'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'
import { catalog, CATALOG_ENTRIES, choiceRadio, checkedChoice, chooseRow, typeProjectName } from './choiceList.mjs'

const nodes = (node, predicate = () => true) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]

const byId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)[0]
const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const byLabel = (tree, label) => nodes(tree, n => n.props?.['aria-label'] === label)[0]
const textOf = node =>
  !node
    ? ''
    : typeof node === 'string' || typeof node === 'number'
      ? String(node)
      : [node.props?.children].flat().map(textOf).join('')

const KIT_CATALOG = [
  {
    kit_id: 'studio-3d',
    name: '3D studio',
    summary: 'Source scenes and exports for Blender or Houdini.',
    tags: ['studio', 'render', 'blender']
  },
  {
    kit_id: 'game-assets',
    name: 'Game workspace: Unreal + Blender + Houdini',
    summary: 'Game workspace with one folder per source asset and Git LFS rules.',
    tags: ['game', 'unreal', 'assets']
  },
  {
    kit_id: 'video-production',
    name: 'Video production',
    summary: 'AI-assisted video or storyboard production with locked canon references.',
    tags: ['video', 'storyboard', 'production']
  }
]

const VIDEO_PREVIEW = {
  kit: {
    id: 'video-production',
    name: 'Video production',
    summary: 'AI-assisted video or storyboard production with locked canon references.',
    tags: ['video', 'storyboard', 'production'],
    version: 2
  },
  tree: [
    '.gitattributes',
    '.gitignore',
    'AGENTS.md',
    'archive/',
    'archive/.gitkeep',
    'assets/',
    'assets/approved/',
    'assets/approved/.gitkeep',
    'assets/canon/',
    'assets/canon/CANON.md',
    'renders/',
    'renders/.gitkeep'
  ],
  declared_dirs: [
    { dir: 'assets/canon', summary: 'Locked reference images', why: 'canon check' },
    { dir: 'renders', summary: 'Render output', why: 'disposable renders' }
  ],
  placement_rules: [
    { kind: 'video', match_ext: ['.mp4'], dest_dir: 'renders', lfs: true, reason: 'video renders' }
  ]
}

function createModelFixture(handler) {
  const calls = []
  let dispose
  const ctx = {
    onDispose(fn) { dispose = fn; return () => {} },
    setTimeout: () => () => {},
    setInterval: () => () => {},
    async rest(path, opts) {
      calls.push({ path, opts })
      return handler(path, opts, calls)
    }
  }
  const model = ui.createWorkspaceModel(ctx)
  return { ctx, calls, model, dispose: () => dispose?.() }
}

function mountHarness(t, restHandler, initialScreen = 'main') {
  const instances = new Map(), calls = [], routes = [], cleanups = new Set(), effects = []
  let slots, cursor, dirty, currentScreen = initialScreen
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
  const ctx = {
    onDispose(fn) { disposers.push(fn); return () => {} },
    setTimeout: () => () => {},
    setInterval: () => () => {},
    async rest(path, opts) {
      calls.push({ path, opts })
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
      disposers.forEach(fn => fn?.())
      disposers.length = 0
    }
  }
}

const FUTURE_ENTRY = { kind: 'kit', id: 'future-render', title: 'Future renderer', line: 'A synthetic renderer.', group: 'workspace', group_title: 'Workspaces for files', coming_soon: true, selectable: false }

test('coming-soon rows stay visible but cannot be selected by click or keyboard', async t => {
  const entries = [...CATALOG_ENTRIES, FUTURE_ENTRY]
  const h = mountHarness(t, async path => path === '/scaffold/match' ? { catalog: catalog({ entries }) } : {})
  await byDomId(h.render(), 'start-project').props.onClick()
  let modal = byDomId(h.render(), 'new-project-dialog')
  await typeProjectName(modal, 'render')
  const radio = choiceRadio(modal, 'kit:future-render')
  assert.equal(radio.props.disabled, true)
  assert.equal(radio.props['aria-disabled'], 'true')
  assert.equal(radio.props.tabIndex, -1)
  assert.match(textOf(modal), /Coming soon/)
  await radio.props.onChange({ target: { checked: true } })
  modal = byDomId(h.render(), 'new-project-dialog')
  assert.equal(checkedChoice(modal), '')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true)
  assert.equal(h.calls.some(c => c.path.includes('/scaffold/kits/')), false)
})

test('coming-soon only list cannot be chosen with Home or End', async t => {
  const entries = [FUTURE_ENTRY]
  const h = mountHarness(t, async path => path === '/scaffold/match' ? { catalog: catalog({ entries, suggested: ['kit:future-render'] }) } : {})
  await byDomId(h.render(), 'start-project').props.onClick()
  for (const key of ['Home', 'End']) {
    const modal = byDomId(h.render(), 'new-project-dialog')
    await byDomId(modal, 'new-project-choice').props.onKeyDown({ key, preventDefault() {} })
    assert.equal(checkedChoice(byDomId(h.render(), 'new-project-dialog')), '')
    assert.equal(byDomId(byDomId(h.render(), 'new-project-dialog'), 'accept-project').props.disabled, true)
  }
})

test('model: match sends prompt, stores the server catalog, and never selects a kit even when preferred=kit', async () => {
  const { model, calls } = createModelFixture(async (path, opts) => {
    if (path === '/scaffold/match') {
      return {
        matches: [],
        closest: [],
        handoff: null,
        kits: [{ ...KIT_CATALOG[2], score: 7, reasons: ['building: video'] }, { ...KIT_CATALOG[0], score: 3, reasons: ['tag: render'] }],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'kit',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/kits/video-production') {
      return VIDEO_PREVIEW
    }
    return {}
  })

  assert.equal(model.get().catalog, null, 'no list before the first match')
  assert.equal(Object.hasOwn(model.get(), 'preferred'), false)
  assert.equal(model.get().selectedKitId, '')
  assert.equal(model.get().kitPreview, null)
  assert.equal(model.get().kitPreviewError, '')

  model.edit({ idea: 'Storyboard and video shoot for launch trailer', answers: { building: 'video' } })
  await model.match()

  assert.equal(calls[0].path, '/scaffold/match')
  assert.deepEqual(calls[0].opts.body, {
    answers: {},
    prompt: 'Storyboard and video shoot for launch trailer'
  }, 'the list request carries only the idea')
  assert.deepEqual(model.get().answers, { building: 'video' }, 'the answers kept for Create are unchanged')
  assert.deepEqual(model.get().catalog.entries.map(e => `${e.kind}:${e.id}`), CATALOG_ENTRIES.map(e => `${e.kind}:${e.id}`), 'the list is stored as received')
  assert.deepEqual(model.get().catalog.suggested, [])
  assert.equal(model.get().catalog.notice, '')
  assert.equal(model.get().selectedKitId, '', 'preferred=kit does not select a kit')
  assert.equal(calls.length, 1, 'no kit preview is fetched without a choice')
  assert.equal(model.get().kitPreview, null)
})

test('model: selectKit clears an existing proposal and template, and propose sends kit_id without template_id or layout/languages', async () => {
  const { model, calls } = createModelFixture(async (path, opts) => {
    if (path === '/scaffold/propose') {
      if (opts?.body?.template_id) {
        return { proposal_id: 'prop-tpl-1', template_id: opts.body.template_id, tree: [{ name: opts.body.name, dest: `/srv/${opts.body.name}`, files: ['AGENTS.md'] }] }
      }
      return {
        proposal_id: 'prop-kit-1',
        kind: 'kit',
        kit_id: opts.body.kit_id,
        slug: opts.body.name,
        tree: [{ name: opts.body.name, dest: `/srv/${opts.body.name}`, files: ['AGENTS.md', 'assets/canon/CANON.md'] }],
        declared_dirs: VIDEO_PREVIEW.declared_dirs,
        placement_rules: VIDEO_PREVIEW.placement_rules
      }
    }
    if (path === '/scaffold/discard') {
      return { status: 'discarded' }
    }
    if (path === '/scaffold/kits/video-production') {
      return VIDEO_PREVIEW
    }
    if (path === '/scaffold/accept') {
      return {
        status: 'created',
        kind: 'kit',
        kit_id: 'video-production',
        dest: '/srv/night-shoot',
        path: '/srv/night-shoot',
        placement: 'on',
        repos: [{ name: 'night-shoot', path: '/srv/night-shoot', registration: 'registered', registration_result: { registered: true } }]
      }
    }
    return {}
  })

  // First stage a template proposal
  model.edit({
    name: 'night-shoot',
    answers: { building: 'video', layout: 'mono', languages: ['typescript'], custom_tag: '4k' }
  })
  model.choose({ template_id: 'ts-node-golden', id: 'ts-node-golden', name: 'TypeScript' })
  await model.propose()
  assert.equal(model.get().proposal?.proposal_id, 'prop-tpl-1')

  // Selecting a kit clears the template and existing proposal (and discards it on the server)
  await model.selectKit('video-production')
  assert.equal(model.get().selectedKitId, 'video-production')
  assert.equal(model.get().template, null)
  assert.equal(model.get().proposal, null)
  assert.ok(calls.some(c => c.path === '/scaffold/discard' && c.opts?.body?.proposal_id === 'prop-tpl-1'))
  assert.deepEqual(model.get().kitPreview, VIDEO_PREVIEW)

  // Proposing with kit selected sends kit_id, no template_id, and answers without layout/languages
  await model.propose()
  const kitProposeCall = calls.filter(c => c.path === '/scaffold/propose').at(-1)
  assert.ok(kitProposeCall)
  assert.equal(kitProposeCall.opts.body.kit_id, 'video-production')
  assert.equal(Object.hasOwn(kitProposeCall.opts.body, 'template_id'), false)
  assert.equal(Object.hasOwn(kitProposeCall.opts.body.answers, 'layout'), false)
  assert.equal(Object.hasOwn(kitProposeCall.opts.body.answers, 'languages'), false)
  assert.deepEqual(kitProposeCall.opts.body.answers, { building: 'video', custom_tag: '4k' })

  // Clear kit works
  model.clearKit()
  assert.equal(model.get().selectedKitId, '')
  assert.equal(model.get().kitPreview, null)
  assert.equal(model.get().proposal, null)
})

test('model: preview 503 sets one-line kitPreviewError and leaves kitPreview null', async () => {
  const { model } = createModelFixture(async path => {
    if (path === '/scaffold/kits/video-production') {
      const err = new Error('componentize CLI is unavailable.\nAdditional stack detail')
      err.status = 503
      err.body = { detail: 'componentize CLI is unavailable.\nExtra debug line' }
      throw err
    }
    return {}
  })

  await model.selectKit('video-production')
  assert.equal(model.get().selectedKitId, 'video-production')
  assert.equal(model.get().kitPreview, null)
  assert.ok(model.get().kitPreviewError.length > 0)
  assert.equal(model.get().kitPreviewError.includes('\n'), false)
  assert.match(model.get().kitPreviewError, /componentize CLI is unavailable/i)
})

test('model: late match response after idea changed and late preview response after selection changed are ignored', async () => {
  let resolveSlowMatch
  let resolveSlowPreview
  const { model } = createModelFixture((path) => {
    if (path === '/scaffold/match') {
      return new Promise(resolve => { resolveSlowMatch = resolve })
    }
    if (path === '/scaffold/kits/studio-3d') {
      return new Promise(resolve => { resolveSlowPreview = resolve })
    }
    if (path === '/scaffold/kits/video-production') {
      return VIDEO_PREVIEW
    }
    return Promise.resolve({})
  })

  model.edit({ idea: 'first video idea', answers: { building: 'video' } })
  const pendingMatch = model.match()

  // Change idea while match is in flight
  model.edit({ idea: 'second code idea', answers: { building: 'service' } })

  resolveSlowMatch({
    matches: [],
    closest: [],
    handoff: null,
    kits: [{ ...KIT_CATALOG[2], score: 8, reasons: ['building: video'] }],
    kit_catalog: KIT_CATALOG,
    kits_notice: '',
    preferred: 'kit',
    catalog: catalog()
  })
  await pendingMatch

  assert.equal(model.get().selectedKitId, '', 'stale match after idea change must not select a kit')
  assert.equal(model.get().catalog, null, 'stale match after idea change must not populate the list')

  // Now test stale preview response when selection changes in flight
  const pendingSlowPreview = model.selectKit('studio-3d')
  await model.selectKit('video-production')
  assert.equal(model.get().selectedKitId, 'video-production')
  assert.deepEqual(model.get().kitPreview, VIDEO_PREVIEW)

  resolveSlowPreview({
    kit: KIT_CATALOG[0],
    tree: ['scenes/'],
    declared_dirs: [],
    placement_rules: []
  })
  await pendingSlowPreview
  assert.equal(model.get().selectedKitId, 'video-production')
  assert.deepEqual(model.get().kitPreview, VIDEO_PREVIEW, 'stale preview for studio-3d must be ignored')
})

test('modal UI: kit rows come from the list; choosing one shows the folder-only tree with 60-line cap, switching rows clears it, and kit accept surfaces destination + placement on', async t => {
  const manyFoldersTree = [
    '.gitignore',
    'AGENTS.md',
    'assets/',
    'assets/canon/',
    'assets/canon/CANON.md',
    'assets/canon/plates/',
    ...Array.from({ length: 62 }, (_, i) => `shots/shot-${String(i + 1).padStart(2, '0')}/`),
    'shots/shot-01/frame.png'
  ]
  const manyFoldersPreview = {
    ...VIDEO_PREVIEW,
    tree: manyFoldersTree
  }

  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') {
      return {
        matches: [
          { template_id: 'ts-node-golden', name: 'TypeScript', options: { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } } }
        ],
        closest: [],
        handoff: null,
        kits: [{ ...KIT_CATALOG[2], score: 9, reasons: ['building: video'] }],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'kit',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/kits/video-production') {
      return manyFoldersPreview
    }
    if (path === '/scaffold/propose') {
      return {
        proposal_id: 'prop-kit-ui',
        kind: 'kit',
        kit_id: opts.body.kit_id,
        slug: opts.body.name,
        tree: [{ name: opts.body.name, dest: `/srv/${opts.body.name}`, files: manyFoldersTree }],
        declared_dirs: VIDEO_PREVIEW.declared_dirs,
        placement_rules: VIDEO_PREVIEW.placement_rules
      }
    }
    if (path === '/scaffold/accept') {
      return {
        status: 'created',
        kind: 'kit',
        kit_id: 'video-production',
        dest: '/srv/inventory-api',
        path: '/srv/inventory-api',
        placement: 'on',
        repos: [{ name: 'inventory-api', path: '/srv/inventory-api', registration: 'registered', registration_result: { registered: true } }]
      }
    }
    if (path === '/workspace/projects') {
      return { coverage: 'verified', projects: [{ name: 'inventory-api', path: '/srv/inventory-api', registered: true }] }
    }
    return {}
  })

  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()

  let modal = byDomId(tree, 'new-project-dialog')
  assert.ok(modal, 'Start project modal opens')

  // Kit rows are the list's kit entries; preferred=kit selects none of them
  assert.deepEqual(['kit:studio-3d', 'kit:game-assets', 'kit:video-production'].map(key => Boolean(choiceRadio(modal, key))), [true, true, true])
  assert.equal(checkedChoice(modal), '', 'nothing is chosen before the person picks a row')
  assert.equal(h.calls.some(c => c.path.startsWith('/scaffold/kits/')), false, 'no kit preview without a choice')
  assert.deepEqual(nodes(modal, n => n.type === 'select').map(s => s.props?.id), ['new-project-adapter'], 'only the template-options select remains')

  await typeProjectName(modal, 'inventory-api')
  await chooseRow(modal, 'kit:video-production')
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), 'kit:video-production')
  assert.equal(textOf(byDomId(modal, 'proposal-template')), 'Video production', 'the badge shows the row title')

  // Preview area shows kit summary and folder-only tree with aria-label 'Folders this workspace creates' and 60-line cap
  assert.match(textOf(modal), /AI-assisted video or storyboard production with locked canon references\./, 'shows kit summary in modal preview area')
  const previewTreeEl = byLabel(modal, 'Folders this workspace creates') || byDomId(modal, 'proposal-tree')
  assert.ok(previewTreeEl, 'tree preview exists')
  assert.equal(previewTreeEl.props['aria-label'], 'Folders this workspace creates')
  const treeLines = textOf(previewTreeEl).split('\n')
  // 3 asset folders + 62 shot folders = 65 folders total -> 60 lines + '… and 5 more' = 61 lines
  assert.equal(treeLines.length, 61, 'capped at 60 folder lines plus final overflow line')
  assert.equal(treeLines[0], 'assets/')
  assert.equal(treeLines[1], '  assets/canon/')
  assert.equal(treeLines[2], '    assets/canon/plates/')
  assert.equal(treeLines[60], '… and 5 more')
  assert.doesNotMatch(textOf(previewTreeEl), /AGENTS\.md|CANON\.md|frame\.png|\.gitignore/, 'files are excluded from folder tree preview')

  // Choosing a template row clears the kit and its preview
  await chooseRow(modal, 'template:ts-node-golden')
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), 'template:ts-node-golden')
  assert.equal(byDomId(modal, 'proposal-tree').props['aria-label'], undefined, 'kit preview cleared')

  // Choosing the kit row again brings the kit back
  await chooseRow(modal, 'kit:video-production')
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), 'kit:video-production')

  // Accept & create with kit selected sends kit_id and no layout/languages, then surfaces dest and placement: on
  await byDomId(modal, 'accept-project').props.onClick()
  tree = h.render()
  const proposeCall = h.calls.find(c => c.path === '/scaffold/propose')
  assert.ok(proposeCall, 'propose called on Accept & create')
  assert.equal(proposeCall.opts.body.kit_id, 'video-production')
  assert.equal(Object.hasOwn(proposeCall.opts.body, 'template_id'), false)
  assert.equal(Object.hasOwn(proposeCall.opts.body.answers, 'layout'), false)
  assert.equal(Object.hasOwn(proposeCall.opts.body.answers, 'languages'), false)

  const statusText = textOf(byDomId(tree, 'status'))
  assert.match(statusText, /\/srv\/inventory-api/, 'surfaces destination path after kit accept')
  assert.match(statusText, /placement.*on/i, 'surfaces automatic file placement is on after kit accept')
})

test('modal UI: when the list has no kits and a notice, no kit rows are shown and the notice is', async t => {
  const h = mountHarness(t, async path => {
    if (path === '/scaffold/match') {
      return {
        matches: [{ template_id: 'ts-node-golden', name: 'TypeScript', options: {} }],
        closest: [],
        handoff: null,
        kits: [],
        kit_catalog: [],
        kits_notice: 'componentize CLI is unavailable.',
        preferred: 'none',
        catalog: catalog({ entries: CATALOG_ENTRIES.filter(e => e.kind !== 'kit'), notice: 'componentize CLI is unavailable.' })
      }
    }
    return {}
  })

  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()

  const modal = byDomId(tree, 'new-project-dialog')
  assert.equal(choiceRadio(modal, 'kit:video-production'), undefined, 'no kit rows')
  assert.ok(choiceRadio(modal, 'template:ts-node-golden'), 'template rows stay')
  assert.equal(textOf(byDomId(modal, 'kits-notice')), 'componentize CLI is unavailable.', 'renders the notice under the list')
})

test('F1: a match whose list drops the chosen kit, or a failing match, clears selectedKitId and discards the stale kit proposal', async t => {
  let matchMode = 'initial-kit'
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') {
      if (matchMode === 'initial-kit') {
        return {
          matches: [{ template_id: 'ts-node-golden', name: 'TypeScript', options: {} }],
          closest: [],
          handoff: null,
          kits: [{ ...KIT_CATALOG[2], score: 9, reasons: ['building: video'] }],
          kit_catalog: KIT_CATALOG,
          kits_notice: '',
          preferred: 'kit',
          catalog: catalog()
        }
      }
      if (matchMode === 'empty-catalog') {
        return {
          matches: [{ template_id: 'ts-node-golden', name: 'TypeScript', options: {} }],
          closest: [],
          handoff: null,
          kits: [],
          kit_catalog: [],
          kits_notice: 'componentize CLI is unavailable.',
          preferred: 'none',
          catalog: catalog({ entries: CATALOG_ENTRIES.filter(e => e.kind !== 'kit'), notice: 'componentize CLI is unavailable.' })
        }
      }
      if (matchMode === 'fail') {
        throw new Error('match service down')
      }
    }
    if (path === '/scaffold/kits/video-production') {
      return VIDEO_PREVIEW
    }
    if (path === '/scaffold/propose') {
      return {
        proposal_id: `prop-${opts.body.name}`,
        kind: 'kit',
        kit_id: opts.body.kit_id,
        slug: opts.body.name,
        tree: [{ name: opts.body.name, dest: `/srv/${opts.body.name}`, files: ['renders/'] }]
      }
    }
    if (path === '/scaffold/accept') {
      return { ok: false, error: 'pre-move check failed', created_dirs: [] }
    }
    if (path === '/scaffold/discard') {
      return { status: 'discarded' }
    }
    return {}
  })

  // Sequence 1: kit selected + kit proposal staged -> later match returns empty kit_catalog with kits_notice
  let scheduledFn = null
  h.ctx.setTimeout = (fn) => { scheduledFn = fn; return () => { scheduledFn = null } }
  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()
  let modal = byDomId(tree, 'new-project-dialog')
  await typeProjectName(modal, 'inventory-api')
  await chooseRow(modal, 'kit:video-production')
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), 'kit:video-production')

  // Schedule a debounced match, stage a kit proposal (accept fails pre-move so proposal remains staged), then let match resolve with empty kit_catalog
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'plain service idea' } })
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'accept-project').props.onClick()
  tree = h.render()
  assert.equal(h.calls.filter(c => c.path === '/scaffold/discard').length, 0)

  matchMode = 'empty-catalog'
  if (scheduledFn) await scheduledFn()
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')

  assert.equal(checkedChoice(modal), '', 'selectedKitId cleared when the list no longer has the kit')
  assert.equal(choiceRadio(modal, 'template:ts-node-golden').props.disabled, false, 'template rows stay usable')
  assert.ok(h.calls.some(c => c.path === '/scaffold/discard' && c.opts?.body?.proposal_id === 'prop-inventory-api'), 'stale kit proposal discarded')

  // Also verify directly on model when a manually selected kit + proposal hits empty catalog then match error
  const { model, calls } = createModelFixture(async (path, opts) => {
    if (path === '/scaffold/kits/video-production') return VIDEO_PREVIEW
    if (path === '/scaffold/propose') return { proposal_id: `prop-${opts.body.name}`, kind: 'kit', kit_id: opts.body.kit_id }
    if (path === '/scaffold/discard') return { status: 'discarded' }
    if (path === '/scaffold/match') {
      if (matchMode === 'empty-catalog') {
        return { matches: [], closest: [], handoff: null, kits: [], kit_catalog: [], kits_notice: 'unavailable', preferred: 'none', catalog: catalog({ entries: CATALOG_ENTRIES.filter(e => e.kind !== 'kit'), notice: 'componentize CLI is unavailable.' }) }
      }
      throw new Error('network error')
    }
    return {}
  })

  model.edit({ name: 'seq-empty' })
  await model.selectKit('video-production')
  await model.propose()
  assert.equal(model.get().selectedKitId, 'video-production')
  assert.equal(model.get().proposal?.proposal_id, 'prop-seq-empty')

  matchMode = 'empty-catalog'
  await model.match()
  assert.equal(model.get().selectedKitId, '')
  assert.equal(model.get().kitPreview, null)
  assert.equal(model.get().proposal, null)
  assert.ok(calls.some(c => c.path === '/scaffold/discard' && c.opts?.body?.proposal_id === 'prop-seq-empty'))

  // Sequence 2: kit selected + kit proposal staged -> later match fails (throws)
  model.edit({ name: 'seq-error' })
  await model.selectKit('video-production')
  await model.propose()
  assert.equal(model.get().selectedKitId, 'video-production')
  assert.equal(model.get().proposal?.proposal_id, 'prop-seq-error')

  matchMode = 'fail'
  await model.match()
  assert.equal(model.get().selectedKitId, '')
  assert.equal(model.get().kitPreview, null)
  assert.equal(model.get().proposal, null)
  assert.ok(calls.some(c => c.path === '/scaffold/discard' && c.opts?.body?.proposal_id === 'prop-seq-error'))

  // And in rendered modal on match failure after manual kit selection
  matchMode = 'initial-kit'
  await byDomId(modal, 'cancel-project').props.onClick()
  tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  await chooseRow(modal, 'kit:video-production')
  tree = h.render()
  assert.equal(checkedChoice(byDomId(tree, 'new-project-dialog')), 'kit:video-production')

  matchMode = 'fail'
  await byDomId(byDomId(tree, 'new-project-dialog'), 'project-idea').props.onChange({ target: { value: 'trigger failing match' } })
  if (scheduledFn) await scheduledFn()
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), '', 'the kit is no longer chosen after a failed match')
  assert.ok(byDomId(modal, 'new-project-choice-retry'), 'a failed match offers Check again')
})

test('F2: typing an idea in the open modal debounces match by 400ms, re-checks a cleared idea, and cancels on close/unmount', async t => {
  const activeTimers = new Map()
  let nextTimerId = 1
  const h = mountHarness(t, async (path) => {
    if (path === '/scaffold/match') {
      return {
        matches: [{ template_id: 'ts-node-golden', name: 'TypeScript', options: {} }],
        closest: [],
        handoff: null,
        kits: [{ ...KIT_CATALOG[2], score: 9, reasons: ['building: video'] }],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'kit',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/kits/video-production') {
      return VIDEO_PREVIEW
    }
    return {}
  })
  h.ctx.setTimeout = (fn, ms) => {
    const id = nextTimerId++
    activeTimers.set(id, { fn, ms })
    return () => activeTimers.delete(id)
  }

  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()

  // Clear initial openNewProjectModal match call
  h.calls.length = 0

  // Three quick edits to Project idea
  let modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'v' } })
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'video' } })
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'video launch storyboard' } })
  tree = h.render()

  // Exactly one timer pending with 400ms delay, and no match request sent yet
  assert.equal(activeTimers.size, 1, 'debounces rapid keystrokes to a single timer')
  const [timerEntry] = activeTimers.values()
  assert.equal(timerEntry.ms, 400, 'schedules match 400ms after last keystroke')
  assert.equal(h.calls.filter(c => c.path === '/scaffold/match').length, 0)

  // Fire the 400ms timer
  activeTimers.clear()
  await timerEntry.fn()
  tree = h.render()

  const matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1, 'three quick edits produce exactly one match request')
  assert.equal(matchCalls[0].opts.body.prompt, 'video launch storyboard')

  // Clearing the idea schedules one match too, so stale "(suggested)" marks go away
  h.calls.length = 0
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: '' } })
  tree = h.render()
  assert.equal(activeTimers.size, 1, 'a cleared idea schedules one match')
  const [clearedTimer] = activeTimers.values()
  activeTimers.clear()
  await clearedTimer.fn()
  assert.deepEqual(h.calls.filter(c => c.path === '/scaffold/match').map(c => c.opts.body.prompt), [''])
  h.calls.length = 0

  // Closing the modal before the 400ms delay cancels the timer and produces no match request
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'unreal asset pack' } })
  tree = h.render()
  assert.equal(activeTimers.size, 1)
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'cancel-project').props.onClick()
  tree = h.render()
  assert.equal(activeTimers.size, 0, 'closing the modal clears pending idea match timer')
  assert.equal(h.calls.filter(c => c.path === '/scaffold/match').length, 0)

  // Unmounting before the 400ms delay cancels the timer and produces no match request
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()
  h.calls.length = 0
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'unmount before timer fires' } })
  tree = h.render()
  assert.equal(activeTimers.size, 1, 'timer scheduled before unmount')
  const [unmountTimer] = activeTimers.values()
  h.unmount()
  assert.equal(activeTimers.size, 0, 'unmounting clears pending idea match timer')
  await unmountTimer.fn()
  assert.equal(h.calls.filter(c => c.path === '/scaffold/match').length, 0, 'no match request sent after unmount')
})

test('F3: preferred=kit selects nothing on open; a manually chosen kit is kept across idea edits', async t => {
  const h = mountHarness(t, async (path) => {
    if (path === '/scaffold/match') {
      return {
        matches: [{ template_id: 'ts-node-golden', name: 'TypeScript', options: {} }],
        closest: [],
        handoff: null,
        kits: [
          { ...KIT_CATALOG[2], score: 9, reasons: ['building: video'] },
          { ...KIT_CATALOG[0], score: 4, reasons: ['tag: render'] }
        ],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'kit',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/kits/video-production') return VIDEO_PREVIEW
    if (path === '/scaffold/kits/studio-3d') return { kit: KIT_CATALOG[0], tree: ['renders/'] }
    return {}
  })

  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()

  let modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), '', 'preferred=kit with a top kit match selects nothing')
  assert.equal(h.calls.some(c => c.path.startsWith('/scaffold/kits/')), false)

  await chooseRow(modal, 'kit:studio-3d')
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), 'kit:studio-3d')

  // Editing the idea several times keeps the chosen kit, before and after the matches run
  let timer = null
  h.ctx.setTimeout = fn => { timer = fn; return () => { timer = null } }
  for (const idea of ['video edit 1', 'video edit 2']) {
    await byDomId(modal, 'project-idea').props.onChange({ target: { value: idea } })
    tree = h.render()
    modal = byDomId(tree, 'new-project-dialog')
    assert.equal(checkedChoice(modal), 'kit:studio-3d', 'the chosen kit is kept when the idea changes')
    if (timer) await timer()
    tree = h.render()
    modal = byDomId(tree, 'new-project-dialog')
    assert.equal(checkedChoice(modal), 'kit:studio-3d', 'the chosen kit is kept after the new match')
  }
})

test('F4: template proposal tree does not have kit aria-label and template accept destination ignores top-level dest/path', async t => {
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') {
      return {
        matches: [{ template_id: 'ts-node-golden', name: 'TypeScript', options: { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } } }],
        closest: [],
        handoff: null,
        kits: [],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'template',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/propose') {
      return {
        proposal_id: 'prop-tpl-parity',
        template_id: opts.body.template_id,
        name: opts.body.name,
        slug: opts.body.name,
        tree: [{ name: opts.body.name, dest: `/srv/from-prop-repo/${opts.body.name}`, files: ['AGENTS.md', 'src/index.ts'] }]
      }
    }
    if (path === '/scaffold/accept') {
      return {
        status: 'created',
        dest: '/srv/wrong-top-level-dest',
        path: '/srv/wrong-top-level-path',
        repos: [{ name: 'inventory-api', registration: 'registered', registration_result: { registered: true } }]
      }
    }
    if (path === '/workspace/projects') {
      return {
        coverage: 'verified',
        projects: [{ name: 'inventory-api', path: '/srv/from-prop-repo/inventory-api', registered: true }]
      }
    }
    return {}
  })

  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()

  await typeProjectName(byDomId(tree, 'new-project-dialog'), 'inventory-api')
  await chooseRow(byDomId(tree, 'new-project-dialog'), 'template:ts-node-golden')
  tree = h.render()
  const modal = byDomId(tree, 'new-project-dialog')
  const proposalTree = byDomId(modal, 'proposal-tree')
  assert.ok(proposalTree)
  assert.equal(proposalTree.props['aria-label'], undefined, 'template proposal tree must not carry Folders this workspace creates aria-label')

  // Accept template project where repos[0].path is absent and top-level acc.dest is present:
  // The created-path expression `createdRepo?.path || propRepo?.dest || ''` must resolve to `/srv/from-prop-repo/inventory-api`
  await byDomId(modal, 'accept-project').props.onClick()
  tree = h.render()

  // Select the newly created project and verify its sessionCreatedFiles were keyed under propRepo.dest, not acc.dest
  const card = nodes(tree, n => n.props?.['data-project'] === 'inventory-api')[0]
  assert.ok(card)
  card.props.onClick()
  tree = h.render()
  assert.match(textOf(byDomId(tree, 'tree')), /AGENTS\.md/, 'template accept used the createdPath expression')
})

test('F6: parseHttpError extracts status/detail from IPC errors and kit propose HTTP 503 formats Project kits are unavailable + detail', async () => {
  assert.equal(typeof ui.parseHttpError, 'function', 'parseHttpError helper is exported')

  // 1. Plain 503 JSON error
  assert.deepEqual(
    ui.parseHttpError(new Error('503: {"detail":"componentize CLI is unavailable."}')),
    { status: 503, detail: 'componentize CLI is unavailable.' }
  )

  // 2. With Electron IPC prefix
  assert.deepEqual(
    ui.parseHttpError(new Error("Error invoking remote method 'hermes:api': Error: 503: {\"detail\":\"componentize CLI is unavailable.\"}")),
    { status: 503, detail: 'componentize CLI is unavailable.' }
  )

  // 3. Error object with statusCode: 503 and plain text message
  const errWithStatusCode = new Error('503: plain text')
  errWithStatusCode.statusCode = 503
  assert.deepEqual(
    ui.parseHttpError(errWithStatusCode),
    { status: 503, detail: 'plain text' }
  )

  // 4. Status 400 JSON error
  assert.deepEqual(
    ui.parseHttpError(new Error('400: {"detail":"Destination already exists"}')),
    { status: 400, detail: 'Destination already exists' }
  )

  // 5. Non-HTTP error (status null)
  assert.deepEqual(
    ui.parseHttpError(new Error('network down')),
    { status: null, detail: '' }
  )

  // 6. Detail that already starts with 'Project kits are unavailable'
  assert.deepEqual(
    ui.parseHttpError(new Error('503: {"detail":"Project kits are unavailable: componentize CLI is unavailable."}')),
    { status: 503, detail: 'Project kits are unavailable: componentize CLI is unavailable.' }
  )

  let errorToThrow = new Error("Error invoking remote method 'hermes:api': Error: 503: {\"detail\":\"componentize CLI is unavailable.\"}")
  const { model } = createModelFixture(async (path) => {
    if (path === '/scaffold/kits/video-production') return VIDEO_PREVIEW
    if (path === '/scaffold/propose') {
      throw errorToThrow
    }
    return {}
  })

  model.edit({ name: 'trailer-cut' })
  await model.selectKit('video-production')
  await model.propose()
  assert.equal(model.get().error, 'Project kits are unavailable: componentize CLI is unavailable.')

  // Detail already starting with 'Project kits are unavailable' must not print the phrase twice
  errorToThrow = new Error('503: {"detail":"Project kits are unavailable: componentize CLI is unavailable."}')
  await model.propose()
  assert.equal(model.get().error, 'Project kits are unavailable: componentize CLI is unavailable.')

  // 503 with empty detail shows 'Project kits are unavailable'
  errorToThrow = new Error('503: {"detail":""}')
  await model.propose()
  assert.equal(model.get().error, 'Project kits are unavailable')

  // Status 400 keeps generic error handling
  errorToThrow = new Error('400: {"detail":"Invalid project name"}')
  await model.propose()
  assert.equal(model.get().error, '400: {"detail":"Invalid project name"}')

  // ...except "Destination already exists", which is one plain sentence
  errorToThrow = new Error('400: {"detail":"Destination already exists"}')
  await model.propose()
  assert.equal(model.get().error, ui.CREATE_NAME_TAKEN_TEXT)

  // Network error (status null) keeps generic error handling
  errorToThrow = new Error('network down')
  await model.propose()
  assert.equal(model.get().error, 'network down')
})

test('F7: model exposes cleanKitAnswers and modal sends kit propose body built from answers that had layout and languages', async t => {
  const { model } = createModelFixture(async () => ({}))
  assert.equal(typeof model.cleanKitAnswers, 'function')
  assert.deepEqual(
    model.cleanKitAnswers({ layout: 'mono', languages: ['python'], engine: '', custom: 'yes' }),
    { building: 'other', custom: 'yes' }
  )

  let scheduledFn = null
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') {
      return {
        matches: [
          { template_id: 'ts-node-golden', name: 'TypeScript', options: {} },
          { template_id: 'python-golden', name: 'Python', options: {} }
        ],
        closest: [],
        handoff: null,
        kits: [],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'template',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/kits/video-production') return VIDEO_PREVIEW
    if (path === '/scaffold/propose') {
      return {
        proposal_id: 'prop-f7',
        kind: 'kit',
        kit_id: opts.body.kit_id,
        slug: opts.body.name,
        tree: [{ name: opts.body.name, dest: `/srv/${opts.body.name}`, files: ['renders/'] }]
      }
    }
    if (path === '/scaffold/accept') {
      return {
        status: 'created',
        kind: 'kit',
        kit_id: 'video-production',
        dest: '/srv/inventory-api',
        path: '/srv/inventory-api',
        placement: 'on',
        repos: [{ name: 'inventory-api', path: '/srv/inventory-api', registration: 'registered', registration_result: { registered: true } }]
      }
    }
    return {}
  })
  h.ctx.setTimeout = fn => { scheduledFn = fn; return () => { scheduledFn = null } }

  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()

  // Switch Tech stack to python-golden so answers in model include layout: 'mono' and languages: ['python']
  let modal = byDomId(tree, 'new-project-dialog')
  await typeProjectName(modal, 'inventory-api')
  await chooseRow(modal, 'template:python-golden')
  tree = h.render()
  const lastMatchBeforeKit = h.calls.filter(c => c.path === '/scaffold/match').at(-1)
  assert.deepEqual(lastMatchBeforeKit.opts.body.answers, { building: 'service', layout: 'mono', languages: ['python'] })

  // Select a kit and click Accept & create; modal must send answers cleaned of layout and languages
  modal = byDomId(tree, 'new-project-dialog')
  await chooseRow(modal, 'kit:video-production')
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'accept-project').props.onClick()
  tree = h.render()

  const proposeCall = h.calls.find(c => c.path === '/scaffold/propose')
  assert.ok(proposeCall, 'kit propose called from modal')
  assert.equal(proposeCall.opts.body.kit_id, 'video-production')
  assert.equal(Object.hasOwn(proposeCall.opts.body.answers, 'layout'), false)
  assert.equal(Object.hasOwn(proposeCall.opts.body.answers, 'languages'), false)
  assert.deepEqual(proposeCall.opts.body.answers, { building: 'service' })
  assert.match(ui.WorkspacePage.toString(), /model\.cleanKitAnswers\(/)
  assert.doesNotMatch(ui.WorkspacePage.toString(), /model\.get\(\)\.idea === modalIdea \? \{ idea: modalIdea \}/)
})

test('R1: idea-triggered match preserves valid non-default adapter choice and falls back to default when current adapter is invalid', async t => {
  let tsChoices = ['hono', 'node_http', 'legacy_http']
  let scheduledFn = null
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') {
      return {
        matches: [
          {
            template_id: 'ts-node-golden',
            name: 'TypeScript',
            options: {
              http_adapter: {
                label: 'HTTP adapter',
                default: 'hono',
                choices: tsChoices
              }
            }
          }
        ],
        closest: [],
        handoff: null,
        kits: [],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'template',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/propose') {
      return {
        proposal_id: 'prop-r1',
        template_id: opts.body.template_id,
        name: opts.body.name,
        slug: opts.body.name,
        tree: [{ name: opts.body.name, dest: `/srv/${opts.body.name}`, files: ['src/index.ts'] }]
      }
    }
    if (path === '/scaffold/accept') {
      return {
        status: 'created',
        repos: [{ name: 'inventory-api', path: '/srv/inventory-api', registration: 'registered', registration_result: { registered: true } }]
      }
    }
    return {}
  })
  h.ctx.setTimeout = fn => { scheduledFn = fn; return () => { scheduledFn = null } }

  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()

  let modal = byDomId(tree, 'new-project-dialog')
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, '', 'no adapter value before a template is chosen')
  await typeProjectName(modal, 'inventory-api')
  await chooseRow(modal, 'template:ts-node-golden')
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, 'hono')

  // 1. Pick non-default adapter 'node_http', edit idea, advance timer, let match resolve -> adapter stays 'node_http'
  await byDomId(modal, 'new-project-adapter').props.onChange({ target: { value: 'node_http' } })
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, 'node_http')

  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'lightweight node http service' } })
  tree = h.render()
  assert.ok(scheduledFn, 'idea match timer scheduled')
  await scheduledFn()
  tree = h.render()

  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, 'node_http', 'idea-triggered match keeps valid non-default adapter')

  // Accept sends 'node_http'
  await byDomId(modal, 'accept-project').props.onClick()
  tree = h.render()
  const proposeCall = h.calls.find(c => c.path === '/scaffold/propose')
  assert.ok(proposeCall)
  assert.deepEqual(proposeCall.opts.body.options, { http_adapter: 'node_http' })

  // 2. Re-open modal, pick 'legacy_http', then type an idea: the list reload does not ask
  // for the template's options again, so the held choice stays; picking the row again asks
  // for its options and starts from the server's default.
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()
  await chooseRow(byDomId(tree, 'new-project-dialog'), 'template:ts-node-golden')
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'new-project-adapter').props.onChange({ target: { value: 'legacy_http' } })
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, 'legacy_http')

  tsChoices = ['hono', 'node_http']
  h.calls.length = 0
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'updated service without legacy adapter' } })
  tree = h.render()
  assert.ok(scheduledFn)
  await scheduledFn()
  tree = h.render()
  assert.deepEqual(h.calls.filter(c => c.path === '/scaffold/match').map(c => c.opts.body), [{ prompt: 'updated service without legacy adapter', answers: {} }], 'only the list is asked for')
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, 'legacy_http', 'a list reload keeps the held option')

  await chooseRow(modal, 'template:python-golden')
  await chooseRow(byDomId(h.render(), 'new-project-dialog'), 'template:ts-node-golden')
  modal = byDomId(h.render(), 'new-project-dialog')
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, 'hono', 'picking the row again starts from the server default')
  assert.deepEqual(nodes(byDomId(modal, 'new-project-adapter'), n => n.type === 'option').map(o => o.props.value), ['hono', 'node_http'], 'with the server\'s current choices')
})

test('R2: choosing a template or kit row within 400ms clears pending idea timer; the pick asks only for the template options and the list request carries only the idea', async t => {
  const activeTimers = new Map()
  let nextTimerId = 1
  const h = mountHarness(t, async (path) => {
    if (path === '/scaffold/match') {
      return {
        matches: [
          { template_id: 'ts-node-golden', name: 'TypeScript', options: { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } } },
          { template_id: 'python-golden', name: 'Python', options: { http_adapter: { label: 'HTTP adapter', default: 'fastapi', choices: ['fastapi', 'stdlib_http'] } } }
        ],
        closest: [],
        handoff: null,
        kits: [],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'template',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/kits/video-production') return VIDEO_PREVIEW
    return {}
  })
  h.ctx.setTimeout = (fn, ms) => {
    const id = nextTimerId++
    activeTimers.set(id, { fn, ms })
    return () => activeTimers.delete(id)
  }

  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()
  h.calls.length = 0

  // Type in idea -> schedules 400ms timer
  let modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'fast python microservice' } })
  tree = h.render()
  assert.equal(activeTimers.size, 1, 'idea typing schedules 400ms timer')
  const [staleTimerEntry] = activeTimers.values()

  // Switch Tech stack before the 400ms delay
  modal = byDomId(tree, 'new-project-dialog')
  await chooseRow(modal, 'template:python-golden')
  tree = h.render()

  // Pending idea timer was cleared by Tech stack change
  assert.equal(activeTimers.size, 0, 'changing Tech stack clears pending idea timer')

  // Advance any remaining timers: exactly one match request was sent and it carries the NEW template's answers
  for (const entry of [...activeTimers.values()]) {
    activeTimers.clear()
    await entry.fn()
  }
  const matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1, 'exactly one match request is sent: the options of the chosen template')
  assert.deepEqual(matchCalls[0].opts.body, {
    answers: { building: 'service', layout: 'mono', languages: ['python'] },
    prompt: ''
  })

  // A list request fired after the pick still carries only the idea.
  h.calls.length = 0
  await staleTimerEntry.fn()
  tree = h.render()
  const fireTimeCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(fireTimeCalls.length, 1)
  assert.deepEqual(fireTimeCalls[0].opts.body, { prompt: 'fast python microservice', answers: {} })

  // Changing the kit also clears any pending idea timer
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'video shoot idea' } })
  tree = h.render()
  assert.equal(activeTimers.size, 1, 'idea typing schedules timer before kit change')
  modal = byDomId(tree, 'new-project-dialog')
  await chooseRow(modal, 'kit:video-production')
  tree = h.render()
  assert.equal(activeTimers.size, 0, 'changing kit clears pending idea timer')
})

test('R3: no match request carries languages_chosen; list requests carry only the idea, before and after a template row is chosen and across reopen', async t => {
  let scheduledFn = null
  const h = mountHarness(t, async path => {
    if (path === '/scaffold/match') {
      return {
        matches: [
          { template_id: 'ts-node-golden', name: 'TypeScript', options: { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } } },
          { template_id: 'python-golden', name: 'Python', options: { http_adapter: { label: 'HTTP adapter', default: 'fastapi', choices: ['fastapi', 'stdlib_http'] } } }
        ],
        closest: [],
        handoff: null,
        kits: [{ ...KIT_CATALOG[2], score: 9, reasons: ['building: video'] }],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'kit',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/kits/video-production') return VIDEO_PREVIEW
    return {}
  })
  h.ctx.setTimeout = fn => { scheduledFn = fn; return () => { scheduledFn = null } }

  // 1. Opening the dialog asks for the list with an empty idea and no answers
  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()

  let matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1)
  assert.deepEqual(matchCalls[0].opts.body, { prompt: '', answers: {} })

  // 2. Typing an idea asks for the list with that idea only
  h.calls.length = 0
  let modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'home server inventory for my homelab' } })
  tree = h.render()
  assert.ok(scheduledFn)
  await scheduledFn()
  tree = h.render()

  matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1)
  assert.deepEqual(matchCalls[0].opts.body, { prompt: 'home server inventory for my homelab', answers: {} })

  // 3. Choosing a template row asks only for its options: empty idea, the template's answers
  assert.equal(checkedChoice(byDomId(tree, 'new-project-dialog')), '', 'preferred=kit chose nothing')
  h.calls.length = 0
  modal = byDomId(tree, 'new-project-dialog')
  await chooseRow(modal, 'template:python-golden')
  tree = h.render()

  matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1)
  assert.deepEqual(matchCalls[0].opts.body, { prompt: '', answers: { building: 'service', layout: 'mono', languages: ['python'] } })

  // 4. With the row chosen, clear the idea and type a new one: the list request still carries only the idea
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: '' } })
  tree = h.render()
  h.calls.length = 0
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), 'template:python-golden')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'a video editing pipeline for film storyboards' } })
  tree = h.render()
  assert.ok(scheduledFn)
  await scheduledFn()
  tree = h.render()

  matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1)
  assert.deepEqual(matchCalls[0].opts.body, { prompt: 'a video editing pipeline for film storyboards', answers: {} })

  // 5. Close and reopen the dialog with the row still chosen: the same holds
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'cancel-project').props.onClick()
  tree = h.render()
  h.calls.length = 0
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), 'template:python-golden')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'another homelab inventory' } })
  tree = h.render()
  if (scheduledFn) await scheduledFn()
  tree = h.render()
  matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.ok(matchCalls.length >= 1)
  for (const call of matchCalls) {
    assert.deepEqual(Object.keys(call.opts.body).sort(), ['answers', 'prompt'])
    assert.deepEqual(call.opts.body.answers, {})
  }
})

test('R5: after a successful create nothing is chosen; a chosen template survives a kit idea; a kit idea never selects the kit; list requests carry only the idea', async t => {
  let scheduledFn = null
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') {
      const langs = opts?.body?.answers?.languages || []
      const chosen = langs.length > 0
      const prompt = String(opts?.body?.prompt || '')
      if (chosen) {
        const tplId = langs.includes('python') ? 'python-golden' : 'ts-node-golden'
        return {
          matches: [{
            template_id: tplId,
            name: tplId === 'python-golden' ? 'Python' : 'TypeScript',
            options: tplId === 'python-golden'
              ? { http_adapter: { label: 'HTTP adapter', default: 'fastapi', choices: ['fastapi', 'stdlib_http'] } }
              : { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } }
          }],
          closest: [],
          handoff: null,
          kits: [{ ...KIT_CATALOG[2], score: 9, reasons: ['building: video'] }],
          kit_catalog: KIT_CATALOG,
          kits_notice: '',
          preferred: 'template',
          catalog: catalog()
        }
      }
      if (/video/i.test(prompt)) {
        return {
          matches: [],
          closest: [],
          handoff: null,
          kits: [{ ...KIT_CATALOG[2], score: 9, reasons: ['building: video'] }],
          kit_catalog: KIT_CATALOG,
          kits_notice: '',
          preferred: 'kit',
          catalog: catalog()
        }
      }
      return {
        matches: [{ template_id: 'ts-node-golden', name: 'TypeScript', options: { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } } }],
        closest: [],
        handoff: null,
        kits: [],
        kit_catalog: KIT_CATALOG,
        kits_notice: '',
        preferred: 'template',
        catalog: catalog()
      }
    }
    if (path === '/scaffold/kits/video-production') return VIDEO_PREVIEW
    if (path === '/scaffold/propose') {
      return {
        proposal_id: `prop-${opts.body.name}`,
        template_id: opts.body.template_id,
        kit_id: opts.body.kit_id,
        kind: opts.body.kit_id ? 'kit' : 'template',
        name: opts.body.name,
        slug: opts.body.name,
        tree: [{ name: opts.body.name, dest: `/srv/${opts.body.name}`, files: ['AGENTS.md'] }]
      }
    }
    if (path === '/scaffold/accept') {
      return {
        ok: true,
        status: 'created',
        repos: [{ name: 'created-proj', path: '/srv/created-proj', registration: 'registered', registration_result: { registered: true } }]
      }
    }
    if (path === '/workspace/projects') {
      return { coverage: 'verified', projects: [] }
    }
    if (path === '/scaffold/discard') return { status: 'discarded' }
    return {}
  })
  h.ctx.setTimeout = fn => { scheduledFn = fn; return () => { scheduledFn = null } }

  // 1. Open dialog, touch menu to pick python-golden, then type a kit idea: keeps user's template (flag true)
  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()

  let modal = byDomId(tree, 'new-project-dialog')
  await typeProjectName(modal, 'inventory-api')
  await chooseRow(modal, 'template:python-golden')
  tree = h.render()

  h.calls.length = 0
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'set up a video project' } })
  tree = h.render()
  assert.ok(scheduledFn)
  await scheduledFn()
  tree = h.render()

  let matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1)
  assert.deepEqual(matchCalls[0].opts.body, { prompt: 'set up a video project', answers: {} }, 'the list request carries only the idea')
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), 'template:python-golden', 'menu keeps user template')
  assert.equal(h.calls.some(c => c.path.startsWith('/scaffold/kits/')), false, 'the kit is not selected')

  // 2. Picking another template row asks only for that template's options
  h.calls.length = 0
  await chooseRow(modal, 'template:ts-node-golden')
  tree = h.render()
  matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1)
  assert.deepEqual(matchCalls[0].opts.body, { prompt: '', answers: { building: 'service', layout: 'mono', languages: ['typescript'] } })

  // Switch back to python-golden and complete a successful create
  modal = byDomId(tree, 'new-project-dialog')
  await chooseRow(modal, 'template:python-golden')
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'accept-project').props.onClick()
  tree = h.render()
  assert.equal(byDomId(tree, 'new-project-dialog'), undefined, 'modal closed after successful create')

  // 3. Reopen modal after successful create -> nothing is chosen
  h.calls.length = 0
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), '', 'nothing chosen after successful create')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true)
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, '', 'adapter resets after successful create')

  h.calls.length = 0
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'another video project' } })
  tree = h.render()
  assert.ok(scheduledFn)
  await scheduledFn()
  tree = h.render()

  matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1)
  assert.deepEqual(matchCalls[0].opts.body, { prompt: 'another video project', answers: {} })
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(checkedChoice(modal), '', 'a kit idea marks rows but selects nothing')
})

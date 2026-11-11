import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'
import { catalog, checkedChoice, choiceRadios, chooseRow, typeProjectName } from './choiceList.mjs'

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
      if (path === '/scaffold/match') {
        return {
          matches: [
            { template_id: 'ts-node-golden', name: 'TypeScript', options: { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } } },
            { template_id: 'rust-golden', name: 'Rust', options: {} },
            { template_id: 'python-golden', name: 'Python', options: { http_adapter: { label: 'HTTP adapter', default: 'fastapi', choices: ['fastapi', 'stdlib_http'] } } },
            { template_id: 'go-golden', name: 'Go', options: {} },
            { template_id: 'cpp-golden', name: 'C++', options: {} },
            { template_id: 'dotnet-golden', name: '.NET', options: {} }
          ],
          closest: [],
          handoff: null,
          catalog: catalog()
        }
      }
      if (path === '/scaffold/discard') {
        return { status: 'discarded' }
      }
      if (path === '/scaffold/projects-root' || path.startsWith('/scaffold/projects-root?')) {
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

test('Fix2 Gap 1: V10 top bar has no legacy nav (Projects / Start Project / Adopted copy inspector / Pro), /defuzz/new wizard route and StartProjectView are removed, and unreachable Componentize/validRuleId/tour remnants are gone', t => {
  const h = mountHarness(t, 'main')
  const tree = h.render('main')
  const topBar = byId(tree, 'v10-top-bar')
  assert.ok(topBar, 'V10 top bar renders')
  assert.equal(byLabel(tree, 'Project workspace'), undefined, 'legacy Project workspace nav bar removed from top bar')
  for (const legacyLabel of ['Projects', 'Start Project', 'Adopted copy inspector', 'Pro']) {
    assert.equal(nodes(topBar, n => n.type === 'Button' && textOf(n) === legacyLabel).length, 0, `top bar must not render legacy nav button ${legacyLabel}`)
  }
  assert.ok(byDomId(topBar, 'start-project'), 'top bar has Start project modal button')
  assert.ok(byDomId(topBar, 'settings-button'), 'top bar has Settings button')

  assert.equal(ui.StartProjectView, undefined, 'old StartProjectView wizard removed')
  assert.equal(ui.validRuleId, undefined, 'unused validRuleId removed')
  assert.equal(ui.WORKSPACE_SCREENS.some(s => s.path === '/defuzz/new' || s.screen === 'start'), false, '/defuzz/new wizard route removed')
  assert.equal(ui.WORKSPACE_SCREENS.length, 4, '4 routes remain (main, its /projects alias, settings, inspector); Pro is gone')

  const liveModel = ui.createLiveModel(h.ctx)
  assert.equal(liveModel.loadComponentize, undefined, 'unreachable loadComponentize removed')
  assert.equal(liveModel.editComponentize, undefined, 'unreachable editComponentize removed')
  assert.equal(liveModel.saveComponentize, undefined, 'unreachable saveComponentize removed')
})

test('Fix2 Gap 2: Stale /audit/scope response from previous modal opening is ignored and cannot enable consent after current scope failed', async t => {
  let resolveOldFullScope
  const h = mountHarness(t, 'main', [
    () => new Promise(resolve => { resolveOldFullScope = resolve }),
    new Error('quick scope service unavailable')
  ])
  let tree = h.render('main')

  // 1. Open Full (scope held)
  const openFullPromise = byDomId(tree, 'audit-full-button').props.onClick()
  tree = h.render('main')
  assert.ok(byDomId(tree, 'audit-review-dialog'), 'Full audit dialog open')

  // 2. Cancel / close Full modal while scope #1 is still in flight
  const cancelBtn = nodes(byDomId(tree, 'audit-review-dialog'), n => n.type === 'Button' && textOf(n) === 'Cancel')[0]
  cancelBtn.props.onClick()
  tree = h.render('main')
  assert.equal(byDomId(tree, 'audit-review-dialog'), undefined, 'modal closed on Cancel')

  // 3. Open Quick -> scope #2 rejects
  await byDomId(tree, 'audit-quick-button').props.onClick()
  tree = h.render('main')
  let modal = byDomId(tree, 'audit-review-dialog')
  assert.ok(modal, 'Quick audit dialog open')
  assert.equal(byDomId(modal, 'audit-review-consent').props.disabled, true, 'consent disabled after Quick scope failure')
  assert.equal(byDomId(modal, 'audit-review-run').props.disabled, true, 'Run disabled after Quick scope failure')

  // 4. Resolve old Full scope -> must be ignored!
  resolveOldFullScope({ scope_disclosure: 'Stale Full Scope Disclosure' })
  await openFullPromise
  tree = h.render('main')
  modal = byDomId(tree, 'audit-review-dialog')
  assert.equal(byDomId(modal, 'audit-review-consent').props.disabled, true, 'consent MUST stay disabled when stale Full scope resolves')
  assert.equal(byDomId(modal, 'audit-review-run').props.disabled, true, 'Run MUST stay disabled when stale Full scope resolves')
  assert.doesNotMatch(textOf(modal), /Stale Full Scope Disclosure/, 'stale scope disclosure must not render')
})

test('Fix2 Gap 3: Start project sends valid template options for all 6 templates (http_adapter for TS/Python, empty options {} for Rust/Go/C++/.NET)', async t => {
  const parseTemplateYamlOptions = templateId => {
    const raw = readFileSync(new URL(`../../templates/${templateId}/template.yaml`, import.meta.url), 'utf8')
    if (!/^options:\s*$/m.test(raw)) return {}
    const afterOptions = raw.split(/^options:\s*$/m)[1].split(/^[a-z_]+:\s*$/m)[0]
    const keyMatch = afterOptions.match(/^\s{2}([a-z_]+):\s*$/m)
    const choicesMatch = afterOptions.match(/choices:\s*\[([^\]]+)\]/)
    if (!keyMatch || !choicesMatch) return {}
    return {
      [keyMatch[1]]: choicesMatch[1].split(',').map(s => s.trim())
    }
  }

  for (const tpl of ui.V10_TEMPLATES) {
    const templateId = tpl.id
    const yamlOptions = parseTemplateYamlOptions(templateId)
    const declaredKeys = Object.keys(yamlOptions)
    const slug = `proj-${templateId.split('-')[0]}`
    const h = mountHarness(t, 'main', [
      { proposal_id: `prop-${slug}`, tree: [{ name: slug, dest: `/p/${slug}`, files: ['AGENTS.md'] }] },
      { ok: true, status: 'created', repos: [{ name: slug, path: `/p/${slug}`, registration: 'registered', registration_result: { registered: true } }] },
      { coverage: 'verified', projects: [{ name: slug, path: `/p/${slug}`, registered: true, template_id: templateId }] }
    ])
    let tree = h.render('main')
    await byDomId(tree, 'start-project').props.onClick()
    tree = h.render('main')

    const modal = byDomId(tree, 'new-project-dialog')
    await chooseRow(modal, `template:${templateId}`)
    tree = h.render('main')
    const nameInput = byDomId(byDomId(tree, 'new-project-dialog'), 'new-project-name') || byLabel(byDomId(tree, 'new-project-dialog'), 'Project name')
    nameInput.props.onChange({ target: { value: slug } })
    tree = h.render('main')

    await byDomId(byDomId(tree, 'new-project-dialog'), 'accept-project').props.onClick()
    const proposeCall = h.calls.find(c => c.path === '/scaffold/propose')
    assert.ok(proposeCall, `propose called for ${templateId}`)
    assert.equal(proposeCall.opts.body.template_id, templateId)
    if (declaredKeys.length === 0) {
      assert.deepEqual(proposeCall.opts.body.options, {}, `${templateId} defines no options in template.yaml and must send {}`)
    } else {
      assert.deepEqual(Object.keys(proposeCall.opts.body.options), declaredKeys, `${templateId} must only send declared option keys`)
      for (const k of declaredKeys) {
        assert.ok(yamlOptions[k].includes(proposeCall.opts.body.options[k]), `${templateId} option ${k} must be one of ${yamlOptions[k].join(', ')}`)
      }
    }
  }
})

test('Fix2 Gap 4: Failed accept then rename discards old proposal, re-proposes new project, disables inputs while busy, displays server proposal tree, and announces backend-returned name', async t => {
  let resolveSecondPropose
  const acceptFailErr = Object.assign(new Error('staged check failed'), { body: { stderr: 'ci check failed', created_dirs: [] } })
  const h = mountHarness(t, 'main', [
    { proposal_id: 'prop-inv', tree: [{ name: 'inventory-api', dest: '/srv/inventory-api', files: ['AGENTS.md', 'src/from_server_inv.ts'] }] },
    acceptFailErr,
    () => new Promise(resolve => { resolveSecondPropose = resolve }),
    { ok: true, status: 'created', repos: [{ name: 'different-project-server', path: '/srv/different-project', registration: 'registered', registration_result: { registered: true } }] },
    { coverage: 'verified', projects: [{ name: 'different-project-server', path: '/srv/different-project', registered: true, template_id: 'ts-node-golden' }] }
  ])

  let tree = h.render('main')
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render('main')
  await typeProjectName(byDomId(tree, 'new-project-dialog'), 'inventory-api')
  await chooseRow(byDomId(tree, 'new-project-dialog'), 'template:ts-node-golden')
  tree = h.render('main')

  // 1. First accept of inventory-api fails
  await byDomId(byDomId(tree, 'new-project-dialog'), 'accept-project').props.onClick()
  tree = h.render('main')
  let modal = byDomId(tree, 'new-project-dialog')
  assert.ok(modal, 'modal stays open after failed accept')
  assert.match(textOf(byDomId(modal, 'proposal-tree')), /src\/from_server_inv\.ts/, 'displays SERVER proposal tree, not hardcoded paths')
  assert.equal(textOf(byDomId(modal, 'proposal-destination')), '/srv/inventory-api', 'displays server proposal destination')

  // 2. Rename to different-project -> must discard old proposal
  const nameInput = byDomId(modal, 'new-project-name') || byLabel(modal, 'Project name')
  nameInput.props.onChange({ target: { value: 'different-project' } })
  tree = h.render('main')
  modal = byDomId(tree, 'new-project-dialog')

  // 3. Click Accept & create -> holds on second /scaffold/propose; inputs must be disabled while pending
  const secondAcceptPromise = byDomId(modal, 'accept-project').props.onClick()
  tree = h.render('main')
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal((byDomId(modal, 'new-project-name') || byLabel(modal, 'Project name')).props.disabled, true, 'name input disabled while proposal pending')
  assert.equal((byDomId(modal, 'project-idea') || byLabel(modal, 'Project idea')).props.disabled, true, 'idea input disabled while proposal pending')
  assert.ok(choiceRadios(modal).length > 0 && choiceRadios(modal).every(r => r.props.disabled === true), 'list rows disabled while proposal pending')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true, 'accept button disabled while proposal pending')

  // 4. Resolve second propose and accept
  resolveSecondPropose({ proposal_id: 'prop-diff', tree: [{ name: 'different-project-server', dest: '/srv/different-project', files: ['AGENTS.md', 'src/from_server_diff.ts'] }] })
  await secondAcceptPromise
  tree = h.render('main')

  const proposeCalls = h.calls.filter(c => c.path === '/scaffold/propose')
  const acceptCalls = h.calls.filter(c => c.path === '/scaffold/accept')
  assert.equal(proposeCalls.length, 2, 'must re-propose after rename')
  assert.equal(proposeCalls[1].opts.body.name, 'different-project', 'second propose sends new name different-project')
  assert.equal(acceptCalls.length, 2)
  assert.equal(acceptCalls[1].opts.body.proposal_id, 'prop-diff', 'second accept uses new proposal_id prop-diff')
  assert.match(textOf(byDomId(tree, 'status')), /different-project-server/, 'announces name returned by backend')
})

test('Fix2 Gap 5: File tree never uses fabricated paths when project has no file list, and preview attribution ignores out-of-order responses and unaccepted clicks', async t => {
  let resolvePkg, resolveBiome
  const h = mountHarness(t, 'main', [
    // Load 1: project without files or locked_hashes
    { coverage: 'verified', projects: [{ name: 'bare-proj', path: '/p/bare', registered: true, template_id: 'ts-node-golden' }] },
    // Load 2: project with real locked_hashes
    { coverage: 'verified', projects: [{ name: 'real-proj', path: '/p/real', registered: true, template_id: 'ts-node-golden', locked_hashes: { 'AGENTS.md': 'h1', 'package.json': 'h2', 'biome.json': 'h3' } }] },
    // Preview 1: AGENTS.md
    { path: 'AGENTS.md', content: '# Real AGENTS.md' },
    // Preview 2: package.json (held)
    () => new Promise(resolve => { resolvePkg = resolve }),
    // Preview 3: biome.json (held)
    () => new Promise(resolve => { resolveBiome = resolve })
  ])

  let tree = h.render('main')
  // Before any project is loaded/selected, must not show fabricated paths
  assert.equal(nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'packages/adapters/http-hono/src/index.ts').length, 0, 'no fabricated template paths before project load')

  // Load bare-proj (no files, no locked_hashes)
  await nodes(tree, n => n.type === 'Button' && textOf(n) === 'Refresh projects')[0].props.onClick()
  tree = h.render('main')
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'bare-proj')[0].props.onClick()
  tree = h.render('main')
  assert.equal(nodes(byDomId(tree, 'tree'), n => n.props?.['data-path']).length, 0, 'bare project with no file list renders zero fabricated file rows')
  assert.match(textOf(byDomId(tree, 'tree')), /unavailable/i, 'shows explicit file listing unavailable state')

  // Load real-proj with locked_hashes: AGENTS.md, package.json, biome.json
  await nodes(tree, n => n.type === 'Button' && textOf(n) === 'Refresh projects')[0].props.onClick()
  tree = h.render('main')
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'real-proj')[0].props.onClick()
  tree = h.render('main')

  // 1. Load AGENTS.md
  await nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'AGENTS.md')[0].props.onClick()
  tree = h.render('main')
  assert.equal(textOf(byDomId(tree, 'file-title')), 'AGENTS.md')
  assert.match(textOf(byDomId(tree, 'editor')), /Real AGENTS\.md/)

  // 2. Click package.json (held)
  const pkgPromise = nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'package.json')[0].props.onClick()
  tree = h.render('main')

  // 3. Click biome.json (held)
  const biomePromise = nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'biome.json')[0].props.onClick()
  tree = h.render('main')

  // 4. Resolve stale package.json -> viewer must NEVER show package.json content under biome.json!
  resolvePkg({ path: 'package.json', content: '{"name":"STALE_PACKAGE_JSON"}' })
  await pkgPromise
  tree = h.render('main')
  assert.equal(textOf(byDomId(tree, 'file-title')), 'biome.json')
  assert.doesNotMatch(textOf(byDomId(tree, 'editor')), /STALE_PACKAGE_JSON/, 'viewer must never show package.json content under biome.json')

  // 5. Resolve current biome.json -> viewer shows biome.json content under biome.json
  resolveBiome({ path: 'biome.json', content: '{"linter":{"enabled":true}}' })
  await biomePromise
  tree = h.render('main')
  assert.equal(textOf(byDomId(tree, 'file-title')), 'biome.json')
  assert.match(textOf(byDomId(tree, 'editor')), /"linter"/)
})

test('Fix2 Gap 6: Divider sets/releases pointer capture, computes split percent from measured container width (getBoundingClientRect), clamps to [20,80], and grid columns sum to 100%', t => {
  const h = mountHarness(t, 'main')
  let tree = h.render('main')

  const cols = nodes(tree, n => n.props?.className === 'columns')[0]
  assert.doesNotMatch(cols.props.style.gridTemplateColumns, /42%/, 'grid columns must not be 58% + 7px + 42% (>100%)')
  assert.match(cols.props.style.gridTemplateColumns, /1fr/, 'right column uses 1fr so columns sum to 100%')

  let capturedId = null
  let releasedId = null
  const mockTarget = {
    setPointerCapture(id) { capturedId = id },
    releasePointerCapture(id) { releasedId = id },
    parentElement: {
      getBoundingClientRect: () => ({ width: 500 })
    }
  }

  const divider = byDomId(tree, 'pane-divider')
  divider.props.onPointerDown({ button: 0, pointerId: 9, clientX: 290, currentTarget: mockTarget, preventDefault() {} })
  assert.equal(capturedId, 9, 'setPointerCapture called on pointerdown')

  // Move left by 100px on a 500px container => -20% => 58% - 20% = 38% (NOT 48% from 10px/pt)
  byDomId(h.render('main'), 'pane-divider').props.onPointerMove({ pointerId: 9, clientX: 190, currentTarget: mockTarget })
  tree = h.render('main')
  assert.equal(byDomId(tree, 'pane-divider').props['aria-valuenow'], 38, 'computes percent from measured 500px container width')

  // Clamp to [20, 80]
  byDomId(tree, 'pane-divider').props.onPointerMove({ pointerId: 9, clientX: -500, currentTarget: mockTarget })
  tree = h.render('main')
  assert.equal(byDomId(tree, 'pane-divider').props['aria-valuenow'], 20, 'clamps minimum split to 20%')

  byDomId(tree, 'pane-divider').props.onPointerUp({ pointerId: 9, currentTarget: mockTarget })
  assert.equal(releasedId, 9, 'releasePointerCapture called on pointerup')
})

test('Fix2 Gap 7: Modals move focus to explicit initial target on open, mark background inert/aria-hidden while open, and keep Tab wrap, Escape, and focus restore', async t => {
  const h = mountHarness(t, 'main', [{ scope_disclosure: 'Live scope' }])
  let tree = h.render('main')

  assert.equal(byId(tree, 'v10-top-bar').props.inert, undefined, 'top bar not inert when modal closed')
  assert.equal(byDomId(tree, 'workspace').props.inert, undefined, 'workspace not inert when modal closed')

  let openerFocused = 0
  const opener = { focus() { openerFocused += 1 } }
  byDomId(tree, 'start-project').props.onClick({ currentTarget: opener })
  tree = h.render('main')

  assert.equal(byId(tree, 'v10-top-bar').props.inert, true, 'top bar is inert while Start project modal is open')
  assert.equal(byDomId(tree, 'workspace').props.inert, true, 'workspace is inert while Start project modal is open')
  assert.equal(byDomId(tree, 'workspace').props['aria-hidden'], 'true', 'workspace has aria-hidden=true while modal is open')

  const modal = byDomId(tree, 'new-project-dialog')
  const ideaInput = byDomId(modal, 'project-idea') || byLabel(modal, 'Project idea')
  assert.ok(ideaInput, 'project-idea input exists')
  assert.equal(ideaInput.props.autoFocus, true, 'project-idea is explicit initial focus target in Start project modal')

  // Tab wrap forward & backward inside modal
  let firstFocused = 0, lastFocused = 0
  const firstEl = { disabled: false, tabIndex: 0, focus() { firstFocused += 1 } }
  const lastEl = { disabled: false, tabIndex: 0, focus() { lastFocused += 1 } }
  modal.props.onKeyDown({
    key: 'Tab',
    shiftKey: false,
    target: lastEl,
    currentTarget: { querySelectorAll: () => [firstEl, lastEl] },
    preventDefault() {}
  })
  assert.equal(firstFocused, 1, 'Tab on last element wraps focus to first element')
  modal.props.onKeyDown({
    key: 'Tab',
    shiftKey: true,
    target: firstEl,
    currentTarget: { querySelectorAll: () => [firstEl, lastEl] },
    preventDefault() {}
  })
  assert.equal(lastFocused, 1, 'Shift+Tab on first element wraps focus to last element')

  // Escape closes modal, restores focus to opener, and clears background inert
  modal.props.onKeyDown({ key: 'Escape', preventDefault() {} })
  tree = h.render('main')
  assert.equal(byDomId(tree, 'new-project-dialog'), undefined)
  assert.equal(openerFocused, 1, 'focus restored to opener on Escape')
  assert.equal(byDomId(tree, 'workspace').props.inert, undefined, 'background inert cleared when modal closes')

  // Audit review modal & Plugin storage modal also set initial focus target and background inert
  await byDomId(tree, 'audit-full-button').props.onClick({ currentTarget: opener })
  tree = h.render('main')
  assert.equal(byDomId(tree, 'workspace').props.inert, true, 'workspace inert while audit modal open')
  assert.ok(nodes(byDomId(tree, 'audit-review-dialog'), n => n.props?.autoFocus === true)[0], 'audit modal has explicit initial focus target')
  byDomId(tree, 'audit-review-dialog').props.onKeyDown({ key: 'Escape', preventDefault() {} })
  tree = h.render('main')
  assert.equal(openerFocused, 2, 'focus restored on audit modal Escape')

  byDomId(tree, 'plugin-storage-button').props.onClick({ currentTarget: opener })
  tree = h.render('main')
  assert.equal(byDomId(tree, 'workspace').props.inert, true, 'workspace inert while storage modal open')
  assert.ok(nodes(byDomId(tree, 'plugin-storage-dialog'), n => n.props?.autoFocus === true)[0], 'storage modal has explicit initial focus target')
  byDomId(tree, 'plugin-storage-dialog').props.onKeyDown({ key: 'Escape', preventDefault() {} })
  tree = h.render('main')
  assert.equal(openerFocused, 3, 'focus restored on storage modal Escape')
})

test('Fix2 Gap 8: Settings Save checks initializes from saved settings (keeping disabled Biome+Ruff disabled) and never announces saved on GET or PUT failure', async t => {
  // Part 1: Saved disabled Biome + Ruff stay disabled after load + Save
  const savedRules = [
    { id: 'biome', label: 'Formatting & style', mode: 'both', enabled: false },
    { id: 'ruff', label: 'Python diagnostics', mode: 'both', enabled: false }
  ]
  const h = mountHarness(t, 'settings', [
    { seq: 3, value: { rules: savedRules } },
    { seq: 4, value: { rules: savedRules } },
    { seq: 4, value: { rules: savedRules } }
  ])
  let tree = h.render('settings')
  byDomId(tree, 'lint-tab').props.onClick()
  tree = h.render('settings')

  await byDomId(tree, 'lint-save').props.onClick()
  tree = h.render('settings')

  const postCall = h.calls.find(c => c.path === '/ui-state' && c.opts?.method === 'POST')
  assert.ok(postCall, 'Save checks POSTs to /ui-state')
  const postedRules = postCall.opts.body.value.rules
  assert.equal(postedRules.find(r => r.id === 'biome')?.enabled, false, 'saved disabled Biome stays disabled after load+Save')
  assert.equal(postedRules.find(r => r.id === 'ruff')?.enabled, false, 'saved disabled Ruff stays disabled after load+Save')
  assert.equal(byLabel(byDomId(tree, 'lint-panel'), 'Enable Biome').props.checked, false, 'Biome checkbox reflects disabled state')

  // Part 2: Failed settings GET => never claims 'Lint tool preferences saved.'
  const hFail = mountHarness(t, 'settings', [new Error('settings GET failed')])
  let failTree = hFail.render('settings')
  byDomId(failTree, 'lint-tab').props.onClick()
  failTree = hFail.render('settings')
  await byDomId(failTree, 'lint-save').props.onClick()
  failTree = hFail.render('settings')
  const statusText = textOf(byDomId(failTree, 'settings-status'))
  assert.doesNotMatch(statusText, /Lint tool preferences saved/i, 'failed GET must never show Lint tool preferences saved.')
  assert.match(statusText, /settings GET failed|error|failed/i, 'failed GET shows error in settings status')

  // Part 3: Failed settings write => never claims 'Lint tool preferences saved.'
  const hWriteFail = mountHarness(t, 'settings', [
    { seq: 1, value: { rules: savedRules } },
    new Error('settings write rejected')
  ])
  let writeFailTree = hWriteFail.render('settings')
  byDomId(writeFailTree, 'lint-tab').props.onClick()
  writeFailTree = hWriteFail.render('settings')
  await byDomId(writeFailTree, 'lint-save').props.onClick()
  writeFailTree = hWriteFail.render('settings')
  const writeStatusText = textOf(byDomId(writeFailTree, 'settings-status'))
  assert.doesNotMatch(writeStatusText, /Lint tool preferences saved/i, 'failed write must never show Lint tool preferences saved.')
  assert.match(writeStatusText, /settings write rejected|error|failed/i, 'failed write shows error in settings status')
})

test('Fix2 Gap 9: Footer lint state is keyed by project (switching project isolates job/result, stale jobs and unmount isolated) and backend {state:"failed", ok:false, error} reports failure instead of Lint completed', async t => {
  let resolveStaleOne, resolveUnmountLint
  const h = mountHarness(t, 'main', [
    { coverage: 'verified', projects: [
      { name: 'proj-one', path: '/p/one', registered: true, template_id: 'ts-node-golden' },
      { name: 'proj-two', path: '/p/two', registered: true, template_id: 'python-golden' }
    ] },
    { state: 'running', job_id: 'job-one' },
    { state: 'done', ok: true, findings: [{ file: 'two.py', line: 1, tool: 'ruff', rule: 'F401', message: 'unused' }] },
    { state: 'failed', job_id: 'job-one', ok: false, error: 'biome crashed with exit code 2' },
    () => new Promise(resolve => { resolveStaleOne = resolve }),
    () => new Promise(resolve => { resolveUnmountLint = resolve })
  ])

  let tree = h.render('main')
  await nodes(tree, n => n.type === 'Button' && textOf(n) === 'Refresh projects')[0].props.onClick()
  tree = h.render('main')

  // Select /p/one and start lint -> returns running job-one
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'proj-one')[0].props.onClick()
  tree = h.render('main')
  await byId(tree, 'footer-lint-play').props.onClick()
  tree = h.render('main')
  assert.match(textOf(byDomId(tree, 'status')), /job-one/)

  // Switch to /p/two -> must NOT show /p/one's job or poll /lint/job-one
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'proj-two')[0].props.onClick()
  tree = h.render('main')
  assert.equal(byId(tree, 'footer-lint-output'), undefined, 'switching project hides previous project lint output')
  await byId(tree, 'footer-lint-play').props.onClick()
  tree = h.render('main')
  assert.deepEqual(h.calls[2], { path: '/lint', opts: { method: 'POST', body: { project: '/p/two', mode: 'both' } } }, 'clicking LINT on /p/two starts POST /lint for /p/two, not GET /lint/job-one')

  // Switch back to /p/one and poll job-one -> returns { state: 'failed', ok: false, error: 'biome crashed with exit code 2' }
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'proj-one')[0].props.onClick()
  tree = h.render('main')
  await byId(tree, 'footer-lint-play').props.onClick()
  tree = h.render('main')
  assert.equal(h.calls[3].path, '/lint/job-one', 'polls /p/one running job when back on /p/one')
  const notice = textOf(byDomId(tree, 'status'))
  assert.doesNotMatch(notice, /Lint completed/i, 'failed lint job must not announce Lint completed.')
  assert.match(notice, /biome crashed with exit code 2|failed/i, 'failed lint job announces failure')

  // Stale in-flight lint job: start lint on /p/one (held), switch to /p/two, resolve /p/one -> must not overwrite /p/two output
  const stalePromise = byId(tree, 'footer-lint-play').props.onClick()
  nodes(byDomId(h.render('main'), 'project-cards'), n => n.props?.['data-project'] === 'proj-two')[0].props.onClick()
  resolveStaleOne({ state: 'done', ok: true, findings: [{ file: 'stale-one.ts', line: 9, message: 'stale' }] })
  await stalePromise
  tree = h.render('main')
  assert.doesNotMatch(JSON.stringify(byId(tree, 'footer-lint-output')), /stale-one\.ts/, 'stale /p/one response must not display under /p/two')

  // Unmount isolation: start lint on /p/two (held), unmount, resolve
  const unmountLintPromise = byId(tree, 'footer-lint-play').props.onClick()
  h.unmount()
  resolveUnmountLint({ state: 'done', ok: true, findings: [] })
  await unmountLintPromise
})

test('Fix2 Gap 10: Late /audit/status response after unmount or superseded run does not recreate polling timer', async t => {
  let resolveInitialStatus
  const h = mountHarness(t, 'main', [
    { scope_disclosure: 'Live scope disclosure' },
    { run_id: 'run-late', status: 'running' },
    () => new Promise(resolve => { resolveInitialStatus = resolve })
  ])

  let tree = h.render('main')
  await byDomId(tree, 'audit-full-button').props.onClick()
  tree = h.render('main')
  const modal = byDomId(tree, 'audit-review-dialog')
  byDomId(modal, 'audit-review-consent').props.onChange({ target: { checked: true } })
  tree = h.render('main')

  // Start audit -> /audit/start resolves, initial /audit/status is held
  const runPromise = byDomId(byDomId(tree, 'audit-review-dialog'), 'audit-review-run').props.onClick()
  for (let i = 0; i < 4 && !resolveInitialStatus; i++) await Promise.resolve()
  assert.equal(typeof resolveInitialStatus, 'function', 'initial /audit/status request is in flight')

  // Unmount while initial /audit/status is in flight
  h.unmount()
  resolveInitialStatus({ run_id: 'run-late', status: 'running' })
  await runPromise

  assert.equal(h.intervals.size, 0, 'late /audit/status after unmount must NOT register a polling interval')
})

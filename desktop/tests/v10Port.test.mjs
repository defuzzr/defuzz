import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'
import { catalog, chooseRow, typeProjectName } from './choiceList.mjs'

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
      if (path === '/scaffold/projects-root' || String(path).startsWith('/scaffold/projects-root?')) {
        return { path: '/home/user/Tools', source: 'setting', valid: true, default_path: '/home/user/Tools', message: '' }
      }
      if (path === '/scaffold/match') {
        return { matches: [{ template_id: 'ts-node-golden', options: { http_adapter: { label: 'HTTP adapter', default: 'hono', choices: ['hono', 'node_http'] } } }], closest: [], handoff: null, catalog: catalog() }
      }
      if (path === '/scaffold/discard') return { status: 'discarded' }
      if (path === '/componentize/settings' && !opts?.method) return { enabled_on_adopt: true, run_survey_on_new: false, cli_path_override: null }
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

test('Gap 1 & 9: V10 replaces pre-V10 UI completely — no legacy components, no legacy strings, themed fills except modal scrims', t => {
  const source = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')
  const withoutScrims = source.replace(/const\s+MODAL_SCRIM\s*=\s*\{[^}]*\}/g, '')
  assert.doesNotMatch(withoutScrims, /rgba\(/i, 'only modal dimming scrims use literal rgba(); other fills use theme tokens')

  assert.equal(ui.ONBOARDING_TOUR_STEPS, undefined, 'Onboarding tour steps removed')
  assert.equal(ui.OnboardingTourBar, undefined, 'OnboardingTourBar removed')
  assert.equal(ui.StationScriptsSection, undefined, 'StationScriptsSection removed')
  assert.equal(ui.AuditPaneView, undefined, 'AuditPaneView removed')
  assert.equal(ui.AuditTriggerButton, undefined, 'AuditTriggerButton removed')
  assert.equal(ui.ComponentizeSettingsView, undefined, 'ComponentizeSettingsView removed')

  const forbidden = ['= Project defuzz =', '* SCRIPTS', 'PROJECT Build Editor', '[Onboarding]', '* Settings MENU', '[RETURN]', '◈ defuzz Station', 'Embedded window inside the kernel Popup']
  for (const screen of ['main', 'settings', 'adopt']) {
    const h = mountHarness(t, screen)
    const rendered = JSON.stringify(h.render(screen))
    for (const legacy of forbidden) {
      assert.equal(rendered.includes(legacy), false, `screen ${screen} must not contain legacy string ${legacy}`)
    }
  }
})

test('Gap 2: Single audit launch path — no /defuzz/audit route, no Audit nav button, no Settings or inspector audit trigger', t => {
  assert.equal(ui.WORKSPACE_SCREENS.some(s => s.screen === 'audit' || s.path.endsWith('/audit')), false, 'audit route removed from WORKSPACE_SCREENS')
  const entries = []
  ui.default.register({ register: e => entries.push(e) })
  assert.equal(entries.some(e => e.data?.path === '/defuzz/audit'), false, 'no /defuzz/audit registration')

  for (const screen of ['main', 'settings', 'adopt']) {
    const h = mountHarness(t, screen)
    const tree = h.render(screen)
    assert.equal(byDomId(tree, 'audit-run'), undefined)
    assert.equal(nodes(tree, n => n.type === 'Button' && textOf(n) === 'Audit').length, 0)
  }
})

test('Gap 3 & 4: Audit consent dialog requires live /audit/scope, clears on open, renders scope & boundaries, and polls async status via ctx.setInterval until completed', async t => {
  // Probe 1: Failed scope => consent & Run stay disabled
  const hFail = mountHarness(t, 'main', [new Error('scope service down')])
  let treeFail = hFail.render()
  await (byDomId(treeFail, 'audit-full-button') || byId(treeFail, 'audit-full-button')).props.onClick()
  treeFail = hFail.render()
  const failModal = byDomId(treeFail, 'audit-review-dialog') || byId(treeFail, 'audit-review-dialog')
  assert.ok(failModal, 'audit dialog opens on scope failure')
  const failConsent = byDomId(failModal, 'audit-review-consent') || byId(failModal, 'audit-review-consent')
  const failRun = byDomId(failModal, 'audit-review-run') || byId(failModal, 'audit-review-run')
  assert.equal(failConsent.props.disabled, true, 'consent checkbox disabled when scope fails')
  assert.equal(failRun.props.disabled, true, 'Run disabled when scope fails')
  failConsent.props.onChange({ target: { checked: true } })
  treeFail = hFail.render()
  assert.equal((byDomId(treeFail, 'audit-review-run') || byId(treeFail, 'audit-review-run')).props.disabled, true, 'Run remains disabled even if onChange attempted without scope')

  // Probe 2: Two footer audits => two consent reviews, async status polling (running -> no completed -> completed)
  const h = mountHarness(t, 'main', [
    { scope_disclosure: 'Live scope disclosure #1' },
    { run_id: 'run-1', status: 'running' },
    { run_id: 'run-1', status: 'running' },
    { run_id: 'run-1', status: 'running' },
    { run_id: 'run-1', status: 'completed', report: { coverage: 'could_not_verify', findings: [{ id: 'f1', coverage: 'could_not_verify' }] } },
    { coverage: 'could_not_verify', findings: [{ id: 'f1', coverage: 'could_not_verify' }], proposals: [] },
    { text: null }, // /audit/summary for run-1: no text, JSON view stays
    { scope_disclosure: 'Live scope disclosure #2' },
    { run_id: 'run-2', status: 'completed', report: { coverage: 'verified', findings: [] } },
    { run_id: 'run-2', status: 'completed', report: { coverage: 'verified', findings: [] } },
    { coverage: 'verified', findings: [], proposals: [] }
  ])
  let tree = h.render()
  await (byDomId(tree, 'audit-full-button') || byId(tree, 'audit-full-button')).props.onClick()
  tree = h.render()
  let modal = byDomId(tree, 'audit-review-dialog') || byId(tree, 'audit-review-dialog')
  const modalText = textOf(modal)
  assert.match(modalText, /Scope & boundaries/)
  assert.match(modalText, /Outward references may lead into shared context or another profile/)
  assert.match(modalText, /Uncollected or inaccessible regions remain unknown, not clean/)
  assert.match(modalText, /Live scope disclosure #1/)

  const consent1 = byDomId(modal, 'audit-review-consent') || byId(modal, 'audit-review-consent')
  assert.equal(consent1.props.disabled, false)
  consent1.props.onChange({ target: { checked: true } })
  tree = h.render()
  modal = byDomId(tree, 'audit-review-dialog') || byId(tree, 'audit-review-dialog')
  const run1 = byDomId(modal, 'audit-review-run') || byId(modal, 'audit-review-run')
  await run1.props.onClick()
  tree = h.render()

  // While status is 'running', must NOT announce 'completed' and must poll via ctx.setInterval
  const statusEl = byDomId(tree, 'status') || byId(tree, 'audit-status-notice')
  assert.doesNotMatch(textOf(statusEl), /completed|finished/i, 'running status must not announce completed')
  assert.equal(h.intervals.size, 1, 'polling interval registered while audit is running')

  // First interval tick still returns running
  await h.tickIntervals()
  tree = h.render()
  assert.doesNotMatch(textOf(byDomId(tree, 'status')), /completed|finished/i, 'still running on tick 1')
  assert.equal(h.intervals.size, 1)

  // Second interval tick returns completed -> clears interval, fetches report, announces completed + unknown coverage
  await h.tickIntervals()
  tree = h.render()
  assert.equal(h.intervals.size, 0, 'polling interval cleared on completion')
  assert.match(textOf(byDomId(tree, 'status')), /audit finished/i)
  assert.match(JSON.stringify(tree), /could_not_verify/, 'renders returned report including unknown coverage')

  // Second footer audit requires a second fresh /audit/scope + fresh consent
  await (byDomId(tree, 'audit-quick-button') || byId(tree, 'audit-quick-button')).props.onClick()
  tree = h.render()
  modal = byDomId(tree, 'audit-review-dialog') || byId(tree, 'audit-review-dialog')
  assert.match(textOf(modal), /Live scope disclosure #2/)
  assert.equal((byDomId(modal, 'audit-review-consent') || byId(modal, 'audit-review-consent')).props.checked, false)
  assert.equal((byDomId(modal, 'audit-review-run') || byId(modal, 'audit-review-run')).props.disabled, true)
  assert.equal(h.calls.filter(c => c.path === '/audit/scope').length, 2, 'two footer audits trigger two /audit/scope calls')
})

test('Gap 5: Real overlay modals with backdrop, focus containment/restore, available on all screens with top-bar Start project, and Accept & create runs backend propose+accept inside modal', async t => {
  const h = mountHarness(t, 'settings', [
    { proposal_id: 'prop-123', tree: [{ name: 'inventory-api', dest: '/p/inventory-api', files: ['AGENTS.md', 'package.json'] }] },
    { ok: true, status: 'created', repos: [{ name: 'inventory-api', path: '/p/inventory-api', registration: 'registered', registration_result: { registered: true } }] },
    { coverage: 'verified', projects: [{ name: 'inventory-api', path: '/p/inventory-api', registered: true, template_id: 'ts-node-golden' }] }
  ])
  let tree = h.render('settings')
  const startBtn = byDomId(tree, 'start-project') || byId(tree, 'start-project-modal-btn')
  assert.ok(startBtn, 'Start project button is in top bar on settings screen too')
  await startBtn.props.onClick()
  tree = h.render('settings')

  const modal = byDomId(tree, 'new-project-dialog') || byId(tree, 'new-project-modal')
  assert.ok(modal, 'Start project modal opens over settings screen')
  assert.equal(modal.props['aria-modal'], 'true')
  const backdrop = byId(tree, 'modal-backdrop') || nodes(tree, n => n.props?.['data-modal-backdrop'] === 'true')[0]
  assert.ok(backdrop, 'modal has overlay backdrop')
  assert.equal(typeof modal.props.onKeyDown, 'function', 'modal has keydown handler for Escape / Tab focus trap')

  await typeProjectName(modal, 'inventory-api')
  await chooseRow(modal, 'template:ts-node-golden')
  tree = h.render('settings')
  const acceptBtn = byDomId(byDomId(tree, 'new-project-dialog') || byId(tree, 'new-project-modal'), 'accept-project') || byId(tree, 'accept-project')
  await acceptBtn.props.onClick()
  tree = h.render('settings')

  assert.equal(h.routes.includes('/defuzz/new'), false, 'Accept & create must not navigate to /defuzz/new')
  assert.ok(h.calls.some(c => c.path === '/scaffold/propose'), 'Accept & create calls /scaffold/propose')
  assert.ok(h.calls.some(c => c.path === '/scaffold/accept' && c.opts?.body?.confirm === true), 'Accept & create calls /scaffold/accept with confirm: true')
  assert.equal(byDomId(tree, 'new-project-dialog'), undefined, 'modal closes after successful creation')
})

test('Gap 6: Expandable folder tree from real data, 7px draggable divider defaulting to 58%, and safe Markdown Preview vs Source raw', async t => {
  const h = mountHarness(t, 'main', [
    { coverage: 'verified', projects: [{ name: 'invoice-tracker', path: '/p/ts', registered: true, template_id: 'ts-node-golden', locked_hashes: { 'packages/adapters/http-hono/src/index.ts': 'h1', 'AGENTS.md': 'h2' } }] },
    { content: '# Heading 1\n\n## Section 2\n\n- **Bold item** with `inline_code`\n\n```sh\npnpm xtask ci\n```\n\n<img src=x onerror=alert(1)>' }
  ])
  let tree = h.render()

  // Divider defaults to 58% and 7px column
  const divider = byDomId(tree, 'pane-divider') || byId(tree, 'pane-divider')
  assert.equal(divider.props['aria-valuenow'], 58, 'divider defaults to 58%')
  assert.equal(typeof divider.props.onPointerDown, 'function', 'divider has pointerdown handler')
  assert.equal(typeof divider.props.onKeyDown, 'function', 'divider has keyboard handler')
  divider.props.onKeyDown({ key: 'ArrowLeft', shiftKey: false, preventDefault() {} })
  tree = h.render()
  assert.ok((byDomId(tree, 'pane-divider') || byId(tree, 'pane-divider')).props['aria-valuenow'] < 58, 'ArrowLeft shrinks tree split')

  // Load projects and select project so real locked_hashes populate expandable folder tree
  await nodes(tree, n => n.type === 'Button' && textOf(n) === 'Refresh projects')[0].props.onClick()
  tree = h.render()
  const projBtn = nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'invoice-tracker')[0]
  projBtn.props.onClick()
  tree = h.render()

  // Expandable folder tree with folder chevrons & aria-expanded
  const treeEl = byDomId(tree, 'tree')
  const folderRow = nodes(treeEl, n => n.props?.['data-folder'] === 'true')[0]
  assert.ok(folderRow, 'tree contains expandable folder nodes')
  assert.equal(folderRow.props['aria-expanded'], true)
  folderRow.props.onClick()
  tree = h.render()
  const collapsedFolder = nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === folderRow.props['data-path'])[0]
  assert.equal(collapsedFolder.props['aria-expanded'], false, 'clicking folder toggles aria-expanded')

  // Select AGENTS.md to load real file via /workspace/file
  const agentsRow = nodes(byDomId(tree, 'tree'), n => n.props?.['data-path'] === 'AGENTS.md')[0]
  await agentsRow.props.onClick()
  tree = h.render()

  assert.ok(h.calls.some(c => c.path.startsWith('/workspace/file?') && c.path.includes('AGENTS.md')), 'selecting file fetches /workspace/file')

  // Markdown Preview renders h1, h2, ul/li, strong, code, pre — and never raw HTML tags
  const editor = byDomId(tree, 'editor')
  assert.ok(nodes(editor, n => n.type === 'h1' && textOf(n) === 'Heading 1').length === 1, 'Markdown preview renders h1')
  assert.ok(nodes(editor, n => n.type === 'h2' && textOf(n) === 'Section 2').length === 1, 'Markdown preview renders h2')
  assert.ok(nodes(editor, n => n.type === 'strong' && textOf(n) === 'Bold item').length === 1, 'Markdown preview renders strong')
  assert.ok(nodes(editor, n => n.type === 'code' && textOf(n) === 'inline_code').length === 1, 'Markdown preview renders inline code')
  assert.ok(nodes(editor, n => n.type === 'pre' && textOf(n).includes('pnpm xtask ci')).length === 1, 'Markdown preview renders code fence')
  assert.equal(nodes(editor, n => n.type === 'img' || n.type === 'script').length, 0, 'Untrusted HTML is never rendered as DOM elements')
  assert.match(textOf(editor), /<img src=x onerror=alert\(1\)>/, 'Untrusted HTML is rendered as safe text')

  // Switching to Source mode shows raw markdown with line numbers
  ;(byDomId(tree, 'md-source') || byId(tree, 'md-source')).props.onClick()
  tree = h.render()
  assert.equal(nodes(byDomId(tree, 'editor'), n => n.type === 'h1').length, 0, 'Source mode does not render markdown elements')
  assert.match(textOf(byDomId(tree, 'editor')), /# Heading 1/)
})

test('Gap 7: Footer LINT ▶ and CHECKS ▶ execute backend calls and display results', async t => {
  const h = mountHarness(t, 'main', [
    { coverage: 'verified', projects: [{ name: 'invoice-tracker', path: '/p/ts', registered: true, template_id: 'ts-node-golden' }] },
    { state: 'done', ok: true, findings: [{ file: 'src/index.ts', line: 4, tool: 'biome', rule: 'noUnusedVariables', message: 'unused x' }] },
    { items: [{ name: 'biome', expected_version: '2.6.6', installed_version: '2.6.6', status: 'ok' }] },
    { lock: '/p/ts/TOOLS.lock', enforce: 'warn', rows: [], summary: 'all 1 tools match TOOLS.lock' }
  ])
  let tree = h.render()
  await nodes(tree, n => n.type === 'Button' && textOf(n) === 'Refresh projects')[0].props.onClick()
  tree = h.render()
  nodes(byDomId(tree, 'project-cards'), n => n.props?.['data-project'] === 'invoice-tracker')[0].props.onClick()
  tree = h.render()

  // Click Footer LINT ▶
  const lintPlay = byId(tree, 'footer-lint-play')
  assert.equal(lintPlay.props.disabled, false)
  await lintPlay.props.onClick()
  tree = h.render()
  assert.ok(h.calls.some(c => c.path === '/lint' && c.opts?.method === 'POST' && c.opts?.body?.project === '/p/ts'), 'Footer LINT ▶ POSTs to /lint')
  assert.match(JSON.stringify(tree), /noUnusedVariables/, 'Footer LINT ▶ renders findings/result')

  // Click Footer CHECKS ▶
  const checksPlay = byId(tree, 'footer-checks-play')
  await checksPlay.props.onClick()
  tree = h.render()
  assert.ok(h.calls.some(c => c.path === '/tools/status' || c.path.startsWith('/tools-lock')), 'Footer CHECKS ▶ calls backend check endpoints')
  assert.match(JSON.stringify(tree), /2\.6\.6|TOOLS\.lock/, 'Footer CHECKS ▶ renders check result')
})

test('Gap 8 & 9: Settings Lint rules (12 tools) tab label, ← Workspace button, tool enable checkboxes, Enable all / Clear, execution legend, and persistence via /ui-state', async t => {
  const h = mountHarness(t, 'settings', [
    { seq: 1, value: { rules: [] } },
    { seq: 2, value: { rules: [] } },
    { seq: 2, value: { rules: [] } }
  ])
  let tree = h.render('settings')

  const lintTab = byDomId(tree, 'lint-tab') || byId(tree, 'lint-tab')
  assert.match(textOf(lintTab), /Lint rules\s*12 tools/, 'Lint rules tab matches approved design literal Lint rules (12 tools)')
  const backBtn = byDomId(tree, 'back-button')
  assert.equal(textOf(backBtn), '← Workspace', 'Back button label is ← Workspace')

  // Switch to Lint rules tab
  lintTab.props.onClick()
  tree = h.render('settings')
  const lintPanel = byDomId(tree, 'lint-panel') || byId(tree, 'lint-panel')
  assert.ok(lintPanel)

  // Checkboxes for each tool in active language
  const checkboxes = nodes(lintPanel, n => n.type === 'input' && n.props?.type === 'checkbox')
  assert.ok(checkboxes.length >= 2, 'Tool enable checkboxes rendered')
  assert.equal(checkboxes[0].props['aria-label'], 'Enable Biome')

  // Execution rules legend (3 cards: Manual trigger only, Binary execution, Missing tools reported)
  const legend = byLabel(lintPanel, 'Lint execution rules')
  assert.ok(legend, 'Lint execution rules legend exists')
  for (const heading of ['Manual trigger only', 'Binary execution', 'Missing tools reported']) {
    assert.match(textOf(legend), new RegExp(heading))
  }

  // How Auditor & Lint differ comparison card
  assert.match(textOf(lintPanel), /How Auditor & Lint differ/)

  // Clear and Enable all buttons
  const clearBtn = nodes(lintPanel, n => n.type === 'Button' && textOf(n) === 'Clear')[0]
  const enableAllBtn = nodes(lintPanel, n => n.type === 'Button' && textOf(n) === 'Enable all')[0]
  assert.ok(clearBtn && enableAllBtn, 'Enable all and Clear buttons exist')
  clearBtn.props.onClick()
  tree = h.render('settings')
  assert.ok(nodes(byDomId(tree, 'lint-panel'), n => n.type === 'input' && n.props?.type === 'checkbox').every(c => c.props.checked === false), 'Clear unchecks active language tools')
  enableAllBtn.props.onClick()
  tree = h.render('settings')
  assert.ok(nodes(byDomId(tree, 'lint-panel'), n => n.type === 'input' && n.props?.type === 'checkbox').every(c => c.props.checked === true), 'Enable all checks active language tools')

  // Save checks persists via /ui-state
  const saveBtn = byDomId(tree, 'lint-save') || nodes(tree, n => n.type === 'Button' && textOf(n) === 'Save checks')[0]
  assert.ok(saveBtn, 'Save checks button exists on Lint tab')
  await saveBtn.props.onClick()
  assert.ok(h.calls.some(c => c.path.startsWith('/ui-state')), 'Save checks persists via /ui-state')
})

test('V10 main workspace: project strip with TS / R / Py / Go / C++ / C# badges, filter pills for all 6 templates + csharpier, resizable tree + file viewer, top-bar Start project modal', async t => {
  const projectsPayload = {
    coverage: 'verified',
    projects: [
      { name: 'invoice-tracker', path: '/p/ts', registered: true, template_id: 'ts-node-golden' },
      { name: 'rust-cli', path: '/p/rs', registered: true, template_id: 'rust-golden' },
      { name: 'data-tools', path: '/p/py', registered: true, template_id: 'python-golden' },
      { name: 'go-svc', path: '/p/go', registered: true, template_id: 'go-golden' },
      { name: 'cpp-engine', path: '/p/cpp', registered: true, template_id: 'cpp-golden' },
      { name: 'dotnet-api', path: '/p/cs', registered: true, template_id: 'dotnet-golden' }
    ]
  }
  const h = mountHarness(t, 'main', [projectsPayload])
  let tree = h.render()

  const topBar = byId(tree, 'v10-top-bar')
  assert.ok(topBar, 'V10 top bar exists')
  assert.doesNotMatch(textOf(topBar), /Quick tour|= Project defuzz =/)
  const startBtn = byId(tree, 'start-project-modal-btn') || byDomId(tree, 'start-project')
  assert.ok(startBtn, 'top-bar Start project modal trigger exists')
  assert.match(textOf(startBtn), /Start project/i)

  const refreshBtn = nodes(tree, n => n.type === 'Button' && textOf(n) === 'Refresh projects')[0]
  await refreshBtn.props.onClick()
  tree = h.render()

  const strip = byId(tree, 'v10-project-strip') || byDomId(tree, 'project-cards')
  assert.ok(strip, 'project strip exists')
  const stripText = textOf(strip)
  for (const badge of ['TS', 'R', 'Py', 'Go', 'C++', 'C#']) {
    assert.ok(stripText.includes(badge), `project strip includes badge ${badge}`)
  }

  const filterBar = byId(tree, 'v10-template-filter-pills')
  assert.ok(filterBar, 'template filter pills exist')
  const filterText = JSON.stringify(filterBar)
  for (const token of ['ts-node-golden', 'rust-golden', 'python-golden', 'go-golden', 'cpp-golden', 'dotnet-golden', 'csharpier']) {
    assert.ok(filterText.includes(token), `filter pills cover ${token}`)
  }

  const divider = byDomId(tree, 'pane-divider') || byId(tree, 'pane-divider')
  assert.equal(divider?.props?.role, 'separator')
  const wrapBtn = byDomId(tree, 'wrap-button') || byId(tree, 'wrap-button')
  assert.equal(textOf(wrapBtn), 'Wrap off')
  wrapBtn.props.onClick()
  tree = h.render()
  assert.equal(textOf(byDomId(tree, 'wrap-button') || byId(tree, 'wrap-button')), 'Wrap on')

  const fontLarger = byDomId(tree, 'font-larger') || byId(tree, 'font-larger')
  const fontSize = () => textOf(byDomId(h.render(), 'font-size') || byId(h.render(), 'font-size'))
  const beforeFont = Number(fontSize())
  fontLarger.props.onClick()
  assert.equal(Number(fontSize()), beforeFont + 1)

  assert.equal(byId(tree, 'new-project-modal'), undefined)
  startBtn.props.onClick()
  tree = h.render()
  const modal = byId(tree, 'new-project-modal') || byDomId(tree, 'new-project-dialog')
  assert.ok(modal, 'Start project modal popup opens')
  assert.match(textOf(modal), /Start project/i)
  const cancelModal = byDomId(modal, 'cancel-project') || byId(modal, 'cancel-project')
  assert.ok(cancelModal, 'Cancel button inside Start project modal')
  cancelModal.props.onClick()
  tree = h.render()
  assert.equal(byId(tree, 'new-project-modal'), undefined)
})

test('V10 settings: Interactive guide collapsed by default, 4-stage sync, Play/Pause/Prev/Next/Hide, no SandboxedFrame/srcdoc, timer disposal', async t => {
  const source = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /SandboxedFrame|srcdoc/)

  const h = mountHarness(t, 'settings')
  let tree = h.render('settings')

  const settingsRoot = byDomId(tree, 'settings') || byId(tree, 'v10-settings')
  assert.ok(settingsRoot, 'V10 settings root exists')
  assert.match(textOf(settingsRoot), /Project settings/)
  const auditorTab = byDomId(tree, 'auditor-tab') || byId(tree, 'auditor-tab')
  const lintTab = byDomId(tree, 'lint-tab') || byId(tree, 'lint-tab')
  assert.ok(auditorTab && lintTab, 'Auditor and Lint rules tabs exist')
  assert.match(textOf(auditorTab), /Auditor.*7 scripts/)
  assert.match(textOf(lintTab), /Lint rules.*12 tools/)

  assert.equal(byDomId(tree, 'audit-run'), undefined)
  assert.equal(byDomId(tree, 'scope-confirm'), undefined)

  const guideToggle = byDomId(tree, 'tutorial-toggle') || byId(tree, 'tutorial-toggle')
  assert.ok(guideToggle, 'Interactive guide toggle button exists')
  assert.equal(guideToggle.props['aria-expanded'], false)
  assert.equal(byDomId(tree, 'tutorial-strip') || byId(tree, 'tutorial-strip'), undefined)

  const scriptRows = nodes(tree, n => n.props?.['data-testid']?.startsWith('v10-script-row-'))
  assert.equal(scriptRows.length, 7)

  guideToggle.props.onClick()
  tree = h.render('settings')
  assert.equal((byDomId(tree, 'tutorial-toggle') || byId(tree, 'tutorial-toggle')).props['aria-expanded'], true)
  const guideStrip = byDomId(tree, 'tutorial-strip') || byId(tree, 'tutorial-strip')
  assert.ok(guideStrip, 'Interactive guide strip rendered when expanded')
  const stageCards = nodes(guideStrip, n => n.props?.['data-testid']?.startsWith('v10-stage-card-'))
  assert.equal(stageCards.length, 4)
  assert.ok(byDomId(guideStrip, 'spot-text') || byId(guideStrip, 'spot-text'))

  scriptRows[3].props.onClick()
  tree = h.render('settings')
  assert.equal(textOf(byDomId(tree, 'insp-title') || byId(tree, 'insp-title')), 'Template drift')
  assert.match(textOf(byDomId(tree, 'spot-badge') || byId(tree, 'spot-badge')), /STAGE 3 OF 4/)

  const playBtn = byDomId(tree, 'dry-run-button') || byId(tree, 'dry-run-button')
  playBtn.props.onClick()
  tree = h.render('settings')
  assert.equal(h.intervals.size, 1, 'Play registers one scoped ctx.setInterval')
  await h.tickIntervals()
  tree = h.render('settings')
  assert.equal(h.intervals.size, 1)

  nodes(tree, n => n.props?.['data-testid']?.startsWith('v10-script-row-'))[0].props.onClick()
  tree = h.render('settings')
  assert.equal(h.intervals.size, 0, 'Manual script selection clears interval')

  ;(byDomId(tree, 'dry-run-button') || byId(tree, 'dry-run-button')).props.onClick()
  tree = h.render('settings')
  assert.equal(h.intervals.size, 1)
  ;(byDomId(tree, 'lint-tab') || byId(tree, 'lint-tab')).props.onClick()
  tree = h.render('settings')
  assert.equal(h.intervals.size, 0, 'Switching tab clears interval')

  const lintPanel = byDomId(tree, 'lint-panel') || byId(tree, 'lint-panel')
  assert.ok(lintPanel, 'Lint rules panel visible')
  assert.deepEqual(h.calls.filter(c => !(c.path === '/componentize/settings' && !c.opts?.method)), [], 'Guide and inspector interactions make zero backend calls (the companion section only reads its saved values)')
})

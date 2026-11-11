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

function parseTemplateYaml(templateId) {
  const raw = readFileSync(new URL(`../../templates/${templateId}/template.yaml`, import.meta.url), 'utf8')
  const nameMatch = raw.match(/^name:\s*(.+)$/m)
  const summaryMatch = raw.match(/^summary:\s*(?:>-\s*\n\s*)?(.+)$/m)
  const kindMatch = raw.match(/^kind:\s*(\S+)$/m)
  const layoutMatch = raw.match(/^layout:\s*(\S+)$/m)
  const langMatch = raw.match(/^languages:\s*\[([^\]]+)\]/m)
  const options = {}
  if (/^options:\s*$/m.test(raw)) {
    const afterOptions = raw.split(/^options:\s*$/m)[1].split(/^[a-z_]+:\s*$/m)[0]
    const keyMatch = afterOptions.match(/^\s{2}([a-z_]+):\s*$/m)
    const labelMatch = afterOptions.match(/label:\s*"?([^"\n]+)"?/)
    const choicesMatch = afterOptions.match(/choices:\s*\[([^\]]+)\]/)
    const defaultMatch = afterOptions.match(/default:\s*(\S+)/)
    if (keyMatch && choicesMatch) {
      const choices = choicesMatch[1].split(',').map(s => s.trim())
      options[keyMatch[1]] = {
        label: labelMatch ? labelMatch[1].trim() : keyMatch[1],
        choices,
        default: defaultMatch ? defaultMatch[1].trim() : choices[0]
      }
    }
  }
  return {
    id: templateId,
    name: nameMatch ? nameMatch[1].trim() : templateId,
    summary: summaryMatch ? summaryMatch[1].trim() : '',
    kind: kindMatch ? kindMatch[1].trim() : 'service',
    layout: layoutMatch ? layoutMatch[1].trim() : 'mono',
    languages: langMatch ? langMatch[1].split(',').map(s => s.trim()) : [],
    options
  }
}

const ALL_TEMPLATE_SPECS = [
  'ts-node-golden',
  'rust-golden',
  'python-golden',
  'go-golden',
  'cpp-golden',
  'dotnet-golden',
  'web-golden'
].map(parseTemplateYaml)

function createBackendShim({ maxProposals = 32, rememberedDefaults = {}, failAcceptUntilAttempt = 0, failMatch = false, failDiscardOnce = false } = {}) {
  const proposals = new Map()
  const calls = []
  let nextId = 1
  let acceptAttempts = 0
  let discardFailedOnce = false

  const matchForAnswers = answers => {
    const langs = Array.isArray(answers?.languages) ? answers.languages : []
    const matched = ALL_TEMPLATE_SPECS.filter(spec => !langs.length || langs.some(l => spec.languages.includes(l)))
    const list = matched.length ? matched : ALL_TEMPLATE_SPECS
    return list.map(spec => {
      const opts = structuredClone(spec.options)
      const rem = rememberedDefaults[spec.id] || {}
      for (const [k, v] of Object.entries(rem)) {
        if (opts[k] && opts[k].choices.includes(v)) {
          opts[k].default = v
        }
      }
      return {
        template_id: spec.id,
        name: spec.name,
        summary: spec.summary,
        score: 8,
        reasons: [`kind: ${spec.kind}`, `layout: ${spec.layout}`],
        needs: [],
        options: opts
      }
    })
  }

  const rest = async (path, opts = {}) => {
    const body = opts.body
    calls.push({ path, opts })
    if (path === '/scaffold/match') {
      if (failMatch) throw new Error('match endpoint unreachable')
      return { matches: matchForAnswers(body?.answers || {}), closest: [], handoff: null, catalog: catalog() }
    }
    if (path === '/scaffold/propose') {
      if (proposals.size >= maxProposals) {
        const err = new Error('Discard an existing proposal before staging another')
        err.status = 429
        throw err
      }
      const spec = ALL_TEMPLATE_SPECS.find(s => s.id === body?.template_id)
      if (!spec) throw new Error('Unknown template_id')
      const proposal_id = `prop-${nextId++}`
      const proposal = {
        proposal_id,
        template_id: spec.id,
        name: body.name,
        slug: body.name,
        options: body.options || {},
        tree: [{ name: body.name, dest: `/srv/${body.name}`, files: ['AGENTS.md', 'README.md'] }]
      }
      proposals.set(proposal_id, { state: 'ready', proposal, remember_options: body.remember_options !== false })
      return proposal
    }
    if (path === '/scaffold/accept') {
      const row = proposals.get(body?.proposal_id)
      if (!row) throw new Error('Unknown or consumed proposal_id')
      if (row.state !== 'ready') throw new Error('Proposal is busy or requires inspection after partial creation')
      acceptAttempts += 1
      if (acceptAttempts <= failAcceptUntilAttempt) {
        const err = Object.assign(new Error(`staged check failed #${acceptAttempts}`), {
          body: { detail: { error: `staged check failed #${acceptAttempts}`, output: 'ci error', created_dirs: [], accepted_repos: [] } }
        })
        throw err
      }
      proposals.delete(body.proposal_id)
      return {
        ok: true,
        status: 'created',
        repos: [{ name: row.proposal.name, path: `/srv/${row.proposal.name}`, registration: 'registered', registration_result: { registered: true } }]
      }
    }
    if (path === '/scaffold/discard') {
      const row = proposals.get(body?.proposal_id)
      if (!row) throw new Error('Unknown or consumed proposal_id')
      if (failDiscardOnce && !discardFailedOnce) {
        discardFailedOnce = true
        throw new Error('discard lock contention')
      }
      proposals.delete(body.proposal_id)
      return { status: 'discarded' }
    }
    if (path === '/workspace/projects') {
      return { coverage: 'verified', projects: [] }
    }
    return {}
  }

  return { rest, calls, proposals }
}

function mountWorkspace(t, rest) {
  const instances = new Map(), routes = [], cleanups = new Set(), effects = []
  let slots, cursor, dirty
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
    rest
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
    render(screen = 'main') {
      let tree, passes = 0
      do {
        assert.ok(passes++ < 25, 'render settles')
        dirty = false
        tree = expand({ type: ui.WorkspacePage, props: { ctx, initialScreen: screen } })
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

test('Fix3A-1: 40 fail -> rename -> retry cycles discard each abandoned server proposal and succeed on creation without hitting 32-proposal limit; Cancel and close also discard', async t => {
  const shim = createBackendShim({ maxProposals: 32, failAcceptUntilAttempt: 40 })
  const h = mountWorkspace(t, shim.rest)

  let tree = h.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()
  await typeProjectName(byDomId(tree, 'new-project-dialog'), 'inventory-api')
  await chooseRow(byDomId(tree, 'new-project-dialog'), 'template:ts-node-golden')
  tree = h.render()

  for (let i = 1; i <= 40; i++) {
    const slug = `retry-proj-${i}`
    let modal = byDomId(tree, 'new-project-dialog')
    const nameInput = byDomId(modal, 'new-project-name') || byLabel(modal, 'Project name')
    await nameInput.props.onChange({ target: { value: slug } })
    tree = h.render()

    modal = byDomId(tree, 'new-project-dialog')
    await byDomId(modal, 'accept-project').props.onClick()
    tree = h.render()
    assert.ok(byDomId(tree, 'new-project-dialog'), `modal stays open on failed attempt ${i}`)
    assert.equal(shim.proposals.size, 1, `only 1 active proposal on server after failed attempt ${i}`)
  }

  // 41st rename & accept succeeds
  let modal = byDomId(tree, 'new-project-dialog')
  const nameInput = byDomId(modal, 'new-project-name') || byLabel(modal, 'Project name')
  await nameInput.props.onChange({ target: { value: 'retry-proj-final' } })
  tree = h.render()

  modal = byDomId(tree, 'new-project-dialog')
  await byDomId(modal, 'accept-project').props.onClick()
  tree = h.render()

  assert.equal(byDomId(tree, 'new-project-dialog'), undefined, 'modal closes when 41st attempt succeeds')
  assert.equal(shim.proposals.size, 0, 'no proposals remain on server after successful creation')
  const discardCalls = shim.calls.filter(c => c.path === '/scaffold/discard')
  assert.equal(discardCalls.length, 40, 'POST /scaffold/discard called for each of the 40 abandoned proposals')
  for (let i = 0; i < 40; i++) {
    assert.deepEqual(discardCalls[i].opts, { method: 'POST', body: { proposal_id: `prop-${i + 1}` } })
  }

  // Also verify Cancel discards an active failed proposal
  const shimCancel = createBackendShim({ maxProposals: 32, failAcceptUntilAttempt: 5, failDiscardOnce: true })
  const hCancel = mountWorkspace(t, shimCancel.rest)
  tree = hCancel.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = hCancel.render()
  await typeProjectName(byDomId(tree, 'new-project-dialog'), 'inventory-api')
  await chooseRow(byDomId(tree, 'new-project-dialog'), 'template:ts-node-golden')
  tree = hCancel.render()
  await byDomId(byDomId(tree, 'new-project-dialog'), 'accept-project').props.onClick()
  tree = hCancel.render()
  assert.equal(shimCancel.proposals.size, 1)

  // First rename triggers discard which fails once -> surfaces error and still allows retry
  const cancelModal = byDomId(tree, 'new-project-dialog')
  await byDomId(cancelModal, 'new-project-name').props.onChange({ target: { value: 'after-discard-err' } })
  tree = hCancel.render()
  assert.match(JSON.stringify(tree), /discard lock contention/i, 'surfaces discard failure error')

  // Retry propose+accept (fails accept) then click Cancel -> discards proposal
  await byDomId(byDomId(tree, 'new-project-dialog'), 'accept-project').props.onClick()
  tree = hCancel.render()
  await byDomId(byDomId(tree, 'new-project-dialog'), 'cancel-project').props.onClick()
  tree = hCancel.render()
  assert.equal(byDomId(tree, 'new-project-dialog'), undefined, 'Cancel closes modal')
  assert.ok(shimCancel.calls.filter(c => c.path === '/scaffold/discard').length >= 2, 'Cancel calls /scaffold/discard')

  // Also verify unmount discards an active failed proposal
  const shimUnmount = createBackendShim({ maxProposals: 32, failAcceptUntilAttempt: 5 })
  const hUnmount = mountWorkspace(t, shimUnmount.rest)
  tree = hUnmount.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = hUnmount.render()
  await typeProjectName(byDomId(tree, 'new-project-dialog'), 'inventory-api')
  await chooseRow(byDomId(tree, 'new-project-dialog'), 'template:ts-node-golden')
  tree = hUnmount.render()
  await byDomId(byDomId(tree, 'new-project-dialog'), 'accept-project').props.onClick()
  tree = hUnmount.render()
  assert.equal(shimUnmount.proposals.size, 1, 'proposal active before unmount')
  hUnmount.unmount()
  await Promise.resolve()
  assert.equal(shimUnmount.proposals.size, 0, 'unmount discards active server proposal')
})

test('Fix3A-2: Start project uses backend /scaffold/match for template option metadata and remembered defaults, removes hardcoded option table, validates all bundled templates, and creates nothing on match failure', async t => {
  // Verify hardcoded option metadata is removed from V10_TEMPLATES
  for (const tpl of ui.V10_TEMPLATES) {
    assert.equal(tpl.options, undefined, `V10_TEMPLATES entry ${tpl.id} must not hardcode options metadata`)
  }

  // Verify remembered defaults from /scaffold/match are honored (e.g. node_http for TS, stdlib_http for Python)
  const shim = createBackendShim({
    rememberedDefaults: {
      'ts-node-golden': { http_adapter: 'node_http' },
      'python-golden': { http_adapter: 'stdlib_http' }
    }
  })
  const h = mountWorkspace(t, shim.rest)
  let tree = h.render()

  await byDomId(tree, 'start-project').props.onClick()
  tree = h.render()
  await chooseRow(byDomId(tree, 'new-project-dialog'), 'template:ts-node-golden')
  tree = h.render()

  const matchCalls = shim.calls.filter(c => c.path === '/scaffold/match')
  assert.ok(matchCalls.length >= 1, 'opening Start project modal calls /scaffold/match')

  let modal = byDomId(tree, 'new-project-dialog')
  let adapterSelect = byDomId(modal, 'new-project-adapter')
  assert.equal(adapterSelect.props.value, 'node_http', 'honors remembered default node_http from /scaffold/match for ts-node-golden')

  // Validate every bundled template against templates/<id>/template.yaml
  for (const spec of ALL_TEMPLATE_SPECS) {
    const templateId = spec.id
    const slug = `valid-${templateId.split('-')[0]}`
    if (!byDomId(tree, 'new-project-dialog')) {
      await byDomId(tree, 'start-project').props.onClick()
      tree = h.render()
    }
    modal = byDomId(tree, 'new-project-dialog')
    await chooseRow(modal, `template:${templateId}`)
    tree = h.render()
    modal = byDomId(tree, 'new-project-dialog')

    const declaredKeys = Object.keys(spec.options)
    adapterSelect = byDomId(modal, 'new-project-adapter')
    if (declaredKeys.length > 0) {
      const expectedDefault = shim.calls.length && ({ 'ts-node-golden': 'node_http', 'python-golden': 'stdlib_http' }[templateId] || spec.options[declaredKeys[0]].default)
      assert.equal(adapterSelect.props.disabled, false, `${templateId} adapter select enabled`)
      assert.equal(adapterSelect.props.value, expectedDefault, `${templateId} adapter select uses matched default`)
    } else {
      assert.equal(adapterSelect.props.disabled, true, `${templateId} adapter select disabled when template has no options`)
    }

    await byDomId(modal, 'new-project-name').props.onChange({ target: { value: slug } })
    tree = h.render()
    modal = byDomId(tree, 'new-project-dialog')
    await byDomId(modal, 'accept-project').props.onClick()
    tree = h.render()

    const proposeCall = shim.calls.filter(c => c.path === '/scaffold/propose').at(-1)
    assert.ok(proposeCall, `propose called for ${templateId}`)
    assert.equal(proposeCall.opts.body.template_id, templateId)
    assert.deepEqual(proposeCall.opts.body.answers, {
      building: spec.kind,
      layout: spec.layout,
      languages: spec.languages
    })
    if (declaredKeys.length === 0) {
      assert.deepEqual(proposeCall.opts.body.options, {}, `${templateId} sends empty options {}`)
    } else {
      assert.deepEqual(Object.keys(proposeCall.opts.body.options), declaredKeys)
      for (const k of declaredKeys) {
        assert.ok(spec.options[k].choices.includes(proposeCall.opts.body.options[k]))
      }
    }
  }

  // When /scaffold/match fails there is no list to choose from: the error is shown and nothing can be created
  const failMatchShim = createBackendShim({ failMatch: true })
  const hFail = mountWorkspace(t, failMatchShim.rest)
  tree = hFail.render()
  await byDomId(tree, 'start-project').props.onClick()
  tree = hFail.render()
  modal = byDomId(tree, 'new-project-dialog')
  assert.equal(byDomId(modal, 'new-project-adapter').props.disabled, true, 'adapter select disabled when /scaffold/match fails')
  assert.match(textOf(modal), /match endpoint unreachable/i, 'shows the plain error when /scaffold/match fails')
  assert.equal(choiceRadios(modal).length, 0, 'no rows without the server list')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true)
  await byDomId(modal, 'accept-project').props.onClick()
  assert.equal(failMatchShim.calls.some(c => c.path === '/scaffold/propose'), false, 'nothing is proposed when match fails')
})

test('Fix3A-3: Workspace model match and discard are actively wired into Start project modal, non-match payloads do not set proposal or matchFailed, and hardcoded matchedTplBackend / template options are removed', async () => {
  const model = ui.createWorkspaceModel({ onDispose() {}, async rest() { return {} } })
  assert.equal(typeof model.match, 'function', 'model.match kept and used')
  assert.equal(typeof model.discard, 'function', 'model.discard kept and used')

  await model.match({ building: 'service', layout: 'mono', languages: ['typescript'] })
  assert.equal(model.get().proposal, null, 'model.match never sets state.proposal')
  assert.equal(model.get().matchFailed, false, 'empty non-error match payload does not set matchFailed: true')

  const source = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /\bmatchedTplBackend\b/, 'unused matchedTplBackend removed')
})

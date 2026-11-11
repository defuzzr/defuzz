// Release-review fixes for the New Project dialog and the audit view. The fake
// server answers from the request body, so these tests check what the page sends.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { host } from '@hermes/plugin-sdk'
import * as ui from '../plugin.js'

const nodes = (node, predicate = () => true) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const textOf = node =>
  !node
    ? ''
    : typeof node === 'string' || typeof node === 'number'
      ? String(node)
      : [node.props?.children].flat().map(textOf).join('')
const tick = () => new Promise(resolve => setImmediate(resolve))

const ENTRIES = [
  { kind: 'template', id: 'python-golden', title: 'Python project', line: 'A Python project with tests.', group: 'code', group_title: 'Code projects' },
  { kind: 'template', id: 'ts-node-golden', title: 'TypeScript service', line: 'A Node service in TypeScript.', group: 'code', group_title: 'Code projects' },
  { kind: 'template', id: 'web-golden', title: 'Static website', line: 'A website built with Vite.', group: 'code', group_title: 'Code projects' },
  { kind: 'kit', id: 'video-production', title: 'Video production', line: 'Folders for a video.', group: 'workspace', group_title: 'Workspaces for files' }
]
const catalogOf = (overrides = {}) => ({ entries: ENTRIES, suggested: [], notice: '', ...overrides })
const matchReply = (catalog = catalogOf(), extra = {}) => ({ matches: [], closest: [], handoff: null, kits: [], kit_catalog: [{ kit_id: 'video-production' }], kits_notice: '', preferred: 'none', catalog, ...extra })

function mountHarness(t, restHandler) {
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
  t.after(() => {
    cleanups.forEach(fn => fn?.())
    disposers.forEach(fn => fn?.())
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
  return { ctx, calls, render, modal, open, fireTimers, typeIdea, timers }
}

const radios = tree => nodes(tree, n => n.type === 'input' && n.props?.type === 'radio')
const checkedKeys = tree => radios(tree).filter(r => r.props.checked).map(r => r.props.value)
const radioFor = (tree, key) => radios(tree).find(r => r.props.value === key)
const pick = async (h, key) => { await radioFor(h.modal(), key).props.onChange({ target: { value: key, checked: true } }); return h.modal() }
const labelFor = (tree, radio) => nodes(tree, n => n.type === 'label' && n.props?.htmlFor === radio.props.id)
const rowText = (tree, key) => textOf(labelFor(tree, radioFor(tree, key))[0])
const matchCalls = h => h.calls.filter(c => c.path === '/scaffold/match')

// S1 ---------------------------------------------------------------------------------
test('S1: opening the New Project dialog shows no server reply: no "Check output" area, no JSON', async t => {
  const h = mountHarness(t, async path => (path === '/scaffold/match'
    ? matchReply(catalogOf(), { handoff: { cwd: '/srv/x', text: 'hand off' }, closest: [{ template_id: 'python-golden', options: {} }] })
    : {}))
  let modal = await h.open()
  assert.equal(radios(modal).length, ENTRIES.length, 'the list is shown')
  const text = textOf(modal)
  for (const raw of ['kit_catalog', 'handoff', '"matches"', 'Check output', 'partial progress', 'What happened']) {
    assert.equal(text.includes(raw), false, `"${raw}" is not shown when the dialog opens`)
  }
  assert.equal(nodes(modal, n => n.type === 'pre' && /[{[]/.test(textOf(n))).length, 0, 'no JSON block')
  // Typing an idea reloads the list; still nothing raw.
  modal = await h.typeIdea('a static website for my bakery')
  assert.equal(textOf(modal).includes('kit_catalog'), false)
  assert.equal(h.render() && byDomId(h.modal(), 'new-project-output'), undefined)
})

// S2 ---------------------------------------------------------------------------------
// The fake server marks rows the way the old route did: chosen languages win over the idea.
const markingServer = (optionsFor = {}) => async (path, opts) => {
  if (path !== '/scaffold/match') return {}
  const body = opts?.body || {}
  const langs = Array.isArray(body.answers?.languages) ? body.answers.languages : []
  const suggested = langs.includes('python') ? ['template:python-golden']
    : /website/.test(body.prompt || '') ? ['template:web-golden'] : []
  const matches = langs.includes('python') && optionsFor['python-golden']
    ? [{ template_id: 'python-golden', options: optionsFor['python-golden'] }]
    : []
  return matchReply(catalogOf({ suggested }), { matches })
}

test('S2: the list request carries only the typed idea; choosing a row never moves the "(suggested)" mark', async t => {
  const h = mountHarness(t, markingServer())
  await h.open()
  let modal = await h.typeIdea('a static website for my bakery')
  assert.equal(rowText(modal, 'template:web-golden'), 'Static website (suggested)')
  modal = await pick(h, 'template:python-golden')
  assert.deepEqual(checkedKeys(modal), ['template:python-golden'])
  assert.equal(rowText(modal, 'template:web-golden'), 'Static website (suggested)', 'the idea still marks the website row')
  assert.equal(rowText(modal, 'template:python-golden'), 'Python project', 'the chosen row is not marked because it was chosen')
  // Reopen and retype: the chosen row still does not change the marks.
  modal = await h.typeIdea('a static website for my bakery, with a menu')
  assert.equal(rowText(modal, 'template:python-golden'), 'Python project')
  assert.equal(rowText(modal, 'template:web-golden'), 'Static website (suggested)')

  for (const call of matchCalls(h)) {
    assert.equal(Object.hasOwn(call.opts.body, 'languages_chosen'), false, 'no languages_chosen in any match request')
  }
  const listCalls = matchCalls(h).filter(c => c.opts.body.prompt !== '' || Object.keys(c.opts.body.answers).length === 0)
  assert.ok(listCalls.length >= 3)
  for (const call of listCalls) {
    assert.deepEqual(Object.keys(call.opts.body).sort(), ['answers', 'prompt'])
    assert.deepEqual(call.opts.body.answers, {}, 'the list request sends no answers')
  }
  // Any other match request is the separate options request: empty idea, the chosen template's answers.
  for (const call of matchCalls(h).filter(c => !listCalls.includes(c))) {
    assert.equal(call.opts.body.prompt, '')
    assert.deepEqual(call.opts.body.answers, { building: 'service', layout: 'mono', languages: ['python'] })
  }
})

test('S2: the chosen template keeps its remembered option default from a separate request whose reply never touches the list', async t => {
  const options = { http_adapter: { label: 'HTTP adapter', default: 'stdlib_http', choices: ['fastapi', 'stdlib_http'], choiceLabels: { fastapi: 'FastAPI', stdlib_http: 'Python standard library' } } }
  const h = mountHarness(t, markingServer({ 'python-golden': options }))
  await h.open()
  let modal = await pick(h, 'template:python-golden')
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, 'stdlib_http', 'the remembered default is used')
  assert.equal(rowText(modal, 'template:python-golden'), 'Python project', 'the options reply does not mark rows')
  const optionCalls = matchCalls(h).filter(c => c.opts.body.prompt === '' && Object.keys(c.opts.body.answers).length > 0)
  assert.equal(optionCalls.length, 1, 'one options request for the pick')
  // The person changes the option, then types an idea: the choice survives the list reload.
  await byDomId(modal, 'new-project-adapter').props.onChange({ target: { value: 'fastapi' } })
  modal = await h.typeIdea('a website')
  assert.equal(byDomId(modal, 'new-project-adapter').props.value, 'fastapi')
  assert.equal(rowText(modal, 'template:web-golden'), 'Static website (suggested)')
})

test('S2: Create still sends the chosen template, its answers and remember_options as before', async t => {
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') return markingServer()(path, opts)
    if (path === '/scaffold/propose') return { proposal_id: 'p1', template_id: opts.body.template_id, tree: [{ name: opts.body.name, dest: '/srv/projects/' + opts.body.name, files: ['AGENTS.md'] }] }
    if (path === '/scaffold/accept') return { status: 'created', repos: [{ name: 'my-tool', path: '/srv/projects/my-tool', registration: 'registered', registration_result: { registered: true } }] }
    if (path === '/workspace/projects') return { coverage: 'verified', projects: [] }
    return {}
  })
  await h.open()
  await byDomId(h.modal(), 'new-project-name').props.onChange({ target: { value: 'my-tool' } })
  const modal = await pick(h, 'template:python-golden')
  await byDomId(modal, 'accept-project').props.onClick()
  const propose = h.calls.filter(c => c.path === '/scaffold/propose').at(-1)
  assert.deepEqual(propose.opts.body, { template_id: 'python-golden', name: 'my-tool', answers: { building: 'service', layout: 'mono', languages: ['python'] }, options: { http_adapter: 'fastapi' }, remember_options: true })
})

// S3 ---------------------------------------------------------------------------------
test('S3: opening the dialog while another request runs loads the list once that request ends', async t => {
  let releaseProjects
  const h = mountHarness(t, async path => {
    if (path === '/workspace/projects') return new Promise(resolve => { releaseProjects = () => resolve({ coverage: 'verified', projects: [] }) })
    if (path === '/scaffold/match') return matchReply()
    return {}
  })
  const refresh = nodes(h.render(), n => textOf(n) === 'Refresh projects' && typeof n.props?.onClick === 'function')[0]
  const loading = refresh.props.onClick()
  let modal = await h.open()
  assert.equal(matchCalls(h).length, 0, 'no match while the model is busy')
  assert.match(textOf(modal), /Loading the list/)
  releaseProjects()
  await loading
  h.render(); await tick(); await tick()
  modal = h.modal()
  assert.equal(matchCalls(h).length, 1, 'the list is asked for once the model is free')
  assert.equal(radios(modal).length, ENTRIES.length)
})

test('S3: a list that does not arrive offers "Check again" next to the loading text after a short delay', async t => {
  let answer = false
  const h = mountHarness(t, async path => {
    if (path === '/scaffold/match') return answer ? matchReply() : new Promise(() => {})
    return {}
  })
  byDomId(h.render(), 'start-project').props.onClick() // the list request never answers
  await tick()
  let modal = h.modal()
  assert.match(textOf(modal), /Loading the list/)
  assert.equal(byDomId(modal, 'new-project-choice-retry'), undefined, 'no retry at once')
  const delay = h.timers.filter(e => e.live && e.ms !== 400)
  assert.equal(delay.length, 1, 'one delay timer')
  assert.ok(delay[0].ms >= 1000 && delay[0].ms <= 10000, 'a short delay')
  await h.fireTimers()
  modal = h.modal()
  const retry = byDomId(modal, 'new-project-choice-retry')
  assert.ok(retry, 'Check again is offered while loading')
  assert.equal(textOf(retry), 'Check again')
  assert.match(textOf(modal), /Loading the list/)
  answer = true
  await retry.props.onClick()
  modal = h.modal()
  assert.equal(radios(modal).length, ENTRIES.length, 'Check again loads the list')
  assert.equal(byDomId(modal, 'new-project-choice-retry'), undefined)
})

// S4 ---------------------------------------------------------------------------------
test('S4: a chosen template that leaves the list is cleared with one plain line, and is not chosen again when it returns', async t => {
  let without = false
  const h = mountHarness(t, async (path, opts) => {
    if (path !== '/scaffold/match') return {}
    return matchReply(catalogOf({ entries: without && opts.body.prompt ? ENTRIES.filter(e => e.id !== 'web-golden') : ENTRIES }))
  })
  await h.open()
  let modal = await pick(h, 'template:web-golden')
  assert.match(textOf(byDomId(modal, 'proposal-tree')), /design\/tokens/)
  without = true
  modal = await h.typeIdea('something else')
  assert.deepEqual(checkedKeys(modal), [])
  assert.doesNotMatch(textOf(byDomId(modal, 'proposal-tree')), /design\/tokens/, 'the preview is gone')
  assert.equal(textOf(byDomId(modal, 'new-project-choice-gone')), '“Static website” is no longer in the list; choose another row.')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true)
  without = false
  modal = await h.typeIdea('something else again')
  assert.ok(radioFor(modal, 'template:web-golden'), 'the row is back')
  assert.deepEqual(checkedKeys(modal), [], 'it is not chosen again by itself')
  modal = await pick(h, 'template:python-golden')
  assert.equal(byDomId(modal, 'new-project-choice-gone'), undefined, 'a new choice removes the line')
})

test('S4: a chosen kit that leaves the list is cleared with the same line', async t => {
  let without = false
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/kits/video-production') return { kit: { id: 'video-production', summary: 'Folders for a video.' }, tree: ['footage/'] }
    if (path !== '/scaffold/match') return {}
    return matchReply(catalogOf({ entries: without ? ENTRIES.filter(e => e.kind !== 'kit') : ENTRIES }))
  })
  await h.open()
  await pick(h, 'kit:video-production')
  without = true
  const modal = await h.typeIdea('a video')
  assert.deepEqual(checkedKeys(modal), [])
  assert.equal(textOf(byDomId(modal, 'new-project-choice-gone')), '“Video production” is no longer in the list; choose another row.')
  assert.doesNotMatch(textOf(byDomId(modal, 'proposal-tree')), /footage/)
})

// S5 (list rows) ----------------------------------------------------------------
const BIDI = '\u202e'
test('S5: New Project list rows show escaped titles and lines', async t => {
  const odd = [{ kind: 'template', id: 'python-golden', title: `Py${BIDI}thon`, line: `Line${BIDI}\nfake`, group: 'code', group_title: `Code${BIDI}` }]
  const h = mountHarness(t, async path => (path === '/scaffold/match' ? matchReply(catalogOf({ entries: odd })) : {}))
  const modal = await h.open()
  assert.equal(rowText(modal, 'template:python-golden'), 'Py\\u202ethon')
  assert.equal(textOf(byDomId(modal, radioFor(modal, 'template:python-golden').props['aria-describedby'])), 'Line\\u202e fake')
  assert.equal(textOf(modal).includes(BIDI), false)
})

// L2 ---------------------------------------------------------------------------------
test('L2: two entry ids that sanitise alike still get distinct DOM ids, and each label and line belongs to its own radio', async t => {
  const odd = [
    { kind: 'template', id: 'x<b>', title: 'First', line: 'First line.', group: 'a b', group_title: 'Group one' },
    { kind: 'template', id: 'x_b_', title: 'Second', line: 'Second line.', group: 'a_b', group_title: 'Group two' }
  ]
  const h = mountHarness(t, async path => (path === '/scaffold/match' ? matchReply(catalogOf({ entries: odd })) : {}))
  const modal = await h.open()
  const ids = nodes(modal, n => typeof n.props?.id === 'string').map(n => n.props.id)
  assert.equal(new Set(ids).size, ids.length, 'every DOM id in the dialog is unique')
  for (const [key, title, line] of [['template:x<b>', 'First', 'First line.'], ['template:x_b_', 'Second', 'Second line.']]) {
    const radio = radioFor(modal, key)
    assert.equal(labelFor(modal, radio).length, 1, 'one label per radio')
    assert.equal(rowText(modal, key), title)
    assert.equal(textOf(byDomId(modal, radio.props['aria-describedby'])), line)
    assert.match(radio.props.id, /^[A-Za-z][A-Za-z0-9_-]*$/)
  }
  const groups = nodes(modal, n => n.props?.role === 'group')
  assert.deepEqual(groups.map(g => textOf(byDomId(modal, g.props['aria-labelledby']))), ['Group one', 'Group two'])
})

// Plain wording -----------------------------------------------------------------------
test('wording: the dialog names the chosen row by its title and uses plain labels', async t => {
  const h = mountHarness(t, async path => {
    if (path === '/scaffold/kits/video-production') return { kit: { id: 'video-production', summary: 'Folders for a video.' }, tree: ['footage/'] }
    return path === '/scaffold/match' ? matchReply() : {}
  })
  let modal = await h.open()
  assert.equal(textOf(byDomId(modal, 'proposal-template')), 'Nothing chosen yet')
  assert.equal(byDomId(modal, 'new-project-adapter').props['aria-label'], 'Web server library')
  assert.equal(textOf(byDomId(modal, 'new-project-adapter')), 'No choices for this project type')
  assert.equal(textOf(modal).includes('Adapter'), false)
  modal = await pick(h, 'template:python-golden')
  assert.equal(textOf(byDomId(modal, 'proposal-template')), 'Python project', 'the badge shows the title, not the raw id')
  modal = await pick(h, 'kit:video-production')
  assert.equal(textOf(byDomId(modal, 'proposal-template')), 'Video production')
  assert.equal(byDomId(modal, 'proposal-tree').props['aria-label'], 'Folders this workspace creates')
})

test('wording: the jargon listed by the release review is gone from both views', () => {
  const src = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')
  for (const gone of ['Defuzz sent no projects to choose from.', 'Partial creation: inspect the preserved destination paths below.',
    'Check output / partial progress', 'Manual registration required', 'Scaffold acceptance failed', 'Template metadata unavailable',
    'Kit preview unavailable', 'Folders this kit creates', "'Default (no template options)'", 'Unknown / could_not_verify coverage is not a pass',
    'From the report; the summary has no section', 'full list in the raw report', 'None selected (selected_projects',
    "'Full outward scan'", '🚫 Zero network', '🚫 No hooks/scripts launched', ') completed${rId']) {
    assert.equal(src.includes(gone), false, `${gone} is replaced`)
  }
  for (const plain of ['No project types are available right now.', 'They were left in place (listed below); nothing will be deleted.',
    "'What happened'", 'The project was created but not added to Hermes. Add it yourself:', 'The project could not be created.',
    'The list of project types could not be loaded.', 'Could not show the folders for this workspace.',
    'The audit only reports; it changes nothing.', 'No project selected: only your Hermes settings will be checked.',
    'Full check (also follows links to outside folders)', 'No internet use', 'Runs none of your scripts', 'Some parts could not be checked.']) {
    assert.ok(src.includes(plain), `${plain} is used`)
  }
})

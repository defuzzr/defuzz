// New Project dialog, list-first: the whole pick-list comes from the server's
// `catalog` key of /scaffold/match, nothing is pre-selected, and Create stays
// disabled until the person chooses one row.
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

const ENTRIES = [
  { kind: 'template', id: 'python-golden', title: 'Python project', line: 'A Python project with tests and one check command.', group: 'code', group_title: 'Code projects', flag: '--template python-golden' },
  { kind: 'template', id: 'ts-node-golden', title: 'TypeScript service', line: 'A Node service written in TypeScript.', group: 'code', group_title: 'Code projects', flag: '--template ts-node-golden' },
  { kind: 'template', id: 'web-golden', title: 'Static website', line: 'A website built with Vite and TypeScript.', group: 'code', group_title: 'Code projects', flag: '--template web-golden' },
  { kind: 'kit', id: 'video-production', title: 'Video production', line: 'Folders for a video, from script to final cut.', group: 'workspace', group_title: 'Workspaces for files', flag: '--kit video-production' },
  { kind: 'kit', id: 'studio-3d', title: '3D studio', line: 'Render Blender scenes on a rented GPU.', group: 'workspace', group_title: 'Workspaces for files', flag: '--kit studio-3d' }
]
const catalogOf = (overrides = {}) => ({ entries: ENTRIES, suggested: [], notice: '', ...overrides })
const matchReply = (catalog = catalogOf(), extra = {}) => ({ matches: [], closest: [], handoff: null, kits: [], kit_catalog: [], kits_notice: '', preferred: 'none', catalog, ...extra })

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
  const disposers = []
  const timers = []
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
  const fireTimers = async () => {
    for (const entry of timers.splice(0)) if (entry.live) await entry.fn()
  }
  return { ctx, calls, render, modal, open, fireTimers, timers }
}

const radios = tree => nodes(tree, n => n.type === 'input' && n.props?.type === 'radio')
const checkedKeys = tree => radios(tree).filter(r => r.props.checked).map(r => r.props.value)
const radioFor = (tree, key) => radios(tree).find(r => r.props.value === key)
const pick = async (h, key) => { await radioFor(h.modal(), key).props.onChange({ target: { value: key, checked: true } }); return h.modal() }
const rowText = (tree, key) => {
  const radio = radioFor(tree, key)
  const label = nodes(tree, n => n.type === 'label' && n.props?.htmlFor === radio.props.id)[0]
  return textOf(label)
}
const proposeCalls = h => h.calls.filter(c => c.path === '/scaffold/propose')

test('list-first: opening the dialog asks the match route once with an empty idea and renders catalog.entries grouped, in order, with nothing selected', async t => {
  const h = mountHarness(t, async path => (path === '/scaffold/match' ? matchReply() : {}))
  const modal = await h.open()

  const matchCalls = h.calls.filter(c => c.path === '/scaffold/match')
  assert.equal(matchCalls.length, 1, 'one match call on open')
  assert.equal(matchCalls[0].opts.body.prompt, '', 'the open-time match carries an empty idea')
  assert.equal(byDomId(modal, 'project-idea').props.value, '', 'the idea box starts empty')
  assert.equal(byDomId(modal, 'project-idea').props.placeholder, 'Optional: describe your idea to see suggestions')

  const list = byDomId(modal, 'new-project-choice')
  assert.ok(list, 'the pick-list is rendered')
  assert.equal(list.type, 'fieldset')
  const groups = nodes(list, n => n.props?.role === 'group')
  assert.deepEqual(groups.map(g => textOf(byDomId(list, g.props['aria-labelledby']))), ['Code projects', 'Workspaces for files'], 'groups follow the order received and are named by group_title')
  assert.deepEqual(radios(groups[0]).map(r => r.props.value), ['template:python-golden', 'template:ts-node-golden', 'template:web-golden'])
  assert.deepEqual(radios(groups[1]).map(r => r.props.value), ['kit:video-production', 'kit:studio-3d'])

  const all = radios(list)
  assert.equal(all.length, ENTRIES.length, 'every entry is one row')
  assert.ok(all.every(r => r.props.name === all[0].props.name), 'all rows form one radio group')
  assert.deepEqual(checkedKeys(modal), [], 'nothing is selected by default')
  for (const entry of ENTRIES) {
    const radio = radioFor(modal, `${entry.kind}:${entry.id}`)
    assert.equal(rowText(modal, `${entry.kind}:${entry.id}`), entry.title, 'the bound label names the row by its title')
    assert.equal(textOf(byDomId(modal, radio.props['aria-describedby'])), entry.line, 'the line text describes the row')
  }
  assert.equal(nodes(modal, n => n.type === 'select' && (n.props?.id === 'new-project-template' || n.props?.id === 'new-project-kit')).length, 0, 'the two dropdowns are gone')
})

test('list-first: Create is disabled with a readable reason until a row is chosen; no propose request is sent before a choice', async t => {
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') return matchReply()
    if (path === '/scaffold/propose') return { proposal_id: 'p1', template_id: opts.body.template_id, tree: [{ name: opts.body.name, dest: '/srv/projects/' + opts.body.name, files: ['AGENTS.md'] }] }
    if (path === '/scaffold/accept') return { status: 'created', repos: [{ name: opts?.body?.name || 'x', path: '/srv/projects/x', registration: 'registered', registration_result: { registered: true } }] }
    if (path === '/workspace/projects') return { coverage: 'verified', projects: [] }
    return {}
  })
  let modal = await h.open()
  await byDomId(modal, 'new-project-name').props.onChange({ target: { value: 'my-tool' } })
  modal = h.modal()
  const accept = byDomId(modal, 'accept-project')
  assert.equal(accept.props.disabled, true, 'Create is disabled before a choice')
  const reasonId = accept.props['aria-describedby']
  assert.ok(reasonId, 'the disabled Create button points at its reason')
  assert.match(textOf(byDomId(modal, reasonId)), /Choose/i)
  await accept.props.onClick()
  assert.equal(proposeCalls(h).length, 0, 'clicking Create before a choice sends nothing')

  modal = await pick(h, 'template:python-golden')
  assert.deepEqual(checkedKeys(modal), ['template:python-golden'])
  assert.equal(byDomId(modal, 'accept-project').props.disabled, false, 'Create is enabled after a choice')
  assert.equal(byDomId(modal, 'accept-project').props['aria-describedby'], undefined)
  await byDomId(modal, 'accept-project').props.onClick()
  const body = proposeCalls(h).at(-1).opts.body
  assert.equal(body.template_id, 'python-golden', 'the request carries exactly the chosen template id')
  assert.equal(Object.hasOwn(body, 'kit_id'), false)
})

test('list-first: choosing a kit row sends exactly that kit id and shows the kit controls', async t => {
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') return matchReply()
    if (path === '/scaffold/kits/studio-3d') return { kit: { id: 'studio-3d', summary: 'Render Blender scenes on a rented GPU.' }, tree: ['renders/'] }
    if (path === '/scaffold/propose') return { proposal_id: 'pk', kind: 'kit', kit_id: opts.body.kit_id, slug: opts.body.name, tree: [{ name: opts.body.name, dest: '/srv/projects/' + opts.body.name, files: ['renders/'] }] }
    if (path === '/scaffold/accept') return { status: 'created', kind: 'kit', placement: 'on', dest: '/srv/projects/my-tool', repos: [] }
    if (path === '/workspace/projects') return { coverage: 'verified', projects: [] }
    return {}
  })
  let modal = await h.open()
  await byDomId(modal, 'new-project-name').props.onChange({ target: { value: 'my-tool' } })
  modal = await pick(h, 'kit:studio-3d')
  assert.deepEqual(checkedKeys(modal), ['kit:studio-3d'])
  assert.equal(byDomId(modal, 'proposal-tree').props['aria-label'], 'Folders this workspace creates', 'the kit preview appears for the chosen kit')
  assert.equal(byDomId(modal, 'new-project-adapter').props.disabled, true, 'template options do not apply to a kit')
  await byDomId(modal, 'accept-project').props.onClick()
  const body = proposeCalls(h).at(-1).opts.body
  assert.equal(body.kit_id, 'studio-3d')
  assert.equal(Object.hasOwn(body, 'template_id'), false)
})

test('list-first: typing an idea only marks "(suggested)" rows; it never selects, never changes the chosen row and never reorders', async t => {
  const h = mountHarness(t, async (path, opts) => {
    if (path !== '/scaffold/match') return {}
    const prompt = String(opts?.body?.prompt || '')
    return matchReply(catalogOf({ suggested: /video/.test(prompt) ? ['kit:video-production', 'template:web-golden'] : [] }), { preferred: /video/.test(prompt) ? 'kit' : 'none', kits: [{ kit_id: 'video-production', score: 9 }] })
  })
  let modal = await h.open()
  const order = radios(modal).map(r => r.props.value)

  // Without a choice: suggestions mark rows but select nothing.
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'a video for my band' } })
  await h.fireTimers()
  modal = h.modal()
  assert.deepEqual(checkedKeys(modal), [], 'a suggestion never selects a row')
  assert.equal(rowText(modal, 'kit:video-production'), 'Video production (suggested)')
  assert.equal(rowText(modal, 'template:web-golden'), 'Static website (suggested)')
  assert.equal(rowText(modal, 'template:python-golden'), 'Python project')
  assert.deepEqual(radios(modal).map(r => r.props.value), order, 'rows keep the order received')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true)

  // With a choice: the choice survives new suggestions.
  modal = await pick(h, 'template:python-golden')
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: 'a video about cats' } })
  modal = h.modal()
  assert.deepEqual(checkedKeys(modal), ['template:python-golden'], 'editing the idea keeps the chosen row')
  await h.fireTimers()
  modal = h.modal()
  assert.deepEqual(checkedKeys(modal), ['template:python-golden'], 'a new match keeps the chosen row')
  assert.equal(rowText(modal, 'kit:video-production'), 'Video production (suggested)')
  assert.deepEqual(radios(modal).map(r => r.props.value), order)

  // Clearing the idea re-runs the match and drops the marks.
  await byDomId(modal, 'project-idea').props.onChange({ target: { value: '' } })
  await h.fireTimers()
  modal = h.modal()
  assert.equal(rowText(modal, 'kit:video-production'), 'Video production')
  assert.deepEqual(checkedKeys(modal), ['template:python-golden'])
})

test('list-first: catalog.notice is shown once under the list and the list keeps the template rows', async t => {
  const notice = 'Workspace kits need the Componentize plugin. Install it to see them here.'
  const h = mountHarness(t, async path => (path === '/scaffold/match'
    ? matchReply({ entries: ENTRIES.filter(e => e.kind === 'template'), suggested: [], notice })
    : {}))
  const modal = await h.open()
  const shown = nodes(modal, n => n.props?.id === 'kits-notice')
  assert.equal(shown.length, 1, 'the notice is rendered once')
  assert.equal(textOf(shown[0]), notice)
  assert.equal(shown[0].props['data-testid'], 'kits-notice')
  assert.match(byDomId(modal, 'new-project-choice').props['aria-describedby'] || '', /kits-notice/)
  assert.equal(radios(modal).length, 3, 'template rows stay')
  assert.equal(nodes(modal, n => n.props?.role === 'group').length, 1, 'no empty kit group')
})

test('list-first: a failed match shows the plain error, a Check again action, no rows, and Create disabled; Check again loads the list', async t => {
  let fail = true
  const h = mountHarness(t, async path => {
    if (path === '/scaffold/match') {
      if (fail) throw new Error('Defuzz could not be reached')
      return matchReply()
    }
    return {}
  })
  let modal = await h.open()
  assert.equal(radios(modal).length, 0, 'no rows')
  assert.ok(nodes(modal, n => n.props?.role === 'alert' && /Defuzz could not be reached/.test(textOf(n))).length >= 1, 'the plain error is shown')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true)
  const retry = byDomId(modal, 'new-project-choice-retry')
  assert.ok(retry, 'a Check again action is offered')
  assert.equal(textOf(retry), 'Check again')

  fail = false
  await retry.props.onClick()
  modal = h.modal()
  assert.equal(radios(modal).length, ENTRIES.length, 'Check again loads the list')
  assert.deepEqual(checkedKeys(modal), [])
  assert.equal(byDomId(modal, 'new-project-choice-retry'), undefined)
})

test('list-first: a response without a catalog shows no rows and offers Check again', async t => {
  const h = mountHarness(t, async path => (path === '/scaffold/match' ? { matches: [], preferred: 'template' } : {}))
  const modal = await h.open()
  assert.equal(radios(modal).length, 0, 'the page keeps no list of its own')
  assert.ok(byDomId(modal, 'new-project-choice-retry'))
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true)
})

test('list-first: an entry of a kind this page does not know is shown; choosing it explains it cannot be created here and Create stays disabled', async t => {
  const odd = { kind: 'recipe', id: 'cookbook', title: 'Cookbook', line: 'A future kind of entry.', group: 'other', group_title: 'Other', flag: '--recipe cookbook' }
  const h = mountHarness(t, async path => (path === '/scaffold/match' ? matchReply(catalogOf({ entries: [...ENTRIES, odd] })) : {}))
  let modal = await h.open()
  assert.ok(radioFor(modal, 'recipe:cookbook'), 'the unknown entry is shown')
  modal = await pick(h, 'recipe:cookbook')
  assert.deepEqual(checkedKeys(modal), ['recipe:cookbook'])
  assert.match(textOf(byDomId(modal, 'new-project-choice-unsupported')), /cannot create/i)
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true)
  await byDomId(modal, 'accept-project').props.onClick()
  assert.equal(proposeCalls(h).length, 0)

  // Choosing a known row afterwards clears the explanation.
  await byDomId(h.modal(), 'new-project-name').props.onChange({ target: { value: 'inventory-api' } })
  modal = await pick(h, 'template:ts-node-golden')
  assert.equal(byDomId(modal, 'new-project-choice-unsupported'), undefined)
  assert.equal(byDomId(modal, 'accept-project').props.disabled, false)
})

test('list-first: Home and End jump to the first and last row and focus it; other keys are left to the native radio group', async t => {
  const h = mountHarness(t, async path => (path === '/scaffold/match' ? matchReply() : {}))
  await h.open()
  const focused = []
  const fakeRadios = ENTRIES.map((e, i) => ({ focus: () => focused.push(i) }))
  const keyEvent = key => {
    const ev = { key, prevented: false, preventDefault() { ev.prevented = true }, currentTarget: { querySelectorAll: sel => (sel.includes('radio') ? fakeRadios : []) } }
    return ev
  }
  const end = keyEvent('End')
  await byDomId(h.modal(), 'new-project-choice').props.onKeyDown(end)
  assert.equal(end.prevented, true)
  assert.deepEqual(focused, [ENTRIES.length - 1])
  assert.deepEqual(checkedKeys(h.modal()), ['kit:studio-3d'])

  const home = keyEvent('Home')
  await byDomId(h.modal(), 'new-project-choice').props.onKeyDown(home)
  assert.equal(home.prevented, true)
  assert.deepEqual(focused, [ENTRIES.length - 1, 0])
  assert.deepEqual(checkedKeys(h.modal()), ['template:python-golden'])

  const down = keyEvent('ArrowDown')
  await byDomId(h.modal(), 'new-project-choice').props.onKeyDown(down)
  assert.equal(down.prevented, false, 'arrow keys stay native')
  assert.deepEqual(checkedKeys(h.modal()), ['template:python-golden'])
})

test('list-first: the list scrolls inside the dialog and its layout has no fixed width wider than a phone', async t => {
  const h = mountHarness(t, async path => (path === '/scaffold/match' ? matchReply() : {}))
  const modal = await h.open()
  const list = byDomId(modal, 'new-project-choice')
  assert.equal(list.props.style.overflowY, 'auto', 'the list scrolls inside the dialog')
  assert.ok(list.props.style.maxHeight, 'the list has a bounded height')
  assert.equal(list.props.style.minWidth, 0)
  assert.equal(modal.props.style.overflowY, 'auto', 'the dialog itself scrolls at small heights')
  const widths = JSON.stringify(modal).match(/"(?:min)?[wW]idth":"\d+px"/g) || []
  assert.deepEqual(widths.filter(w => Number(w.match(/(\d+)px/)[1]) > 360), [], 'no fixed width wider than 360px')
})

test('list-first: the guessing code and the sample idea are gone from the page source', () => {
  const src = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')
  for (const gone of ['Suggested for this idea', 'Inventory API for my shop', 'manualChoiceSinceIdea', 'kitAutoSelected', 'kit-suggested-hint', 'tech-stack-kit-notice', 'Choose a tech stack', 'None (code project)', 'modalLanguagesChosen', 'match-fallback-notice',
    // the removed idea-parsing and hand-off paths
    'parse-idea', 'languages_chosen', 'languagesChosen', 'noMatch', 'ambiguous', 'chips:', 'remember(', 'remember:', 'adapt:', 'syncModalOptionsFromMatch']) {
    assert.equal(src.includes(gone), false, `${gone} is removed`)
  }
  assert.doesNotMatch(src, /\.preferred\b/, 'the page never reads preferred')
  // The only first-template fallback left belongs to the workspace view, not the dialog.
  assert.deepEqual(src.match(/.*\|\| V10_TEMPLATES\[0\].*/g).map(line => line.trim().split(' =')[0]), ['const activeTemplateSpec'], 'no hidden first-template fallback in the dialog')
})

test('the project name starts empty with a placeholder; Create stays disabled until a name is given', async t => {
  const h = mountHarness(t, async (path, opts) => {
    if (path === '/scaffold/match') return matchReply()
    if (path === '/scaffold/propose') return { proposal_id: 'pn', template_id: opts.body.template_id, tree: [{ name: opts.body.name, dest: '/srv/projects/' + opts.body.name, files: ['AGENTS.md'] }] }
    return {}
  })
  let modal = await h.open()
  const name = byDomId(modal, 'new-project-name')
  assert.equal(name.props.value, '', 'no sample name is filled in')
  assert.equal(name.props.placeholder, 'my-project')
  modal = await pick(h, 'template:python-golden')
  assert.equal(byDomId(modal, 'accept-project').props.disabled, true, 'a chosen row alone does not enable Create')
  await byDomId(modal, 'accept-project').props.onClick()
  assert.equal(proposeCalls(h).length, 0, 'nothing is sent without a name')
  await byDomId(modal, 'new-project-name').props.onChange({ target: { value: 'my-tool' } })
  modal = h.modal()
  assert.equal(byDomId(modal, 'accept-project').props.disabled, false, 'a valid name and a chosen row enable Create')
})

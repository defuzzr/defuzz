import test from 'node:test'
import assert from 'node:assert/strict'
import { WorkspacePage } from '../plugin.js'
import { AUDIT_REPORT, AUDIT_SUMMARY } from './auditViewFixture.mjs'

const nodes = (node, predicate) => !node || typeof node !== 'object' ? [] : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => nodes(child, predicate))]
const byId = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)[0]
const allById = (tree, id) => nodes(tree, n => n.props?.['data-testid'] === id)
const byDomId = (tree, id) => nodes(tree, n => n.props?.id === id)[0]
const textOf = node => !node ? '' : typeof node === 'string' || typeof node === 'number' ? String(node) : [node.props?.children].flat().map(textOf).join('')
const clone = value => JSON.parse(JSON.stringify(value))

function fixture(summary = AUDIT_SUMMARY, report = AUDIT_REPORT) {
  const calls = []
  const ctx = { onDispose() {}, async rest(path, opts) {
    calls.push({ path, opts })
    if (path === '/audit/scope') return { scope_disclosure: 'Server scope' }
    if (path === '/audit/start') return { run_id: 'run-1', status: 'completed' }
    if (path.startsWith('/audit/status')) return { run_id: 'run-1', status: 'completed' }
    if (path.startsWith('/audit/report')) return { run_id: 'run-1', status: 'completed', report }
    if (path.startsWith('/audit/summary')) return summary
    return {}
  } }
  return { ctx, calls }
}

function renderHarness(t, Component, props) {
  const slots = []
  let cursor = 0
  globalThis.__adoptTestUseState = init => {
    const i = cursor++
    if (!(i in slots)) slots[i] = typeof init === 'function' ? init() : init
    return [slots[i], next => { slots[i] = typeof next === 'function' ? next(slots[i]) : next }]
  }
  t.after(() => delete globalThis.__adoptTestUseState)
  return () => { cursor = 0; return Component(props) }
}

async function auditView(t, summary, report) {
  const h = fixture(summary, report)
  const render = renderHarness(t, WorkspacePage, { ctx: h.ctx })
  await byDomId(render(), 'audit-full-button').props.onClick()
  byDomId(byDomId(render(), 'audit-review-dialog'), 'audit-review-consent').props.onChange({ target: { checked: true } })
  await byDomId(render(), 'audit-review-run').props.onClick()
  return { render, view: byId(byId(render(), 'footer-audit-output'), 'audit-sections') }
}

const sectionsOf = view => nodes(view, n => typeof n.props?.['data-audit-section'] === 'string')
const sectionOf = (view, key) => sectionsOf(view).find(n => n.props['data-audit-section'] === key)

test('every summary section is shown, in the backend order, with its title', async t => {
  const { view } = await auditView(t)
  assert.ok(view, 'structured audit view is shown')
  const keys = sectionsOf(view).map(n => n.props['data-audit-section'])
  const backend = AUDIT_SUMMARY.summary.sections.map(s => s.section)
  assert.deepEqual(keys.slice(0, backend.length), backend)
  for (const s of AUDIT_SUMMARY.summary.sections) assert.match(textOf(sectionOf(view, s.section)), new RegExp(s.title))
  // The newer sections are there, with their headline and findings.
  assert.match(textOf(sectionOf(view, 'write_settings')), /Skill edits saved without a prompt/)
  assert.match(textOf(sectionOf(view, 'skill_packs')), /skills listed/)
  assert.match(textOf(sectionOf(view, 'kanban_residue')), /Review suggested/)
})

test('a section the page has never seen gets the generic layout, not nothing', async t => {
  const summary = clone(AUDIT_SUMMARY)
  summary.summary.sections.push({ section: 'brand_new_check', title: 'A brand new check', measured: true, partial: false, reason: null,
    headline: 'Seven things were counted.', numbers: { things: 7 },
    findings: { warning: [{ rule_id: 'brand_new_check.something', sentence: 'Something new was found.', count: 2, evidence: [['things', 7]] }], review_suggested: [], info: [] } })
  const { view } = await auditView(t, summary)
  const keys = sectionsOf(view).map(n => n.props['data-audit-section'])
  assert.equal(keys[AUDIT_SUMMARY.summary.sections.length], 'brand_new_check')
  const text = textOf(sectionOf(view, 'brand_new_check'))
  assert.match(text, /A brand new check/)
  assert.match(text, /Seven things were counted\./)
  assert.match(text, /Warning/)
  assert.match(text, /Something new was found\. \(2 times\)/)
})

test('could_not_verify and not measured are shown as such, never as "no findings"', async t => {
  const { view } = await auditView(t)
  const workdirs = sectionOf(view, 'home_workdirs')
  const status = textOf(byId(workdirs, 'audit-section-status'))
  assert.match(status, /not measured/i)
  assert.match(status, /collector failed/)
  assert.match(textOf(workdirs), /Could not verify: The home_workdirs check exceeded its time budget and could not be verified\./)
  assert.doesNotMatch(textOf(workdirs), /\b0 findings|No findings/)
  const sessions = sectionOf(view, 'session_contamination')
  assert.match(textOf(byId(sessions, 'audit-section-status')), /not measured \(not run this time\)/i)
  assert.doesNotMatch(textOf(sessions), /\b0 findings|No findings/)
  // A partly measured section says so in words.
  assert.match(textOf(byId(sectionOf(view, 'skill_packs'), 'audit-section-status')), /partly measured/i)
  // A check the summary does not cover, but the report does, is listed from the report.
  const other = sectionOf(view, 'profile_context')
  assert.ok(other, 'report-only check is shown')
  assert.match(textOf(byId(other, 'audit-section-status')), /could not verify/i)
  assert.match(textOf(other), /The profile_context check stopped without a usable result and could not be verified\./)
})

test('a measured section without findings says so in words', async t => {
  const summary = clone(AUDIT_SUMMARY)
  const sec = summary.summary.sections.find(s => s.section === 'unattended_exposure')
  sec.findings = { warning: [], review_suggested: [], info: [] }
  const { view } = await auditView(t, summary)
  assert.match(textOf(sectionOf(view, 'unattended_exposure')), /No findings in this section\./)
  assert.match(textOf(byId(sectionOf(view, 'unattended_exposure'), 'audit-section-status')), /^Measured/)
})

test('report text is rendered as text and long values wrap', async t => {
  const hostile = '<img src=x onerror=alert(1)> & <b>bold</b>'
  const summary = clone(AUDIT_SUMMARY)
  summary.summary.sections[0].title = `Title ${hostile}`
  summary.summary.sections[0].headline = `Headline ${hostile}`
  summary.summary.sections[0].findings.warning[0].sentence = `Sentence ${hostile} ${'x'.repeat(400)}`
  const report = clone(AUDIT_REPORT)
  report.findings.push({ id: 'zz_other.thing', classification: 'info', coverage: 'verified', consequence: `Other ${hostile}` })
  const { view } = await auditView(t, summary, report)
  const json = JSON.stringify(view)
  assert.doesNotMatch(json, /dangerouslySetInnerHTML/)
  assert.equal(nodes(view, n => n.type === 'img' || n.type === 'b' || n.type === 'script').length, 0)
  const strings = nodes(view, () => true).flatMap(n => [n.props?.children].flat().filter(c => typeof c === 'string'))
  assert.ok(strings.some(s => s.includes(`Title ${hostile}`)))
  assert.ok(strings.some(s => s.includes(`Sentence ${hostile}`)))
  assert.ok(strings.some(s => s.includes(`Other ${hostile}`)))
  assert.equal(view.props.style.overflowWrap, 'anywhere')
  assert.equal(view.props.style.whiteSpace, 'pre-wrap')
})

test('30 sections and 200 findings stay readable: 15 rows per list, the rest as a count', async t => {
  const summary = clone(AUDIT_SUMMARY)
  summary.summary.sections = Array.from({ length: 30 }, (_, i) => ({ section: `s${i}`, title: `Section ${i}`, measured: true, partial: false, reason: null,
    headline: `Headline ${i}.`, numbers: {}, findings: { warning: [], review_suggested: [], info: [] } }))
  summary.summary.sections[0].findings.warning = Array.from({ length: 200 }, (_, i) => ({ rule_id: `s0.rule${i}`, sentence: `Finding ${i}.`, count: 1, evidence: [] }))
  const { view } = await auditView(t, summary, { findings: [] })
  assert.equal(sectionsOf(view).length, 30)
  const first = sectionOf(view, 's0')
  assert.equal(allById(first, 'audit-finding').length, 15)
  assert.match(textOf(first), /185 more\. Choose “Show raw report” to see all\./)
  assert.match(textOf(first), /Finding 14\./)
  assert.doesNotMatch(textOf(first), /Finding 15\./)
})

test('each section is a labelled region with a heading; no actions inside the view', async t => {
  const { view } = await auditView(t)
  assert.ok(sectionsOf(view).length >= AUDIT_SUMMARY.summary.sections.length)
  for (const sec of sectionsOf(view)) {
    assert.equal(sec.type, 'section')
    const labelId = sec.props['aria-labelledby']
    assert.ok(labelId)
    const heading = byDomId(sec, labelId)
    assert.ok(heading && /^h[1-6]$/.test(heading.type), `heading for ${sec.props['data-audit-section']}`)
    assert.ok(textOf(byId(sec, 'audit-section-status')).length > 0, 'status is text')
  }
  assert.equal(nodes(view, n => n.type === 'button' || typeof n.props?.onClick === 'function').length, 0)
})

test('summary counts, not-measured list and next steps come from the summary', async t => {
  const { view } = await auditView(t)
  const c = AUDIT_SUMMARY.summary.counts
  assert.match(textOf(view), new RegExp(`Findings: ${c.warning} warnings, ${c.review_suggested} review suggested, ${c.info} for information`))
  assert.match(textOf(view), /Not measured this time: Memory from other projects in past sessions \(not run this time\), Work files inside the Hermes home \(collector failed\)/)
  for (const step of AUDIT_SUMMARY.summary.next_steps) assert.ok(textOf(view).includes(step))
})

test('without structured sections the plain text stays the fallback', async t => {
  const { render, view } = await auditView(t, { run_id: 'run-1', status: 'completed', text: 'Plain only\n', summary: {} })
  assert.equal(view, undefined)
  assert.equal(textOf(byId(render(), 'audit-summary')), 'Plain only\n')
})

test('raw report stays one toggle away', async t => {
  const { render } = await auditView(t)
  const toggle = byId(render(), 'audit-summary-toggle')
  assert.equal(textOf(toggle), 'Show raw report')
  toggle.props.onClick()
  const footer = byId(render(), 'footer-audit-output')
  assert.equal(byId(footer, 'audit-sections'), undefined)
  assert.match(textOf(footer), /secret_file_copies\.secret_named_files_in_work_folders/)
})

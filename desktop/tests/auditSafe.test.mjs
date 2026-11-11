// Release-review fixes for the audit view: report text is shown escaped the way
// audit_summary.safe_text escapes it, and codes are shown as the command-line phrases.
import test from 'node:test'
import assert from 'node:assert/strict'
import * as ui from '../plugin.js'

const textOf = node =>
  !node
    ? ''
    : typeof node === 'string' || typeof node === 'number'
      ? String(node)
      : [node.props?.children].flat().map(textOf).join('')

// S5 ---------------------------------------------------------------------------------
// Expected strings are what audit_summary.safe_text returns for the same input.
test('S5: auditSafe escapes control, bidi and separator characters exactly like safe_text', () => {
  assert.equal(ui.auditSafe('evil\u202etxt.exe\nline2'), 'evil\\u202etxt.exe line2')
  assert.equal(ui.auditSafe('a\x1bb\x7fc\x85d\u2028e\u2066f\tg\rh'), 'a\\x1bb\\x7fc\\x85d\\u2028e\\u2066f g h')
  assert.equal(ui.auditSafe('/a\u202eb\nc', true), '/a\\u202eb\\x0ac')
  assert.equal(ui.auditSafe('plain é ü 日本'), 'plain é ü 日本')
  assert.equal(ui.auditSafe(null), '')
  assert.equal(ui.auditSafe(12), '12')
  assert.equal(ui.auditSafe(ui.auditSafe('x\u202ey')), 'x\\u202ey', 'idempotent')
})

const BIDI = '\u202e'
const summaryWith = patch => ({ summary: { measured_on: '2026-11-10', counts: { warning: 1, review_suggested: 0, info: 0 }, other_findings: 0,
  biggest_items: [{ label: `Large${BIDI}file`, value: 2048, unit: 'bytes', path: `work/a${BIDI}gpj.exe\nx` }],
  not_measured: [{ section: 'kanban_residue', title: `Board${BIDI}`, reason: 'not_run' }],
  sections: [{ section: 'home_workdirs', title: `Work${BIDI} files`, measured: true, partial: false, reason: null, headline: `Head${BIDI}\nline`, numbers: {},
    findings: { warning: [{ rule_id: 'home_workdirs.x', sentence: `evil${BIDI}txt.exe\nline2`, count: 2, evidence: [[`files${BIDI}_seen`, 3]] }], review_suggested: [], info: [] } }],
  next_steps: [`Step${BIDI}`], ...patch } })

test('S5: every audit text from the report is shown escaped', () => {
  const model = ui.auditViewModel(summaryWith({}), { report: { findings: [{ id: 'other_check.x', classification: 'info', coverage: 'verified', consequence: `Other${BIDI}\nfake line` }] } })
  const all = JSON.stringify(model)
  assert.equal(all.includes(BIDI), false, 'no raw U+202E anywhere in the view model')
  const sec = model.sections[0]
  assert.equal(sec.title, 'Work\\u202e files')
  assert.deepEqual(sec.headline, ['Head\\u202e line'])
  assert.equal(sec.groups[0].rows[0], 'evil\\u202etxt.exe line2 (2 times) [files\\u202e seen 3]')
  assert.equal(model.biggest[0], 'Large\\u202efile: 2.0 KB (work/a\\u202egpj.exe\\x0ax)')
  assert.match(model.notMeasuredLine, /Board\\u202e/)
  assert.deepEqual(model.nextSteps, ['Step\\u202e'])
  assert.equal(model.sections[1].groups[0].rows[0], 'Other\\u202e fake line')
  // The rendered view holds no raw control or bidi character either.
  const tree = ui.auditSummaryView(model)
  assert.doesNotMatch(textOf(tree), /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u2028\u2029]/)
})

// S6 ---------------------------------------------------------------------------------
test('S6: reasons, units and evidence use the command-line phrases; unknown codes fall back to words', () => {
  const s = summaryWith({
    biggest_items: [
      { label: 'Task board logs', value: 2048, unit: 'bytes', path: null },
      { label: 'Text sent with every request', value: 13200, unit: 'characters', path: null },
      { label: 'Cache', value: 12, unit: 'files_count', path: null }
    ],
    not_measured: [
      { section: 'a', title: 'A', reason: 'not_run' },
      { section: 'b', title: 'B', reason: 'bounded_quick_audit_not_collected' },
      { section: 'c', title: 'C', reason: 'timed_out' },
      { section: 'd', title: 'D', reason: null }
    ]
  })
  s.summary.sections = [
    { section: 'a', title: 'A', measured: false, partial: false, reason: 'not_run', headline: null, numbers: {}, findings: {} },
    { section: 'b', title: 'B', measured: false, partial: false, reason: 'not_in_report', headline: null, numbers: {}, findings: {} },
    { section: 'c', title: 'C', measured: false, partial: false, reason: 'timed_out', headline: null, numbers: {}, findings: {} },
    { section: 'd', title: 'D', measured: true, partial: true, reason: 'could_not_verify', headline: 'Counted.', numbers: {},
      findings: { warning: [{ rule_id: 'd.x', sentence: 'Found.', count: 1, evidence: [['total_bytes', 2048], ['share', 0.25], ['files_seen', 1234]] }] } },
    { section: 'e', title: 'E', measured: true, partial: true, reason: 'permission_denied', headline: 'Counted.', numbers: {}, findings: {} }
  ]
  const model = ui.auditViewModel(s, { report: { findings: [{ id: 'profile_context.x', classification: 'info', coverage: 'could_not_verify', consequence: 'Stopped.' }] } })
  const status = key => model.sections.find(x => x.key === key).status
  assert.equal(status('a'), 'Not measured (not run this time).')
  assert.equal(status('b'), 'Not measured (not part of this report).')
  assert.equal(status('c'), 'Not measured (timed out).')
  assert.equal(status('d'), 'Partly measured: some parts could not be checked (could not be verified).')
  assert.equal(status('e'), 'Partly measured: some parts could not be checked (permission denied).')
  assert.equal(model.sections.find(x => x.key === 'd').groups[0].rows[0], 'Found. [total bytes 2.0 KB, share 25%, files seen 1,234]')
  assert.deepEqual(model.biggest, ['Task board logs: 2.0 KB', 'Text sent with every request: 13,200 characters', 'Cache: 12 files count'])
  assert.equal(model.notMeasuredLine, 'Not measured this time: A (not run this time), B (not included in a quick audit), C (timed out), D (unknown).')
  const other = model.sections.find(x => x.key === 'profile_context')
  assert.equal(other.title, 'Other check: Profile context')
  assert.equal(ui.auditReasonPhrase(''), 'unknown')
  assert.equal(ui.auditReasonPhrase('some_new_code'), 'some new code')
})


// Outward-sweep reason codes use the command-line sentences (audit_summary._SCOPE_NOTES).
test('S7: outward-sweep reason codes give the command-line phrases; unknown still falls back', () => {
  assert.equal(ui.auditReasonPhrase('skipped_folders'), 'dependency, cache and Git object folders were skipped and not checked')
  assert.equal(ui.auditReasonPhrase('entry_limit_exceeded'), 'some folders were not fully checked because the entry limit was reached')
  assert.equal(ui.auditReasonPhrase('total_byte_limit_exceeded'), 'some folders were not fully checked because the size limit was reached')
  // time_budget is used by every section, not only the outward sweep: one phrase in both tables.
  assert.equal(ui.auditReasonPhrase('time_budget'), 'the audit time limit was reached')
  assert.equal(ui.auditReasonPhrase('another_new_code'), 'another new code')
})

// The page's table holds the same reason codes and phrases as audit_summary._REASON_PHRASES
// (tests/test_audit_summary_reasons_complete.py compares the two tables).
test('S7b: memory, profile and limit reason codes have plain phrases on the page', () => {
  const phrases = {
    input_unknown: 'a setting the check needs could not be read',
    missing: 'the file or folder it reads was not found',
    no_projects: 'there are no projects to compare with',
    default_profile_never_archived: 'the default profile is never offered for archiving',
    active_profile_never_archived: 'the active profile is never offered for archiving',
    within_active_threshold: 'the profile was used recently',
    file_bytes: 'a file was larger than the size limit',
    entry_budget: 'a folder had more entries than the audit limit',
    scandir_error: 'a folder could not be listed'
  }
  for (const [code, phrase] of Object.entries(phrases)) assert.equal(ui.auditReasonPhrase(code), phrase)
})

test('S8: summary scope_notes are shown as escaped lines', () => {
  const s = summaryWith({ scope_notes: ['Dependency, cache and Git object folders were skipped and not checked.', 'Odd\u202e note', 7] })
  const model = ui.auditViewModel(s, { report: { findings: [] } })
  assert.deepEqual(model.scopeNotes, ['Dependency, cache and Git object folders were skipped and not checked.', 'Odd\\u202e note'])
  const text = textOf(ui.auditSummaryView(model))
  assert.match(text, /Dependency, cache and Git object folders were skipped and not checked\./)
  assert.doesNotMatch(text, /\u202e/)
})

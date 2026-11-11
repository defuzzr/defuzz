import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { mountHarness, nodes, byDomId, matchReply, textOf } from './dialogHarness.mjs'
import { V10_AUDIT_SCRIPTS, V10_LINT_CHECK_GROUPS } from '../plugin.js'

// Taken from verified definitions in Hermes desktop src/styles.css.
// Keep this list explicit: a new token must be checked against the host stylesheet.
const HOST_TOKENS = new Set([
  '--font-mono', '--ui-accent', '--ui-stroke-secondary', '--ui-text-primary',
  '--ui-text-secondary', '--ui-text-quaternary', '--ui-bg-elevated',
  '--ui-bg-secondary', '--ui-bg-tertiary'
])
const source = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')

test('page styles never use fixed host fills with theme-following ink', () => {
  // Hermes styles.css:314 defines this as #fcfcfc, with no dark override.
  // Ban it throughout the page, including inherited ink and literal fallbacks.
  const fixedHostFills = ['--ui-bg-input']
  for (const token of fixedHostFills) assert.ok(!source.includes(token), `${token} cannot contrast with theme-following text in both modes`)
})

test('Settings lint badge counts the actual tool list, including newly added tools', async t => {
  const h = mountHarness(t, async () => ({}))
  byDomId(h.render(), 'settings-button').props.onClick()
  const count = () => Object.values(V10_LINT_CHECK_GROUPS).flat().length
  assert.equal(textOf(byDomId(h.render(), 'lint-tab')), `Lint rules ${count()} tools`)
  V10_LINT_CHECK_GROUPS.python.push({ ...V10_LINT_CHECK_GROUPS.python[0], id: 'future-tool' })
  try {
    assert.equal(textOf(byDomId(h.render(), 'lint-tab')), `Lint rules ${count()} tools`)
  } finally {
    V10_LINT_CHECK_GROUPS.python.pop()
  }
})

for (const kind of ['lint', 'auditor']) {
  test(`Settings ${kind} counts in badges and comparison follow their lists`, t => {
    const h = mountHarness(t, async () => ({}))
    byDomId(h.render(), 'settings-button').props.onClick()
    byDomId(h.render(), 'lint-tab').props.onClick()
    const list = kind === 'lint' ? V10_LINT_CHECK_GROUPS.python : V10_AUDIT_SCRIPTS
    const check = () => {
      const count = kind === 'lint' ? Object.values(V10_LINT_CHECK_GROUPS).flat().length : list.length
      const label = kind === 'lint' ? 'Lint rules' : 'Auditor'
      const unit = kind === 'lint' ? 'tools' : 'scripts'
      assert.equal(textOf(byDomId(h.render(), `${kind}-tab`)), `${label} ${count} ${unit}`)
      assert.ok(nodes(h.render(), n => n.type === 'span' && textOf(n) === `${label} (${count} ${unit})`).length)
    }
    check()
    list.push({ ...list[0], id: 'future-entry' })
    try { check() } finally { list.pop() }
  })
}

test('auditor guide denominators follow added scripts', t => {
  const h = mountHarness(t, async () => ({}))
  byDomId(h.render(), 'settings-button').props.onClick()
  byDomId(h.render(), 'auditor-tab').props.onClick()
  byDomId(h.render(), 'tutorial-toggle').props.onClick()
  nodes(h.render(), n => n.props?.['data-testid'] === 'v10-stage-card-2')[0].props.onClick()
  const check = () => {
    const count = String(V10_AUDIT_SCRIPTS.length).padStart(2, '0')
    assert.ok(textOf(byDomId(h.render(), 'spot-text')).includes(`/${count}]:`))
    assert.ok(textOf(byDomId(h.render(), 'spot-sync')).includes(`/${count} (`))
  }
  check()
  V10_AUDIT_SCRIPTS.push({ ...V10_AUDIT_SCRIPTS[0], id: 'future-script' })
  try { check() } finally { V10_AUDIT_SCRIPTS.pop() }
})

for (const [label, opener] of [
  ['Confirm tool setup', 'Review setup confirmation'],
  ['Confirm lock trust', 'Review trust confirmation'],
  ['Educational pipeline preview', null]
]) {
  test(`${label} has its own raised opaque fill`, async t => {
    const h = mountHarness(t, async () => ({}))
    byDomId(h.render(), 'settings-button').props.onClick()
    if (opener) {
      // Exercise the review-only reveal; no setup or trust request is sent.
      nodes(h.render(), n => n.type === 'Button' && textOf(n) === opener)[0].props.onClick()
    } else byDomId(h.render(), 'tutorial-toggle').props.onClick()
    const panel = nodes(h.render(), n => n.props?.['aria-label'] === label)[0]
    assert.ok(panel)
    assert.equal(panel.props.style?.background, 'var(--ui-bg-elevated, #1f2428)')
    assert.equal(panel.props['data-glass-raised'], true)
  })
}

test('fallback literals exclude non-opaque CSS keywords', () => {
  for (const keyword of ['transparent', 'inherit', 'initial', 'unset', 'none']) {
    assert.equal(literalFallback.test(`, ${keyword})`), false, keyword)
  }
  assert.ok(literalFallback.test(', #1f2428)'))
})

const literalFallback = /^\s*,\s*(?:#[\da-f]{3,8}\b|(?:rgb|rgba|hsl|hsla)\([^)]*\)|(?!transparent\b|inherit\b|initial\b|unset\b|none\b)[a-z]+)\s*\)/i

test('every CSS variable is defined by Hermes or has a literal fallback', () => {
  const missing = [...source.matchAll(/var\(\s*(--[\w-]+)/g)]
    .filter(m => !HOST_TOKENS.has(m[1]) && !literalFallback.test(source.slice(m.index + m[0].length)))
    .map(m => m[1])
  assert.deepEqual([...new Set(missing)].sort(), [])
})

test('page CSS variables exist in the configured Hermes stylesheet', t => {
  const root = process.env.DEFUZZ_HERMES_SOURCE
  const stylesheet = root && join(root, 'apps/desktop/src/styles.css')
  if (!stylesheet || !existsSync(stylesheet)) {
    t.skip('Set DEFUZZ_HERMES_SOURCE to a Hermes checkout containing apps/desktop/src/styles.css')
    return
  }
  const definitions = new Set([...readFileSync(stylesheet, 'utf8').matchAll(/(--[\w-]+)\s*:/g)].map(m => m[1]))
  const used = new Set([...source.matchAll(/var\(\s*(--[\w-]+)/g)].map(m => m[1]))
  assert.deepEqual([...used].filter(token => !definitions.has(token)).sort(), [])
})

function assertDialog(tree, panel) {
  assert.ok(panel, 'dialog opened')
  const id = panel.props.id || panel.props['aria-label'] || 'dialog'
  assert.match(panel.props.style.background, /^var\(--ui-bg-elevated, #[\da-f]{6}\)$/i, `${id}: opaque themed fill and fallback`)
  assert.equal(panel.props['data-glass-raised'], true, `${id}: glass compatibility marker retained`)
  assert.equal(panel.props.style.color, 'var(--ui-text-primary)')
  const backdrop = nodes(tree, n => n.props?.style?.position === 'fixed' && nodes(n).includes(panel))[0]
  assert.ok(backdrop, `${id}: backdrop`)
  assert.match(backdrop.props.style.background, /^rgba\(0, 0, 0, 0\.[1-9]\d*\)$/)
  assert.ok(backdrop.props.style.zIndex >= 50)
  return backdrop
}

test('every rendered dialog has an opaque panel and dimming backdrop', async t => {
  const found = new Set()
  for (const [id, opener] of [
    ['new-project-dialog', 'start-project'],
    ['projects-folder-dialog', 'projects-folder-change'],
    ['audit-review-dialog', 'audit-full-button'],
    ['plugin-storage-dialog', 'plugin-storage-button']
  ]) {
    await t.test(`${id} has a readable raised panel and a dimmed backdrop`, async t => {
      const h = mountHarness(t, async path => path === '/scaffold/match' ? matchReply() : { scope_disclosure: 'Read-only audit scope' })
      if (id === 'projects-folder-dialog') await h.open()
      await byDomId(h.render(), opener).props.onClick()
      const tree = h.render()
      for (const panel of nodes(tree, n => n.props?.role === 'dialog' || n.props?.['aria-modal'] !== undefined)) {
        assertDialog(tree, panel)
        found.add(panel.props.id || panel)
      }
      const backdrop = assertDialog(tree, byDomId(tree, id))
      if (id === 'projects-folder-dialog') {
        const parent = assertDialog(tree, byDomId(tree, 'new-project-dialog'))
        assert.equal(parent.props.style.zIndex, 50)
        assert.equal(backdrop.props.style.zIndex, 60)
      }
    })
  }
  assert.ok(found.size >= 4, 'at least four distinct dialogs exercised')
})

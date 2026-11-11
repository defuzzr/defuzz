import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import * as ui from '../plugin.js'

const templatesDir = new URL('../../templates/', import.meta.url)
const bundled = readdirSync(templatesDir).filter(id => existsSync(new URL(`${id}/template.yaml`, templatesDir))).sort()

function manifest(id) {
  const raw = readFileSync(new URL(`${id}/template.yaml`, templatesDir), 'utf8')
  return {
    name: raw.match(/^name:\s*(.+)$/m)[1].trim(),
    summary: raw.match(/^summary:\s*(.+)$/m)[1].trim(),
    kind: raw.match(/^kind:\s*(\S+)$/m)[1],
    layout: raw.match(/^layout:\s*(\S+)$/m)[1],
    languages: raw.match(/^languages:\s*\[([^\]]+)\]/m)[1].split(',').map(s => s.trim())
  }
}

test('Start project lists every bundled template, web-golden included, each once', () => {
  const ids = ui.V10_TEMPLATES.map(t => t.id)
  assert.deepEqual([...ids].sort(), bundled)
  assert.equal(new Set(ids).size, ids.length)
  assert.equal(new Set(ui.V10_TEMPLATES.map(t => t.badge)).size, ids.length, 'badges are distinct')
})

test('web-golden entry is truthful: kind, layout, language, summary and preview tree match the template', () => {
  const tpl = ui.V10_TEMPLATES.find(t => t.id === 'web-golden')
  assert.ok(tpl)
  const m = manifest('web-golden')
  assert.equal(tpl.kind, m.kind)
  assert.equal(tpl.layout, m.layout)
  assert.deepEqual([tpl.language], m.languages)
  assert.match(tpl.label, /website/i)
  assert.match(tpl.label, /Vite/)
  assert.match(tpl.label, /TypeScript/)
  for (const word of ['Static-first', 'Vite', 'TypeScript', 'no framework', 'design tokens', 'CSS custom properties', 'accessible pages']) {
    assert.ok(tpl.summary.includes(word), `summary says ${word}`)
    assert.ok(m.summary.includes(word), `template.yaml summary says ${word}`)
  }
  const root = new URL('web-golden/tmpl_prefix/', templatesDir)
  for (const entry of tpl.previewTree) {
    if (entry === 'AGENTS.md') continue // written at creation (the template's own copy moves to docs/)
    const target = new URL(entry, root)
    assert.ok(existsSync(target), `${entry} exists in the template`)
    assert.equal(statSync(target).isDirectory(), entry.endsWith('/'), `${entry} is ${entry.endsWith('/') ? 'a folder' : 'a file'}`)
  }
  assert.equal(tpl.options, undefined, 'web-golden has no options')
})

test('the Start project list takes its rows from the server list, not from V10_TEMPLATES; the filter pills still count every bundled template', () => {
  const src = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')
  assert.match(src, /const catalogEntries = current\.catalog\?\.entries \|\| \[\]/)
  assert.doesNotMatch(src, /V10_TEMPLATES\.map\(t => jsx\('option'/, 'no dropdown of bundled templates')
  assert.match(src, /All templates \(\$\{V10_TEMPLATES\.length\}\)/)
})

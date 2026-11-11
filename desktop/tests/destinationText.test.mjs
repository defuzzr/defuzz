import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as ui from '../plugin.js'

const src = readFileSync(new URL('../plugin.js', import.meta.url), 'utf8')

test('destination text is under the chosen projects folder', () => {
  assert.equal(ui.projectDestinationText('/srv/work', 'demo'), '/srv/work/demo')
  assert.equal(ui.projectDestinationText('/srv/work/', 'demo'), '/srv/work/demo')
  assert.equal(ui.projectDestinationText('C:\\work\\', 'demo'), 'C:\\work\\demo')
})

test('destination text without a chosen folder says not chosen, never ~/Projects', () => {
  for (const root of ['', null, undefined]) {
    const text = ui.projectDestinationText(root, 'demo')
    assert.equal(text, ui.DESTINATION_NOT_CHOSEN_TEXT)
    assert.doesNotMatch(text, /~\/Projects/)
  }
})

test('no ~/Projects fallbacks remain in plugin source; placeholder is neutral', () => {
  assert.doesNotMatch(src, /~\/Projects/)
  assert.match(src, /current\.selected \|\| 'No project selected'/)
})

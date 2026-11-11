// Run from worktree root: node --import ./desktop/tests/sdk-shim.mjs --test desktop/tests/
import test from 'node:test'
import assert from 'node:assert/strict'
import { createToolsLockClient, ToolsLockSection } from '../plugin.js'

function collectNodes(node, pred, acc = []) {
  if (!node || typeof node !== 'object') return acc
  if (pred(node)) acc.push(node)
  const children = node.props?.children
  if (Array.isArray(children)) {
    for (const c of children) collectNodes(c, pred, acc)
  } else if (children) {
    collectNodes(children, pred, acc)
  }
  return acc
}

test('createToolsLockClient calls scoped ctx.rest for getLock, accept, reason, snooze, and init', async () => {
  const calls = []
  globalThis.__adoptTestFetchJSON = async (url, opts) => {
    calls.push({ url, opts })
    return { ok: true, url }
  }

  try {
    const client = createToolsLockClient({ rest: globalThis.__adoptTestFetchJSON })
    await client.getLock('/tmp/my proj')
    await client.acceptInstalled('/tmp/my proj', 'cua-driver', 'Verified 0.38.0 on the bench')
    await client.setReason('/tmp/my proj', 'cua-driver', 'Refined reason')
    await client.snooze('/tmp/my proj', 'cua-driver', 30)
    await client.initLock('/tmp/my proj')

    assert.equal(calls.length, 5)
    assert.equal(calls[0].url, '/tools-lock?project=%2Ftmp%2Fmy%20proj')
    assert.equal(calls[1].url, '/tools-lock/accept')
    assert.deepEqual(calls[1].opts.body, {
      project: '/tmp/my proj',
      tool: 'cua-driver',
      reason: 'Verified 0.38.0 on the bench'
    })
    assert.equal(calls[2].url, '/tools-lock/reason')
    assert.deepEqual(calls[2].opts.body, {
      project: '/tmp/my proj',
      tool: 'cua-driver',
      reason: 'Refined reason'
    })
    assert.equal(calls[3].url, '/tools-lock/snooze')
    assert.deepEqual(calls[3].opts.body, {
      project: '/tmp/my proj',
      tool: 'cua-driver',
      days: 30
    })
    assert.equal(calls[4].url, '/tools-lock/init')
    assert.deepEqual(calls[4].opts.body, {
      project: '/tmp/my proj',
      confirm: true
    })

    // Empty reason is rejected client-side before hitting network
    await assert.rejects(() => client.acceptInstalled('/tmp/my proj', 'cua-driver', '   '), /reason/i)
    await assert.rejects(() => client.setReason('/tmp/my proj', 'cua-driver', ''), /reason/i)
  } finally {
    delete globalThis.__adoptTestFetchJSON
  }
})

test('ToolsLockSection renders nudge highlight, upstream hint, and disables Confirm Accept until non-empty', () => {
  const tree = ToolsLockSection({
    project: '/tmp/proj',
    toolsLock: {
      lock: '/tmp/proj/TOOLS.lock',
      enforce: 'warn',
      summary: 'preflight ok',
      rows: [
        {
          tool: 'cua-driver',
          chosen: '0.21.0',
          installed: '0.21.0',
          upstream_latest: '0.38.0',
          chosen_on: '2025-05-01',
          age_months: 18,
          nudge: true,
          by: 'auto',
          reason: 'Auto seeded',
          status: 'ok',
          snoozed_until: null
        },
        {
          tool: 'xdotool',
          chosen: '3.20160805.1',
          installed: '3.20160805.1',
          upstream_latest: null,
          chosen_on: '2026-11-06',
          age_months: 0,
          nudge: false,
          by: 'human',
          reason: 'X11 proven',
          status: 'ok',
          snoozed_until: null
        }
      ]
    },
    promptState: { tool: 'cua-driver', mode: 'accept', text: '   ' },
    busy: false
  })

  const trs = collectNodes(tree, n => n.type === 'tr' && n.props?.['data-tool'])
  assert.equal(trs.length, 2)
  assert.equal(trs[0].props['data-tool'], 'cua-driver')
  assert.equal(trs[0].props['data-nudge'], 'true')
  assert.match(trs[0].props.style.background, /var\(--ui-/)
  assert.equal(trs[1].props['data-nudge'], 'false')
  assert.equal(trs[1].props.style.background, 'transparent')

  const tds = collectNodes(trs[0], n => n.type === 'td')
  assert.equal(tds[3].props.children, 'upstream 0.38.0')

  const confirmBtns = collectNodes(trs[0], n => n.type === 'Button' && n.props?.children === 'Confirm Accept')
  assert.equal(confirmBtns.length, 1)
  assert.equal(confirmBtns[0].props.disabled, true)

  // Non-empty reason enables Confirm Accept
  const treeEnabled = ToolsLockSection({
    project: '/tmp/proj',
    toolsLock: {
      lock: '/tmp/proj/TOOLS.lock',
      enforce: 'warn',
      summary: 'preflight ok',
      rows: [
        {
          tool: 'cua-driver',
          chosen: '0.21.0',
          installed: '0.38.0',
          upstream_latest: '0.38.0',
          chosen_on: '2025-05-01',
          age_months: 18,
          nudge: true,
          by: 'auto',
          reason: 'Auto seeded',
          status: 'drift',
          snoozed_until: null
        }
      ]
    },
    promptState: { tool: 'cua-driver', mode: 'accept', text: 'Deliberate upgrade' },
    busy: false
  })
  const confirmEnabled = collectNodes(treeEnabled, n => n.type === 'Button' && n.props?.children === 'Confirm Accept')
  assert.equal(confirmEnabled.length, 1)
  assert.equal(confirmEnabled[0].props.disabled, false)
})

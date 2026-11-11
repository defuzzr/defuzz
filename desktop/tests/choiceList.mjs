// Shared fixtures for tests that drive the New Project dialog's pick-list.
// The list mirrors the `catalog` key of /scaffold/match (catalog_list.to_json).
import { V10_TEMPLATES } from '../plugin.js'

const KIT_IDS = [
  ['studio-3d', '3D studio', 'Render Blender or Houdini scenes on a rented GPU.'],
  ['game-assets', 'Game workspace', 'One folder per source asset, with Git LFS rules.'],
  ['video-production', 'Video production', 'Folders for a video, from script to final cut.']
]

export const CATALOG_ENTRIES = [
  ...V10_TEMPLATES.map(t => ({ kind: 'template', id: t.id, title: t.label, line: `A ${t.label} project.`, group: 'code', group_title: 'Code projects', flag: `--template ${t.id}` })),
  ...KIT_IDS.map(([id, title, line]) => ({ kind: 'kit', id, title, line, group: 'workspace', group_title: 'Workspaces for files', flag: `--kit ${id}` }))
]

export const catalog = (overrides = {}) => ({ entries: CATALOG_ENTRIES, suggested: [], notice: '', ...overrides })

const walk = (node, predicate) =>
  !node || typeof node !== 'object'
    ? []
    : [...(predicate(node) ? [node] : []), ...[node.props?.children].flat().flatMap(child => walk(child, predicate))]

export const choiceRadios = tree => walk(tree, n => n.type === 'input' && n.props?.type === 'radio')
export const choiceRadio = (tree, key) => choiceRadios(tree).find(r => r.props.value === key)
export const checkedChoice = tree => choiceRadios(tree).find(r => r.props.checked)?.props.value || ''
// Choose one row the way a click or an arrow key does.
export const chooseRow = (tree, key) => {
  const radio = choiceRadio(tree, key)
  if (!radio) throw new Error(`no row ${key} in the pick-list`)
  return radio.props.onChange({ target: { value: key, checked: true } })
}

// The project name starts empty; type one the way a person does.
export const typeProjectName = (tree, name) => {
  const input = walk(tree, n => n.props?.id === 'new-project-name')[0]
  if (!input) throw new Error('no project name field')
  return input.props.onChange({ target: { value: name } })
}

// For the small hand-rolled render harnesses: run each effect once, so the page's
// model is mounted the way the desktop app mounts it (the list loads on open).
export const runEffectsOnce = t => {
  const ran = new Set()
  globalThis.__adoptTestUseEffect = fn => {
    const key = String(fn)
    if (!ran.has(key)) { ran.add(key); fn() }
  }
  t.after(() => delete globalThis.__adoptTestUseEffect)
}

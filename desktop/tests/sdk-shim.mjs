import { registerHooks } from 'node:module'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const STUBS = {
  'react':
    'export function useState(init) {\n' +
    '  if (globalThis.__adoptTestUseState) return globalThis.__adoptTestUseState(init)\n' +
    '  const val = typeof init === "function" ? init() : init\n' +
    '  const setter = (next) => { if (typeof globalThis.__adoptTestStateHook === "function") globalThis.__adoptTestStateHook(next) }\n' +
    '  return [val, setter]\n' +
    '}\n' +
    'export function useEffect(fn, deps) { globalThis.__adoptTestUseEffect?.(fn, deps) }\n' +
    'export function useCallback(fn) { return fn }\n' +
    'export function useRef(init) { return useState(() => ({ current: init }))[0] }\n',
  'react/jsx-runtime':
    'export function jsx(type, props, key) { return { type, props, key } }\nexport const jsxs = jsx\n',
  '@hermes/plugin-sdk': [
    'export const host = { navigate() {}, getGateway() { return null }, async openSession() {} }',
    'export const Button = "Button"',
    'export const Badge = "Badge"',
    'export const ScrollArea = "ScrollArea"',
    'export const Separator = "Separator"',
    'export const EmptyState = "EmptyState"',
    'export const Codicon = "Codicon"',
    'export const ROUTES_AREA = "routes"',
    'export const SIDEBAR_NAV_AREA = "sidebar"',
    'export const PALETTE_AREA = "palette"'
  ].join('\n')
}

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (Object.prototype.hasOwnProperty.call(STUBS, specifier)) {
      return {
        url: 'data:text/javascript;charset=utf-8,' + encodeURIComponent(STUBS[specifier]),
        shortCircuit: true
      }
    }
    return nextResolve(specifier, context)
  },
  load(url, context, nextLoad) {
    if (url.endsWith('/desktop/plugin.js')) {
      return {
        format: 'module',
        source: readFileSync(fileURLToPath(url), 'utf8'),
        shortCircuit: true
      }
    }
    return nextLoad(url, context)
  }
})

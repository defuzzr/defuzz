import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export const PREFIX = "tmpl_prefix";

export const LayerOrder = {
  foundation: 0,
  domain: 1,
  adapters: 2,
  apps: 3,
} as const;

export type LayerName = keyof typeof LayerOrder;

export const LayerNames: readonly LayerName[] = ["foundation", "domain", "adapters", "apps"];

export interface PrefixForms {
  readonly snake: string;
  readonly kebab: string;
  readonly screaming: string;
  readonly pascal: string;
}

export interface PackageManifest {
  readonly name?: string;
  readonly version?: string;
  readonly description?: string;
  readonly type?: string;
  readonly exports?: Readonly<Record<string, unknown>>;
  readonly bin?: Readonly<Record<string, string>>;
  readonly files?: readonly string[];
  readonly sideEffects?: boolean;
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly devDependencies?: Readonly<Record<string, string>>;
  readonly peerDependencies?: Readonly<Record<string, string>>;
  readonly optionalDependencies?: Readonly<Record<string, string>>;
}

export interface TsconfigRef {
  readonly path: string;
}

export interface PackageTsconfig {
  readonly extends?: string;
  readonly compilerOptions?: Readonly<Record<string, unknown>>;
  readonly include?: readonly string[];
  readonly references?: readonly TsconfigRef[];
}

export interface WorkspacePackage {
  readonly name: string;
  readonly layer: LayerName;
  readonly dirPath: string;
  readonly relDir: string;
  readonly manifest: PackageManifest;
  readonly tsconfig: PackageTsconfig;
}

const SNAKE_PREFIX_PATTERN = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;
const KEBAB_NAME_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

export function workspaceRoot(): string {
  const currentFile = fileURLToPath(import.meta.url);
  return path.resolve(path.dirname(currentFile), "../..");
}

export function derivePrefixForms(snakePrefix: string): PrefixForms {
  if (!SNAKE_PREFIX_PATTERN.test(snakePrefix)) {
    throw new Error(
      `Invalid prefix "${snakePrefix}". Expected snake_case matching [a-z][a-z0-9]*(_[a-z0-9]+)*`,
    );
  }
  const parts = snakePrefix.split("_").filter((p) => p.length > 0);
  const kebab = parts.join("-");
  const screaming = snakePrefix.toUpperCase();
  const pascal = parts.map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`).join("");
  return {
    snake: snakePrefix,
    kebab,
    screaming,
    pascal,
  };
}

export function toPascalCase(kebabOrSnake: string): string {
  return kebabOrSnake
    .split(/[-_]+/)
    .filter((p) => p.length > 0)
    .map((p) => `${p.charAt(0).toUpperCase()}${p.slice(1)}`)
    .join("");
}

export function stripJsonComments(raw: string): string {
  let out = "";
  let inString = false;
  let escaped = false;
  let i = 0;

  while (i < raw.length) {
    const ch = raw[i] ?? "";
    const next = raw[i + 1] ?? "";

    if (inString) {
      out += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      i += 1;
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      i += 1;
      continue;
    }

    if (ch === "/" && next === "/") {
      i += 2;
      while (i < raw.length && raw[i] !== "\n") {
        i += 1;
      }
      continue;
    }

    if (ch === "/" && next === "*") {
      i += 2;
      while (i < raw.length && !(raw[i] === "*" && raw[i + 1] === "/")) {
        i += 1;
      }
      i += 2;
      continue;
    }

    out += ch;
    i += 1;
  }

  return out.replace(/,(\s*[}\]])/g, "$1");
}

export function parseJsonc<T>(filePath: string): T {
  const raw = readFileSync(filePath, "utf8");
  const stripped = stripJsonComments(raw);
  return JSON.parse(stripped) as T;
}

export function insertRootTsconfigReference(rootDir: string, refPath: string): void {
  const tsconfigPath = path.join(rootDir, "tsconfig.json");
  const raw = readFileSync(tsconfigPath, "utf8");
  const parsed = parseJsonc<{ references?: TsconfigRef[] }>(tsconfigPath);
  const existing = parsed.references ?? [];
  if (existing.some((r) => r.path === refPath)) {
    return;
  }

  const marker = "// @xtask:references";
  const markerIdx = raw.indexOf(marker);
  if (markerIdx === -1) {
    throw new Error(`Missing "${marker}" marker in ${tsconfigPath}`);
  }

  const beforeMarker = raw.slice(0, markerIdx);
  const afterMarker = raw.slice(markerIdx);

  const lineStart = beforeMarker.lastIndexOf("\n") + 1;
  const indent = beforeMarker.slice(lineStart);
  const prefixTrimmed = beforeMarker.slice(0, lineStart).trimEnd();
  const needsComma = prefixTrimmed.endsWith("}");
  const patchedPrefix = needsComma ? `${prefixTrimmed},\n` : `${beforeMarker.slice(0, lineStart)}`;

  const newEntry = `${indent}{ "path": "${refPath}" }\n${indent}`;
  const updated = `${patchedPrefix}${newEntry}${afterMarker}`;
  writeFileSync(tsconfigPath, updated, "utf8");
}

export function loadWorkspacePackages(rootDir: string): WorkspacePackage[] {
  const packagesRoot = path.join(rootDir, "packages");
  if (!existsSync(packagesRoot)) {
    return [];
  }

  const results: WorkspacePackage[] = [];
  for (const layer of LayerNames) {
    const layerDir = path.join(packagesRoot, layer);
    if (!existsSync(layerDir)) {
      continue;
    }
    const entries = readdirSync(layerDir, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const pkgDir = path.join(layerDir, entry.name);
      const manifestPath = path.join(pkgDir, "package.json");
      const tsconfigPath = path.join(pkgDir, "tsconfig.json");
      if (!existsSync(manifestPath)) {
        continue;
      }
      const manifest = parseJsonc<PackageManifest>(manifestPath);
      const tsconfig: PackageTsconfig = existsSync(tsconfigPath)
        ? parseJsonc<PackageTsconfig>(tsconfigPath)
        : {};
      results.push({
        name: manifest.name ?? entry.name,
        layer,
        dirPath: pkgDir,
        relDir: path.posix.join("packages", layer, entry.name),
        manifest,
        tsconfig,
      });
    }
  }
  return results;
}

function collectTsFiles(dirPath: string): string[] {
  if (!existsSync(dirPath)) {
    return [];
  }
  const files: string[] = [];
  const entries = readdirSync(dirPath, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  for (const entry of entries) {
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectTsFiles(full));
    } else if (entry.isFile() && entry.name.endsWith(".ts")) {
      files.push(full);
    }
  }
  return files;
}

function stripTsComments(source: string): string {
  let out = "";
  let inSingle = false;
  let inDouble = false;
  let inTemplate = false;
  let escaped = false;
  let i = 0;

  while (i < source.length) {
    const ch = source[i] ?? "";
    const next = source[i + 1] ?? "";

    if (inSingle || inDouble || inTemplate) {
      out += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (inSingle && ch === "'") {
        inSingle = false;
      } else if (inDouble && ch === '"') {
        inDouble = false;
      } else if (inTemplate && ch === "`") {
        inTemplate = false;
      }
      i += 1;
      continue;
    }

    if (ch === "'") {
      inSingle = true;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === "`") {
      inTemplate = true;
      out += ch;
      i += 1;
      continue;
    }
    if (ch === "/" && next === "/") {
      i += 2;
      while (i < source.length && source[i] !== "\n") {
        i += 1;
      }
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < source.length && !(source[i] === "*" && source[i + 1] === "/")) {
        i += 1;
      }
      i += 2;
      continue;
    }

    out += ch;
    i += 1;
  }

  return out;
}

export function extractModuleSpecifiers(sourceText: string): string[] {
  const cleaned = stripTsComments(sourceText);
  const specifiers: string[] = [];

  const fromPattern = /\b(?:import|export)\s+(?:type\s+)?(?:[^"';]*?\s+from\s+)?["']([^"']+)["']/g;
  for (const match of cleaned.matchAll(fromPattern)) {
    const spec = match[1];
    if (spec !== undefined) {
      specifiers.push(spec);
    }
  }

  const dynamicImportPattern = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
  for (const match of cleaned.matchAll(dynamicImportPattern)) {
    const spec = match[1];
    if (spec !== undefined) {
      specifiers.push(spec);
    }
  }

  return specifiers;
}

export function packageNameFromBareSpecifier(specifier: string): string {
  if (specifier.startsWith("@")) {
    const parts = specifier.split("/");
    return parts.slice(0, 2).join("/");
  }
  const [first] = specifier.split("/");
  return first ?? specifier;
}

function canImportLayer(fromLayer: LayerName, toLayer: LayerName): boolean {
  if (fromLayer === "apps" && toLayer === "apps") {
    return false;
  }
  return LayerOrder[toLayer] <= LayerOrder[fromLayer];
}

function detectCycles(edges: ReadonlyMap<string, ReadonlySet<string>>): string[] {
  const state = new Map<string, "visiting" | "visited">();
  const stack: string[] = [];
  const errors: string[] = [];

  const dfs = (node: string): void => {
    state.set(node, "visiting");
    stack.push(node);

    const targets = edges.get(node) ?? new Set<string>();
    for (const target of targets) {
      const targetState = state.get(target);
      if (targetState === "visiting") {
        const idx = stack.indexOf(target);
        const cyclePath = [...stack.slice(idx), target].join(" -> ");
        errors.push(`Dependency cycle detected: ${cyclePath}`);
      } else if (targetState === undefined) {
        dfs(target);
      }
    }

    stack.pop();
    state.set(node, "visited");
  };

  for (const node of edges.keys()) {
    if (!state.has(node)) {
      dfs(node);
    }
  }

  return errors;
}

export function checkWorkspace(rootDir: string, currentPrefixSnake: string = PREFIX): string[] {
  const errors: string[] = [];
  const forms = derivePrefixForms(currentPrefixSnake);
  const packages = loadWorkspacePackages(rootDir);
  const pkgByName = new Map<string, WorkspacePackage>();

  for (const pkg of packages) {
    pkgByName.set(pkg.name, pkg);
  }

  const packagesRoot = path.join(rootDir, "packages");
  if (existsSync(packagesRoot)) {
    for (const entry of readdirSync(packagesRoot, { withFileTypes: true })) {
      if (entry.isDirectory() && !LayerNames.includes(entry.name as LayerName)) {
        errors.push(
          `Unknown layer directory "packages/${entry.name}". Allowed layers: ${LayerNames.join(", ")}`,
        );
      }
    }
  }

  const allInternalEdges = new Map<string, Set<string>>();

  for (const pkg of packages) {
    const dirBasename = path.basename(pkg.dirPath);
    const expectedPrefix = `${forms.kebab}-`;

    if (!pkg.name.startsWith(expectedPrefix)) {
      errors.push(
        `Package "${pkg.name}" in ${pkg.relDir} does not start with required prefix "${expectedPrefix}"`,
      );
    }

    if (dirBasename !== pkg.name) {
      errors.push(
        `Package directory "${pkg.relDir}" basename "${dirBasename}" does not match package name "${pkg.name}"`,
      );
    }

    if (pkg.manifest.type !== "module") {
      errors.push(`Package "${pkg.name}" (${pkg.relDir}/package.json) must set "type": "module"`);
    }

    const exportsDot = pkg.manifest.exports?.["."] as Readonly<Record<string, unknown>> | undefined;
    if (
      exportsDot === undefined ||
      exportsDot["types"] !== "./dist/index.d.ts" ||
      exportsDot["default"] !== "./dist/index.js"
    ) {
      errors.push(
        `Package "${pkg.name}" (${pkg.relDir}/package.json) must declare standard exports["."] with types "./dist/index.d.ts" and default "./dist/index.js"`,
      );
    }

    if (
      pkg.tsconfig.extends === undefined ||
      !pkg.tsconfig.extends.endsWith("tsconfig.base.json")
    ) {
      errors.push(
        `Package "${pkg.name}" (${pkg.relDir}/tsconfig.json) must extend tsconfig.base.json`,
      );
    }

    const prodDeps = {
      ...pkg.manifest.dependencies,
      ...pkg.manifest.peerDependencies,
      ...pkg.manifest.optionalDependencies,
    };
    const devDeps = pkg.manifest.devDependencies ?? {};

    const manifestFields: ReadonlyArray<{
      readonly fieldName: string;
      readonly table: Readonly<Record<string, string>>;
      readonly exemptFromDirection: boolean;
    }> = [
      {
        fieldName: "dependencies",
        table: pkg.manifest.dependencies ?? {},
        exemptFromDirection: false,
      },
      {
        fieldName: "peerDependencies",
        table: pkg.manifest.peerDependencies ?? {},
        exemptFromDirection: false,
      },
      {
        fieldName: "optionalDependencies",
        table: pkg.manifest.optionalDependencies ?? {},
        exemptFromDirection: false,
      },
      {
        fieldName: "devDependencies",
        table: devDeps,
        exemptFromDirection: true,
      },
    ];

    const declaredInternalAll = new Set<string>();
    const edgeSet = new Set<string>();
    allInternalEdges.set(pkg.name, edgeSet);

    for (const { fieldName, table, exemptFromDirection } of manifestFields) {
      for (const [depName, depSpec] of Object.entries(table)) {
        const targetPkg = pkgByName.get(depName);
        const looksInternal = depName.startsWith(expectedPrefix);
        if (targetPkg === undefined) {
          if (looksInternal || depSpec.startsWith("workspace:")) {
            errors.push(
              `Package "${pkg.name}" (${pkg.relDir}/package.json) declares unknown internal dependency "${depName}" in ${fieldName}`,
            );
          }
          continue;
        }

        if (depSpec !== "workspace:*") {
          errors.push(
            `Package "${pkg.name}" (${pkg.relDir}/package.json) must reference internal package "${depName}" with "workspace:*" in ${fieldName} (found "${depSpec}")`,
          );
        }

        declaredInternalAll.add(depName);
        edgeSet.add(depName);

        if (!exemptFromDirection && !canImportLayer(pkg.layer, targetPkg.layer)) {
          errors.push(
            `Layer violation in ${pkg.relDir}/package.json (${fieldName}): package "${pkg.name}" (layer "${pkg.layer}") cannot depend on "${targetPkg.name}" (layer "${targetPkg.layer}")`,
          );
        }
      }
    }

    const expectedRefPaths = new Set<string>();
    for (const internalDep of declaredInternalAll) {
      const targetPkg = pkgByName.get(internalDep);
      if (targetPkg !== undefined) {
        const relRef = path.relative(pkg.dirPath, targetPkg.dirPath).split(path.sep).join("/");
        expectedRefPaths.add(relRef.startsWith(".") ? relRef : `./${relRef}`);
      }
    }

    const actualRefPaths = new Set<string>(
      (pkg.tsconfig.references ?? []).map((r) => {
        const norm = r.path.replace(/\\/g, "/").replace(/\/+$/, "");
        return norm.startsWith(".") ? norm : `./${norm}`;
      }),
    );

    for (const expectedRef of expectedRefPaths) {
      if (!actualRefPaths.has(expectedRef)) {
        errors.push(
          `Package "${pkg.name}" (${pkg.relDir}/tsconfig.json) is missing project reference "${expectedRef}" for declared internal dependency`,
        );
      }
    }
    for (const actualRef of actualRefPaths) {
      if (!expectedRefPaths.has(actualRef)) {
        errors.push(
          `Package "${pkg.name}" (${pkg.relDir}/tsconfig.json) has undeclared project reference "${actualRef}" not matching any internal dependency in package.json`,
        );
      }
    }

    const srcDir = path.join(pkg.dirPath, "src");
    const tsFiles = collectTsFiles(srcDir);
    for (const tsFile of tsFiles) {
      const relFile = path.relative(rootDir, tsFile).split(path.sep).join("/");
      const isTestFile = tsFile.endsWith(".test.ts");
      const content = readFileSync(tsFile, "utf8");
      const specifiers = extractModuleSpecifiers(content);

      for (const spec of specifiers) {
        if (spec.startsWith(".")) {
          const resolvedTarget = path.resolve(path.dirname(tsFile), spec);
          const relToPkg = path.relative(pkg.dirPath, resolvedTarget);
          if (relToPkg.startsWith("..") || path.isAbsolute(relToPkg)) {
            errors.push(
              `Relative import "${spec}" in ${relFile} escapes package root "${pkg.relDir}"`,
            );
          }
          continue;
        }

        if (spec.startsWith("node:")) {
          continue;
        }

        const barePkgName = packageNameFromBareSpecifier(spec);
        const targetPkg = pkgByName.get(barePkgName);
        const isInternalName = targetPkg !== undefined || barePkgName.startsWith(expectedPrefix);

        const inProd = Object.hasOwn(prodDeps, barePkgName);
        const inDev = Object.hasOwn(devDeps, barePkgName);

        if (isInternalName) {
          if (targetPkg === undefined) {
            errors.push(
              `Import of unknown internal package "${barePkgName}" in ${relFile} (${pkg.name})`,
            );
            continue;
          }

          if (!inProd && !inDev) {
            errors.push(
              `Undeclared internal import "${barePkgName}" in ${relFile}: not listed in ${pkg.relDir}/package.json`,
            );
          } else if (!inProd && inDev && !isTestFile) {
            errors.push(
              `Production source file ${relFile} (${pkg.name}) imports "${barePkgName}", which is only declared in devDependencies`,
            );
          }

          if (!isTestFile && !canImportLayer(pkg.layer, targetPkg.layer)) {
            errors.push(
              `Layer violation in ${relFile}: package "${pkg.name}" (layer "${pkg.layer}") cannot import "${targetPkg.name}" (layer "${targetPkg.layer}")`,
            );
          }
        } else {
          if (!inProd && !inDev) {
            errors.push(
              `Undeclared dependency import "${barePkgName}" in ${relFile}: not listed in ${pkg.relDir}/package.json`,
            );
          } else if (!inProd && inDev && !isTestFile) {
            errors.push(
              `Production source file ${relFile} (${pkg.name}) imports "${barePkgName}", which is only declared in devDependencies`,
            );
          }
        }
      }
    }
  }

  errors.push(...detectCycles(allInternalEdges));

  return errors;
}

export function formatWorkspaceGraph(rootDir: string): string {
  const packages = loadWorkspacePackages(rootDir);
  const pkgNames = new Set(packages.map((p) => p.name));
  const lines: string[] = [];

  for (const layer of LayerNames) {
    const layerPkgs = packages.filter((p) => p.layer === layer);
    lines.push(`[${layer}] (layer ${LayerOrder[layer]})`);
    if (layerPkgs.length === 0) {
      lines.push("  (none)");
      continue;
    }
    for (const pkg of layerPkgs) {
      const prodInternal = Object.keys({
        ...pkg.manifest.dependencies,
        ...pkg.manifest.peerDependencies,
        ...pkg.manifest.optionalDependencies,
      }).filter((d) => pkgNames.has(d));

      const devInternal = Object.keys(pkg.manifest.devDependencies ?? {}).filter((d) =>
        pkgNames.has(d),
      );

      const depParts: string[] = [];
      if (prodInternal.length > 0) {
        depParts.push(prodInternal.join(", "));
      }
      if (devInternal.length > 0) {
        depParts.push(`dev: ${devInternal.join(", ")}`);
      }
      const suffix = depParts.length > 0 ? ` -> ${depParts.join(" | ")}` : " -> (root)";
      lines.push(`  - ${pkg.name}${suffix}`);
    }
  }

  return lines.join("\n");
}

function renderTemplateFile(
  templatePath: string,
  replacements: Readonly<Record<string, string>>,
): string {
  let content = readFileSync(templatePath, "utf8");
  for (const [placeholder, value] of Object.entries(replacements)) {
    content = content.split(placeholder).join(value);
  }
  return content;
}

function runCommand(
  cmd: string,
  args: readonly string[],
  cwd: string,
): { readonly status: number } {
  process.stdout.write(`+ ${cmd} ${args.join(" ")}\n`);
  const res = spawnSync(cmd, [...args], {
    cwd,
    stdio: "inherit",
    env: process.env,
  });
  if (res.error !== undefined) {
    throw res.error;
  }
  return { status: res.status ?? 1 };
}

export function cmdNewPackage(rootDir: string, rawArgs: readonly string[]): void {
  const { values, positionals } = parseArgs({
    args: [...rawArgs],
    options: {
      app: { type: "boolean", default: false },
      description: { type: "string" },
    },
    strict: true,
    allowPositionals: true,
  });

  const layerArg = positionals[0];
  const nameArg = positionals[1];
  if (layerArg === undefined || nameArg === undefined) {
    throw new Error("Usage: pnpm xtask new-package <layer> <name> [--app] [--description <text>]");
  }
  if (!LayerNames.includes(layerArg as LayerName)) {
    throw new Error(`Invalid layer "${layerArg}". Expected one of: ${LayerNames.join(", ")}`);
  }
  if (!KEBAB_NAME_PATTERN.test(nameArg)) {
    throw new Error(`Invalid package short name "${nameArg}". Expected kebab-case.`);
  }

  const layer = layerArg as LayerName;
  const isApp = (values.app ?? false) || layer === "apps";
  const forms = derivePrefixForms(PREFIX);
  const fullPkgName = `${forms.kebab}-${nameArg}`;
  const description = values.description ?? `${toPascalCase(nameArg)} (${layer} package).`;
  const pascalName = toPascalCase(nameArg);

  const targetDir = path.join(rootDir, "packages", layer, fullPkgName);
  if (existsSync(targetDir)) {
    throw new Error(`Package directory already exists: ${targetDir}`);
  }

  const templateDir = path.join(rootDir, "templates", isApp ? "package-app" : "package-lib");
  mkdirSync(path.join(targetDir, "src"), { recursive: true });

  const replacements: Record<string, string> = {
    __PACKAGE_NAME__: fullPkgName,
    __DESCRIPTION__: description,
    __PASCAL_NAME__: pascalName,
  };

  writeFileSync(
    path.join(targetDir, "package.json"),
    renderTemplateFile(path.join(templateDir, "package.json.tmpl"), replacements),
    "utf8",
  );
  writeFileSync(
    path.join(targetDir, "tsconfig.json"),
    renderTemplateFile(path.join(templateDir, "tsconfig.json.tmpl"), replacements),
    "utf8",
  );
  writeFileSync(
    path.join(targetDir, "src", "index.ts"),
    renderTemplateFile(path.join(templateDir, "src", "index.ts.tmpl"), replacements),
    "utf8",
  );
  writeFileSync(
    path.join(targetDir, "src", "index.test.ts"),
    renderTemplateFile(path.join(templateDir, "src", "index.test.ts.tmpl"), replacements),
    "utf8",
  );
  if (isApp) {
    writeFileSync(
      path.join(targetDir, "src", "main.ts"),
      renderTemplateFile(path.join(templateDir, "src", "main.ts.tmpl"), replacements),
      "utf8",
    );
  }

  const relRef = `./packages/${layer}/${fullPkgName}`;
  insertRootTsconfigReference(rootDir, relRef);

  const installRes = runCommand("pnpm", ["install"], rootDir);
  if (installRes.status !== 0) {
    throw new Error("pnpm install failed after scaffolding new package");
  }
}

function ensureInternalDependency(pkg: WorkspacePackage, targetPkg: WorkspacePackage): void {
  const manifestPath = path.join(pkg.dirPath, "package.json");
  const rawManifest = parseJsonc<Record<string, unknown>>(manifestPath);
  const deps = {
    ...(rawManifest["dependencies"] as Record<string, string> | undefined),
  };

  if (deps[targetPkg.name] !== "workspace:*") {
    deps[targetPkg.name] = "workspace:*";
    const sortedDeps: Record<string, string> = {};
    for (const key of Object.keys(deps).sort((a, b) => a.localeCompare(b))) {
      const val = deps[key];
      if (val !== undefined) {
        sortedDeps[key] = val;
      }
    }
    rawManifest["dependencies"] = sortedDeps;
    writeFileSync(manifestPath, `${JSON.stringify(rawManifest, null, 2)}\n`, "utf8");
  }

  const tsconfigPath = path.join(pkg.dirPath, "tsconfig.json");
  const rawTsconfig = parseJsonc<Record<string, unknown>>(tsconfigPath);
  const refs = [...((rawTsconfig["references"] as Array<{ path: string }> | undefined) ?? [])];
  const relPath = path.relative(pkg.dirPath, targetPkg.dirPath).split(path.sep).join("/");
  const formattedRel = relPath.startsWith(".") ? relPath : `./${relPath}`;
  if (!refs.some((r) => r.path === formattedRel)) {
    refs.push({ path: formattedRel });
    rawTsconfig["references"] = refs;
    writeFileSync(tsconfigPath, `${JSON.stringify(rawTsconfig, null, 2)}\n`, "utf8");
  }
}

export function cmdNewComponent(rootDir: string, rawArgs: readonly string[]): void {
  const { values, positionals } = parseArgs({
    args: [...rawArgs],
    options: {
      wire: { type: "string" },
    },
    strict: true,
    allowPositionals: true,
  });

  const pkgArg = positionals[0];
  const compName = positionals[1];
  if (pkgArg === undefined || compName === undefined) {
    throw new Error("Usage: pnpm xtask new-component <package> <name> [--wire <app>]");
  }
  if (!KEBAB_NAME_PATTERN.test(compName)) {
    throw new Error(`Invalid component name "${compName}". Expected kebab-case.`);
  }

  const forms = derivePrefixForms(PREFIX);
  const packages = loadWorkspacePackages(rootDir);
  const findPackage = (query: string): WorkspacePackage | undefined =>
    packages.find((p) => p.name === query || p.name === `${forms.kebab}-${query}`);

  const targetPkg = findPackage(pkgArg);
  if (targetPkg === undefined) {
    throw new Error(`Workspace package "${pkgArg}" not found`);
  }

  const corePkgName = `${forms.kebab}-core`;
  const corePkg = packages.find((p) => p.name === corePkgName);
  if (corePkg === undefined) {
    throw new Error(`Core foundation package "${corePkgName}" not found`);
  }

  const componentClass = `${toPascalCase(compName)}Component`;
  const compFile = path.join(targetPkg.dirPath, "src", `${compName}.ts`);
  const compTestFile = path.join(targetPkg.dirPath, "src", `${compName}.test.ts`);
  if (existsSync(compFile)) {
    throw new Error(`Component file already exists: ${compFile}`);
  }

  const replacements: Record<string, string> = {
    __COMPONENT_CLASS__: componentClass,
    __COMPONENT_NAME__: compName,
    __PACKAGE_NAME__: targetPkg.name,
  };

  writeFileSync(
    compFile,
    renderTemplateFile(path.join(rootDir, "templates", "component.ts.tmpl"), replacements),
    "utf8",
  );
  writeFileSync(
    compTestFile,
    renderTemplateFile(path.join(rootDir, "templates", "component.test.ts.tmpl"), replacements),
    "utf8",
  );

  const indexPath = path.join(targetPkg.dirPath, "src", "index.ts");
  const indexContent = existsSync(indexPath) ? readFileSync(indexPath, "utf8") : "";
  const exportLine = `export { ${componentClass} } from "./${compName}.js";\n`;
  if (!indexContent.includes(exportLine)) {
    writeFileSync(indexPath, `${indexContent.trimEnd()}\n${exportLine}`, "utf8");
  }

  if (targetPkg.name !== corePkg.name) {
    ensureInternalDependency(targetPkg, corePkg);
  }

  if (values.wire !== undefined) {
    const appPkg = findPackage(values.wire);
    if (appPkg === undefined) {
      throw new Error(`App package "${values.wire}" not found for --wire`);
    }
    if (appPkg.name !== targetPkg.name) {
      ensureInternalDependency(appPkg, targetPkg);
    }

    const wiringPath = path.join(appPkg.dirPath, "src", "wiring.ts");
    if (!existsSync(wiringPath)) {
      throw new Error(`Wiring file not found in app package: ${wiringPath}`);
    }
    let wiringContent = readFileSync(wiringPath, "utf8");
    const importStatement = `import { ${componentClass} } from "${targetPkg.name}";\n`;
    if (!wiringContent.includes(importStatement)) {
      wiringContent = `${importStatement}${wiringContent}`;
    }

    const marker = "// @xtask:register-components";
    const markerIdx = wiringContent.indexOf(marker);
    if (markerIdx === -1) {
      throw new Error(`Missing "${marker}" marker in ${wiringPath}`);
    }
    const before = wiringContent.slice(0, markerIdx);
    const after = wiringContent.slice(markerIdx);
    const lineStart = before.lastIndexOf("\n") + 1;
    const indent = before.slice(lineStart);
    const registrationLine = `registry.register(new ${componentClass}());\n${indent}`;
    wiringContent = `${before}${registrationLine}${after}`;
    writeFileSync(wiringPath, wiringContent, "utf8");
  }

  const installRes = runCommand("pnpm", ["install"], rootDir);
  if (installRes.status !== 0) {
    throw new Error("pnpm install failed after scaffolding new component");
  }

  const fmtRes = runCommand("./node_modules/.bin/biome", ["check", "--write", "."], rootDir);
  if (fmtRes.status !== 0) {
    throw new Error("biome check --write failed after scaffolding new component");
  }
}

function replaceFormsLongestFirst(text: string, src: PrefixForms, dst: PrefixForms): string {
  const pairs: ReadonlyArray<readonly [string, string]> = [
    [src.snake, dst.snake],
    [src.kebab, dst.kebab],
    [src.screaming, dst.screaming],
    [src.pascal, dst.pascal],
  ];
  const mapping = new Map<string, string>();
  for (const [sKey, dVal] of pairs) {
    if (sKey.length > 0 && !mapping.has(sKey)) {
      mapping.set(sKey, dVal);
    }
  }
  const orderedKeys = [...mapping.keys()].sort((a, b) => b.length - a.length);
  const escaped = orderedKeys.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = new RegExp(escaped.join("|"), "g");
  return text.replace(pattern, (matched) => mapping.get(matched) ?? matched);
}

function replacePrefixInFile(filePath: string, src: PrefixForms, dst: PrefixForms): void {
  const rel = path.basename(filePath);
  const raw = readFileSync(filePath, "utf8");

  if (src.kebab !== src.snake) {
    const updated = replaceFormsLongestFirst(raw, src, dst);
    if (updated !== raw) {
      writeFileSync(filePath, updated, "utf8");
    }
    return;
  }

  // Context-aware pass when recovering from a single-word prefix where kebab === snake:
  const singleWord = src.snake;
  const escapedWord = singleWord.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const escapedScreaming = src.screaming.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const escapedPascal = src.pascal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  let text = raw;
  // 1. SCREAMING_SNAKE followed by underscore or word boundary
  text = text.replace(new RegExp(`${escapedScreaming}(?=_|\\b)`, "g"), dst.screaming);
  // 2. PascalCase
  text = text.replace(new RegExp(escapedPascal, "g"), dst.pascal);
  // 3. Explicit snake_case contexts:
  text = text.replace(new RegExp(`\\b${escapedWord}_`, "g"), `${dst.snake}_`);
  text = text.replace(new RegExp(`(rename\\s+\`?)${escapedWord}`, "g"), `$1${dst.snake}`);
  text = text.replace(new RegExp(`(placeholder\\s*\`?)${escapedWord}`, "g"), `$1${dst.snake}`);
  text = text.replace(
    new RegExp(`(PREFIX\\s*=\\s*["'])${escapedWord}(["'])`, "g"),
    `$1${dst.snake}$2`,
  );
  text = text.replace(new RegExp(`(\`)${escapedWord}(\`\\s+identifiers)`, "g"), `$1${dst.snake}$2`);
  text = text.replace(
    new RegExp(`(identifiers(?:\\s+use\\s+snake)?\\s*(?:->|:)?\\s*\`)${escapedWord}(\`)`, "g"),
    `$1${dst.snake}$2`,
  );
  text = text.replace(
    new RegExp(`(from\\s+\`)${escapedWord}(\`\\s+to\\s+your\\s+service\\s+name)`, "g"),
    `$1${dst.snake}$2`,
  );
  text = text.replace(
    new RegExp(`(\`)${escapedWord}(\`,\\s*\`${escapedWord})`, "g"),
    `$1${dst.snake}$2`,
  );
  // 4. Explicit kebab-case contexts: `<word>-` or remaining bare occurrences in source/config/docs
  text = text.replace(new RegExp(`\\b${escapedWord}-`, "g"), `${dst.kebab}-`);
  text = text.replace(new RegExp(`(Usage:\\s+)${escapedWord}\\b`, "g"), `$1${dst.kebab}`);
  if (rel === "package.json" || rel === "pnpm-lock.yaml" || filePath.endsWith(".md")) {
    text = text.replace(new RegExp(`\\b${escapedWord}\\b`, "g"), dst.kebab);
  }

  if (text !== raw) {
    writeFileSync(filePath, text, "utf8");
  }
}

function collectRenameTargetFiles(rootDir: string): string[] {
  const ignoredDirs = new Set([".git", "node_modules", "dist"]);
  const files: string[] = [];

  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (ignoredDirs.has(entry.name)) {
        continue;
      }
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && !entry.name.endsWith(".tsbuildinfo")) {
        files.push(full);
      }
    }
  };

  walk(rootDir);
  return files;
}

export function cmdRename(rootDir: string, rawArgs: readonly string[]): void {
  const newPrefixSnake = rawArgs[0];
  if (newPrefixSnake === undefined || rawArgs.length !== 1) {
    throw new Error("Usage: pnpm xtask rename <new_prefix>");
  }

  const srcForms = derivePrefixForms(PREFIX);
  const dstForms = derivePrefixForms(newPrefixSnake);
  if (srcForms.snake === dstForms.snake) {
    return;
  }

  // 1. Rename package directories under packages/<layer>/<kebab>-*
  for (const layer of LayerNames) {
    const layerDir = path.join(rootDir, "packages", layer);
    if (!existsSync(layerDir)) {
      continue;
    }
    for (const entry of readdirSync(layerDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue;
      }
      if (entry.name.startsWith(`${srcForms.kebab}-`)) {
        const suffix = entry.name.slice(srcForms.kebab.length + 1);
        const newDirName = `${dstForms.kebab}-${suffix}`;
        const oldFull = path.join(layerDir, entry.name);
        const newFull = path.join(layerDir, newDirName);
        const distDir = path.join(oldFull, "dist");
        if (existsSync(distDir) && statSync(distDir).isDirectory()) {
          // Clean stale build outputs before moving directory
          rmSync(distDir, { recursive: true, force: true });
        }
        const tsBuildInfo = path.join(oldFull, "tsconfig.tsbuildinfo");
        if (existsSync(tsBuildInfo)) {
          rmSync(tsBuildInfo, { force: true });
        }
        renameSync(oldFull, newFull);
      }
    }
  }

  // 2. Replace across all tracked files
  const targetFiles = collectRenameTargetFiles(rootDir);
  for (const filePath of targetFiles) {
    replacePrefixInFile(filePath, srcForms, dstForms);
  }

  // 3. Refresh lockfile importer paths and workspace links
  const installRes = runCommand("pnpm", ["install"], rootDir);
  if (installRes.status !== 0) {
    throw new Error("pnpm install failed after rename");
  }

  // 4. Renaming changes import ordering as well as line widths.
  const fmtRes = runCommand(
    "./node_modules/.bin/biome",
    ["check", "--write", "--linter-enabled=false", "."],
    rootDir,
  );
  if (fmtRes.status !== 0) {
    throw new Error("biome formatting/import normalization failed after rename");
  }
}

export function cmdCi(rootDir: string): void {
  const testFiles: string[] = [];
  for (const pkg of loadWorkspacePackages(rootDir)) {
    const distDir = path.join(pkg.dirPath, "dist");
    const collectDistTests = (dir: string): void => {
      if (!existsSync(dir)) {
        return;
      }
      for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
        a.name.localeCompare(b.name),
      )) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          collectDistTests(full);
        } else if (entry.isFile() && entry.name.endsWith(".test.js")) {
          testFiles.push(path.relative(rootDir, full).split(path.sep).join("/"));
        }
      }
    };
    collectDistTests(distDir);
  }

  const forms = derivePrefixForms(PREFIX);
  const serverMain = `packages/apps/${forms.kebab}-server/dist/main.js`;

  interface CiStep {
    readonly label: string;
    readonly run: () => void;
  }

  const results: Array<{ readonly label: string; readonly status: "PASS" | "FAIL" }> = [];

  const steps: readonly CiStep[] = [
    {
      label: "pnpm install --frozen-lockfile",
      run: () => {
        const res = runCommand("pnpm", ["install", "--frozen-lockfile"], rootDir);
        if (res.status !== 0) {
          throw new Error("pnpm install --frozen-lockfile failed");
        }
      },
    },
    {
      label: "biome ci .",
      run: () => {
        const res = runCommand("./node_modules/.bin/biome", ["ci", "."], rootDir);
        if (res.status !== 0) {
          throw new Error("biome ci . failed");
        }
      },
    },
    {
      label: "tsc -b",
      run: () => {
        const res = runCommand("./node_modules/.bin/tsc", ["-b"], rootDir);
        if (res.status !== 0) {
          throw new Error("tsc -b failed");
        }
      },
    },
    {
      label: "node --test packages/**/dist/**/*.test.js",
      run: () => {
        const discovered: string[] = [];
        for (const pkg of loadWorkspacePackages(rootDir)) {
          const distDir = path.join(pkg.dirPath, "dist");
          const walk = (d: string): void => {
            if (!existsSync(d)) {
              return;
            }
            for (const e of readdirSync(d, { withFileTypes: true }).sort((a, b) =>
              a.name.localeCompare(b.name),
            )) {
              const full = path.join(d, e.name);
              if (e.isDirectory()) {
                walk(full);
              } else if (e.isFile() && e.name.endsWith(".test.js")) {
                discovered.push(path.relative(rootDir, full).split(path.sep).join("/"));
              }
            }
          };
          walk(distDir);
        }
        if (discovered.length === 0) {
          throw new Error("No compiled *.test.js files found under packages/**/dist/");
        }
        const res = runCommand("node", ["--test", ...discovered], rootDir);
        if (res.status !== 0) {
          throw new Error("node --test failed");
        }
      },
    },
    {
      label: `node ${serverMain} --check --http node`,
      run: () => {
        const res = runCommand("node", [serverMain, "--check", "--http", "node"], rootDir);
        if (res.status !== 0) {
          throw new Error("server --check --http node failed");
        }
      },
    },
    {
      label: `node ${serverMain} --check --http hono`,
      run: () => {
        const res = runCommand("node", [serverMain, "--check", "--http", "hono"], rootDir);
        if (res.status !== 0) {
          throw new Error("server --check --http hono failed");
        }
      },
    },
    {
      label: "pnpm xtask check",
      run: () => {
        const errs = checkWorkspace(rootDir, PREFIX);
        if (errs.length > 0) {
          throw new Error(`xtask check failed:\n  - ${errs.join("\n  - ")}`);
        }
      },
    },
  ];

  for (const step of steps) {
    try {
      step.run();
      results.push({ label: step.label, status: "PASS" });
    } catch (err: unknown) {
      results.push({ label: step.label, status: "FAIL" });
      printSummaryTable(results);
      throw err;
    }
  }

  printSummaryTable(results);
}

function printSummaryTable(
  rows: ReadonlyArray<{ readonly label: string; readonly status: "PASS" | "FAIL" }>,
): void {
  const width = Math.max(24, ...rows.map((r) => r.label.length));
  const divider = `${"-".repeat(width + 2)}+--------`;
  process.stdout.write(`\n${divider}\n`);
  process.stdout.write(` ${"Step".padEnd(width)} | Status\n`);
  process.stdout.write(`${divider}\n`);
  for (const row of rows) {
    process.stdout.write(` ${row.label.padEnd(width)} | ${row.status}\n`);
  }
  process.stdout.write(`${divider}\n`);
}

export function nodeVersionProblem(found: string, required: string): string | null {
  const need = Number.parseInt(required.trim().replace(/^v/, ""), 10);
  const have = Number.parseInt(found.trim().replace(/^v/, ""), 10);
  if (Number.isNaN(need) || Number.isNaN(have) || have >= need) {
    return null;
  }
  return `This project needs Node.js ${need} or newer, but this is Node.js ${found}.`;
}

function requireNodeFloor(rootDir: string): void {
  const nvmrc = path.join(rootDir, ".nvmrc");
  if (!existsSync(nvmrc)) {
    return;
  }
  const problem = nodeVersionProblem(process.versions.node, readFileSync(nvmrc, "utf8"));
  if (problem !== null) {
    throw new Error(problem);
  }
}

export function main(argv: readonly string[]): void {
  const root = workspaceRoot();
  const subcommand = argv[0];
  const rest = argv.slice(1);

  switch (subcommand) {
    case "check": {
      const errors = checkWorkspace(root, PREFIX);
      if (errors.length > 0) {
        process.stderr.write(
          `xtask check failed (${errors.length} issue(s)):\n  - ${errors.join("\n  - ")}\n`,
        );
        process.exitCode = 1;
        return;
      }
      process.stdout.write("xtask check passed.\n");
      return;
    }
    case "graph": {
      process.stdout.write(`${formatWorkspaceGraph(root)}\n`);
      return;
    }
    case "new-package": {
      cmdNewPackage(root, rest);
      return;
    }
    case "new-component": {
      cmdNewComponent(root, rest);
      return;
    }
    case "rename": {
      cmdRename(root, rest);
      return;
    }
    case "ci": {
      requireNodeFloor(root);
      cmdCi(root);
      return;
    }
    case "prepare-scaffold": {
      // Explicit generation step; CI itself remains read-only.
      requireNodeFloor(root);
      const install = runCommand("pnpm", ["install", "--frozen-lockfile"], root);
      if (install.status !== 0) {
        throw new Error("pnpm install --frozen-lockfile failed during scaffold preparation");
      }
      const normalize = runCommand(
        "./node_modules/.bin/biome",
        ["check", "--write", "--linter-enabled=false", "."],
        root,
      );
      if (normalize.status !== 0) {
        throw new Error("Scaffold formatting/import normalization failed");
      }
      return;
    }
    default: {
      process.stderr.write(
        "Usage: pnpm xtask <check|graph|ci|prepare-scaffold|new-package|new-component|rename>\n",
      );
      process.exitCode = 1;
    }
  }
}

const currentFile = fileURLToPath(import.meta.url);
if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === currentFile) {
  try {
    main(process.argv.slice(2));
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`xtask error: ${msg}\n`);
    process.exitCode = 1;
  }
}

/// <reference types="vitest/config" />
// How this site is built. "pnpm dev" serves it, "pnpm build" writes it to dist/.
//
// Pages: every .html file under src/pages is one page. src/pages/about/index.html is
// served at /about/ and built to dist/about/index.html.
//
// Includes: a comment <!-- include: header.html --> is replaced by the file
// src/components/header.html (partials may include other partials). Add current= with
// the address of a link in that partial, as in <!-- include: header.html current=/about/ -->,
// to mark that link with aria-current="page". The build stops with a plain message when
// an include is wrong: an unknown file, a misspelled setting, or a current= address that
// no link in the partial has. A comment is an include only when it starts with lowercase
// "include:". Include: or INCLUDE: (wrong case) and <!-- include header.html --> (no colon)
// also stop the build; any other comment is an ordinary note. Includes inside <script>,
// <style>, <pre>, <textarea>, <template> and <title> are left as they are.
// Files from src: in img, source, video, audio, track, use, image and link tags (icons,
// manifest, preload; not stylesheets), an address such as /src/assets/photo.jpg names a
// file in src; the build stops if it is missing. Stylesheets and scripts use /src/ too.
//
// Folder notes: README.md and .gitkeep files explain or keep a folder. Those in public/
// are not copied into dist/, and the dev and preview servers answer 404 for them.
//
// The code behind these rules is in tools/xtask/site-plugins.ts.
import path from "node:path";
import { defineConfig, type UserConfig } from "vite";
import { assetFileNames, findPages, sitePlugins } from "./tools/xtask/site-plugins.ts";

const projectDir = import.meta.dirname;
const srcDir = path.join(projectDir, "src");
const pagesDir = path.join(srcDir, "pages");

// The configuration is built when Vite asks for it, so importing this file (as the unit
// tests do) reads nothing from disk.
export default defineConfig(
  (): UserConfig => ({
    root: pagesDir,
    publicDir: path.join(projectDir, "public"),
    appType: "mpa",
    input: findPages(pagesDir),
    resolve: {
      // In a page, "/src/..." means a file in this project's src folder.
      alias: [{ find: /^\/src\//, replacement: `${srcDir}${path.sep}` }],
    },
    plugins: sitePlugins(projectDir),
    server: {
      fs: {
        allow: [projectDir],
      },
    },
    build: {
      outDir: path.join(projectDir, "dist"),
      emptyOutDir: true,
      modulePreload: {
        polyfill: false,
      },
      rolldownOptions: {
        // All CSS is written as assets/site-<hash>.css.
        output: { assetFileNames },
      },
    },
    test: {
      root: projectDir,
      include: ["tests/unit/**/*.test.ts", "tests/unit/**/*.spec.ts"],
      environment: "node",
    },
  }),
);

export {
  expandIncludes,
  type IncludeComment,
  isFolderNote,
  markCurrentLinks,
  parseIncludeComment,
  type ReadPartial,
  relativeSrcUrl,
  rewriteSrcUrls,
  SiteError,
} from "./tools/xtask/site-plugins.ts";

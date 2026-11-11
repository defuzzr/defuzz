"""Deterministic generated corpus of project-request sentences for Defuzz routing."""

from __future__ import annotations

from typing import Iterator, List, Optional, Tuple

REQUEST_FRAMES: Tuple[str, ...] = (
    "set up a {x}",
    "new {x} project",
    "i want to start a {x}",
    "make me a {x} called Demo",
    "scaffold a {x}",
    "create a {x} for my team",
    "{x}",
    "can you set up a {x} called Demo Project",
)

# 6 code templates (web-golden: WEBSITE_TEMPLATE_PHRASES below): 4-8 noun phrases each derived from what template.yaml says it is
# (id, name, summary, kind, languages, options/tools) and ordinary speech.
TEMPLATE_PHRASES: dict[str, Tuple[str, ...]] = {
    "python-golden": (
        "python backend service",
        "fastapi api",
        "python cli tool",
        "python web service",
        "layered python uv workspace",
        "python microservice",
    ),
    "ts-node-golden": (
        "typescript backend service",
        "node.js web service",
        "hono api service in typescript",
        "typescript web app",
        "layered typescript pnpm workspace",
        "node api server",
    ),
    "rust-golden": (
        "rust cli application",
        "rust command line tool",
        "layered rust workspace",
        "rust app",
        "rust cargo cli project",
        "rust backend service",
    ),
    "go-golden": (
        "go backend service",
        "go cli tool",
        "golang web service",
        "layered go workspace",
        "go api server",
        "golang microservice",
    ),
    "dotnet-golden": (
        "c# backend service",
        ".net web service",
        "dotnet cli tool",
        "layered .net c# solution",
        "csharp api service",
        "dotnet backend server",
    ),
    "cpp-golden": (
        "c++ cli tool",
        "c++20 cmake and ninja workspace",
        "cpp command line utility",
        "c++ tool",
        "layered c++ workspace",
        "cpp application",
    ),
}

# 14 project kits: 4-8 noun phrases each derived from kit `name` and `summary` in
# tests/fixtures/kit_contract/list.json and ordinary speech (not copied from `tags`).
KIT_PHRASES: dict[str, Tuple[str, ...]] = {
    "client-job": (
        "client job workspace",
        "freelance job with brief and contract",
        "client project with review rounds and deliveries",
        "freelance client work with contract and intake",
        "client commission and delivery folder",
        "freelance job workspace",
    ),
    "comic-storyboard": (
        "comic and storyboard workspace",
        "storyboard with script and character sheets",
        "comic book project with per-page stage folders",
        "graphic novel script and character sheets",
        "storyboard and animatics project",
        "comic pages and character sheet workspace",
    ),
    "component-library": (
        "component library",
        "folder of reusable python components",
        "reusable python components with componentize specs",
        "python component collection with thin runners",
        "reusable component library with index and specs",
        "componentize reusable python components",
    ),
    "game-assets": (
        "unreal and blender game workspace",
        "game asset workspace for unreal blender and houdini",
        "3d game assets for unreal with blender and houdini",
        "blender and houdini source assets for unreal",
        "unreal game workspace with source asset manifest",
        "houdini and blender game asset pipeline",
    ),
    "godot-game": (
        "godot solo game",
        "solo godot game workspace",
        "godot game with scenes and gdscript",
        "2d indie game in godot",
        "godot game with scenes and source art",
        "solo game project in godot",
    ),
    "homelab": (
        "homelab infrastructure",
        "homelab workspace with host inventory and compose stacks",
        "home server infrastructure with network rules and runbooks",
        "homelab host configs and backup records",
        "self-hosted homelab compose stacks and runbooks",
        "home lab network and host inventory",
    ),
    "image-set": (
        "image generation set",
        "ai image generation workspace with comfyui workflows",
        "comfyui prompt and contact sheet image set",
        "ai generated image set with references and contact sheets",
        "image generation prompts and staged outputs",
        "comfyui image generation workspace",
    ),
    "lora-training": (
        "lora and model training",
        "lora training workspace with staged dataset",
        "model training run with dataset and evaluation sets",
        "lora fine-tuning dataset and datasheets",
        "ai model training with isolated run folders",
        "lora training dataset and configs",
    ),
    "music-production": (
        "music and audio production",
        "music production workspace with stems mixes and masters",
        "audio production with per-song folders for recordings and stems",
        "song recording mixing and mastering workspace",
        "album music production with stems and masters",
        "music recording and audio mix project",
    ),
    "research-writing": (
        "research and writing",
        "research writing workspace with sources and citations",
        "academic paper with outlines section drafts and figures",
        "research report with reading notes and synthesis notes",
        "writing project with section drafts figures and citations",
        "research notes outlines and citations workspace",
    ),
    "studio-3d": (
        "3d design studio for blender houdini ue5 godot and web",
        "multi-tool 3d studio workspace with blender and three.js",
        "3d studio with blender houdini unreal godot and three.js",
        "3d design studio with per-asset sources and exports",
        "blender houdini and three.js 3d studio",
        "multi-tool 3d design studio workspace",
    ),
    "video-channel": (
        "youtube and short-form video channel",
        "youtube channel workspace with episode template and shorts",
        "short-form video channel with brand assets and analytics",
        "youtube channel with idea backlog episodes and shorts",
        "video channel for youtube episodes and shorts",
        "youtube and shorts channel workspace",
    ),
    "video-production": (
        "video production",
        "ai-assisted video production with canon references and footage",
        "video or storyboard production with renders and deliverables",
        "short film video production with footage and renders",
        "video production with generated candidates and approved assets",
        "ai video production with canon references and renders",
    ),
    "web-app": (
        "web app with design assets",
        "web application workspace with handed-over design sources and design tokens",
        "frontend web app with design tokens and raw assets",
        "web app with handed-over design sources and e2e tests",
        "design handoff web application with design tokens",
        "web app and design tokens workspace",
    ),
}

# ~25 hand-written ordinary chat-like or out-of-scope requests that must reach NO kit
# and no wrong template (expected: ('none', None)).
NEGATIVE_CASES: Tuple[str, ...] = (
    "fix the bug in my login page",
    "write a poem about servers",
    "what is a lora",
    "rename my photos",
    "summarize this video",
    "review my pull request",
    "explain how docker compose works",
    "translate this paragraph into spanish",
    "why is my wifi dropping packets",
    "draft an email to my client about the invoice",
    "convert this mov file to mp4",
    "how do i center a div in css",
    "tell me a joke about compilers",
    "find all todo comments in the repo",
    "calculate the mortgage payment for a house",
    "what time is it in tokyo",
    "proofread my thesis introduction",
    "list the top ten indie games of the year",
    "help me debug a segfault",
    "compare blender and houdini for vfx",
    "write a sql query to join two tables",
    "how many calories are in an avocado",
    "summarize the latest research paper on transformers",
    "clean up unused branches in git",
    "schedule a reminder for tomorrow morning",
)

# ~30 hand-written confusable code requests that mention a media word or kit word,
# with expected (catalog, target_id) — always a code template or ('none', None), never a kit.
CONFUSABLE_CASES: Tuple[Tuple[str, str, Optional[str]], ...] = (
    ("video player library in rust", "template", "rust-golden"),
    ("image resizing cli in go", "template", "go-golden"),
    ("api client library in typescript", "template", "ts-node-golden"),
    ("background job runner in go", "template", "go-golden"),
    ("discord bot that posts images in python", "template", "python-golden"),
    ("blender plugin in python", "template", "python-golden"),
    ("music streaming backend service in python", "template", "python-golden"),
    ("web app for a comic shop in typescript", "template", "ts-node-golden"),
    ("homelab dashboard web app in typescript", "template", "ts-node-golden"),
    ("research paper search service in python", "template", "python-golden"),
    ("storyboard viewer desktop app in c++", "template", "cpp-golden"),
    ("youtube analytics backend service in go", "template", "go-golden"),
    ("freelance invoice api service in c#", "template", "dotnet-golden"),
    ("podcast audio transcoder cli tool in rust", "template", "rust-golden"),
    ("lora weights converter cli tool in python", "template", "python-golden"),
    ("comfyui workflow runner service in python", "template", "python-golden"),
    ("citation and bibtex parser library in rust", "template", "rust-golden"),
    ("game asset checksum cli tool in c++", "template", "cpp-golden"),
    ("nas backup daemon service in go", "template", "go-golden"),
    ("design token linter cli tool in typescript", "template", "ts-node-golden"),
    ("video thumbnail generator service in python", "template", "python-golden"),
    ("client contract management web app in typescript", "template", "ts-node-golden"),
    ("3d model format converter cli in rust", "template", "rust-golden"),
    ("gpu render farm scheduler service in go", "template", "go-golden"),
    ("album metadata tagger cli in python", "template", "python-golden"),
    ("manga reader web app in typescript", "template", "ts-node-golden"),
    ("csharp service for client billing and invoices", "template", "dotnet-golden"),
    ("cpp cli tool for audio stem splitting", "template", "cpp-golden"),
    ("music streaming backend service", "template", "python-golden"),
    ("web app for a comic shop", "template", "ts-node-golden"),
)

# Website requests, added with the web-golden template. These pin matcher.py, which now only
# feeds "(suggested)" marks (docs/routing.md, "How suggestions work"): site and page requests reach the template; near-misses (web apps,
# design handoffs, site stacks the template lacks, backends, named languages, games, bots,
# non-project and prose requests) go to the web-app kit, another template, or ask.
WEBSITE_CASES: Tuple[Tuple[str, str, Optional[str]], ...] = (
    ("make me a website", "template", "web-golden"),
    ("a website for my band", "template", "web-golden"),
    ("build a landing page", "template", "web-golden"),
    ("portfolio site", "template", "web-golden"),
    ("a personal website", "template", "web-golden"),
    ("a static site for my bakery", "template", "web-golden"),
    ("a docs site for my library", "template", "web-golden"),
    ("documentation site for our api", "template", "web-golden"),
    ("a blog shell", "template", "web-golden"),
    ("set up a blog", "template", "web-golden"),
    ("small business website for a plumber", "template", "web-golden"),
    ("website with vite", "template", "web-golden"),
    ("html css and typescript site", "template", "web-golden"),
    ("a typescript website", "template", "web-golden"),
    ("landing page in typescript", "template", "web-golden"),
    ("a homepage for my club", "template", "web-golden"),
    ("a simple web page", "template", "web-golden"),
    ("a portfolio to show my photography", "template", "web-golden"),
    ("a landing page for my app", "template", "web-golden"),
    ("a coming soon page", "template", "web-golden"),
    ("a wedding website", "template", "web-golden"),
    ("an event page for our conference", "template", "web-golden"),
    ("a static website with vite and typescript", "template", "web-golden"),
    ("new website project called Demo", "template", "web-golden"),
    ("a resume site", "template", "web-golden"),
    ("a one page site for my cafe", "template", "web-golden"),
    ("product landing page", "template", "web-golden"),
    ("personal site", "template", "web-golden"),
    ("a website for my podcast", "template", "web-golden"),
    ("a portfolio website for my 3d art", "template", "web-golden"),
    ("a marketing site for our startup", "template", "web-golden"),
    ("html and css website", "template", "web-golden"),
    ("a website in typescript with vite", "template", "web-golden"),
    ("an html site", "template", "web-golden"),
    ("website for our open source cli tool", "template", "web-golden"),
    ("a site for my discord server community", "template", "web-golden"),
    ("web app with design assets", "kit", "web-app"),
    ("website from a figma design handoff", "kit", "web-app"),
    ("design handoff workspace for a website", "kit", "web-app"),
    ("frontend web app with design tokens and raw assets", "kit", "web-app"),
    ("figma to code website", "kit", "web-app"),
    ("a web app", "kit", "web-app"),
    ("make me a web app", "kit", "web-app"),
    ("a dashboard", "kit", "web-app"),
    ("an online store", "kit", "web-app"),
    ("a customer portal", "kit", "web-app"),
    ("browser app", "kit", "web-app"),
    ("react website", "kit", "web-app"),
    ("a vue web app", "kit", "web-app"),
    ("svelte site", "kit", "web-app"),
    ("next.js website", "kit", "web-app"),
    ("website for my portfolio with react", "kit", "web-app"),
    ("a wordpress site", "kit", "web-app"),
    ("typescript web app", "template", "ts-node-golden"),
    ("web app in rust", "template", "rust-golden"),
    ("python website with flask", "template", "python-golden"),
    ("rest api in typescript for my website", "template", "ts-node-golden"),
    ("node api server for my blog", "template", "ts-node-golden"),
    ("a website scraper in python", "template", "python-golden"),
    ("static site generator cli in rust", "template", "rust-golden"),
    ("a website in java", "none", None),
    ("backend api for my website", "none", None),
    ("write the copy for my landing page", "none", None),
    ("design a logo for my website", "none", None),
    ("make a mockup of my homepage in figma", "none", None),
    ("a browser game", "none", None),
    ("a browser game in typescript", "none", None),
    ("a chrome extension", "none", None),
    ("a discord bot for my website", "none", None),
    ("fix the css on my website", "none", None),
    ("blog post about my website", "none", None),
    ("explain how static sites work", "none", None),
)

# Generated phrases for the web-golden template, yielded after every older case so existing
# case ids keep their index.
WEBSITE_TEMPLATE_PHRASES: dict[str, Tuple[str, ...]] = {
    "web-golden": (
        "static website",
        "landing page",
        "personal portfolio site",
        "docs site",
        "small business website",
        "website with vite and typescript",
    ),
}

KNOWN_VIOLATIONS: dict[str, str] = {}


def iter_cases() -> Iterator[Tuple[str, str, Optional[str], str]]:
    """Yield (sentence, expected_catalog, expected_id, group) deterministically."""
    for template_id, phrases in TEMPLATE_PHRASES.items():
        for phrase in phrases:
            for frame in REQUEST_FRAMES:
                yield (frame.format(x=phrase), "template", template_id, "template")

    for kit_id, phrases in KIT_PHRASES.items():
        for phrase in phrases:
            for frame in REQUEST_FRAMES:
                yield (frame.format(x=phrase), "kit", kit_id, "kit")

    for sentence in NEGATIVE_CASES:
        yield (sentence, "none", None, "negative")

    for sentence, exp_cat, exp_id in CONFUSABLE_CASES:
        yield (sentence, exp_cat, exp_id, "confusable")

    for template_id, phrases in WEBSITE_TEMPLATE_PHRASES.items():
        for phrase in phrases:
            for frame in REQUEST_FRAMES:
                yield (frame.format(x=phrase), "template", template_id, "template")

    for sentence, exp_cat, exp_id in WEBSITE_CASES:
        yield (sentence, exp_cat, exp_id, "website")

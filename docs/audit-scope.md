# Project-outward audit scope

`hermes defuzz audit --root /registered/project` performs a full outward **static**
audit by default. Tool/API callers can supply `selected_projects`. Roots must be
registered; selecting a parent does not select registered descendants. No project
selection means the active profile. `--quick` is opt-in; `--full-home` does not
implicitly select other projects. For each selected project the audit also runs
`template_drift`, `static_code` and `tools_lock`; the static-code check is
described in [audit-static-code.md](audit-static-code.md).

Hermes-core `file:line` references below describe the static model this plugin
implements, as read from one Hermes source tree; they are not a promise about every
supported Hermes release.

## Before starting

The code-defined `AUDIT_SCOPE_DISCLOSURE` in `audit/evidence_constants.py` is
shared by the tool schema, CLI help and pre-run stderr notice, and the typed
`GET /audit/scope` payload. The desktop panel requires **Review audit scope**
before enabling Run; fetching the disclosure does not start a collector or write
an audit run. A failed disclosure fetch leaves execution disabled. Resume uses
the same disclosure. No audit path offers cleanup execution; writes are confined
to plugin data. A05 (the strict credential policy: credential files are never opened)
applies; the exceptions are listed under Known credential-boundary limitations.
Only lstat metadata is recorded, without following symlinks.

## Advisory report semantics

`policy_recommendations` is separate from coverage and findings. Each entry
references finding IDs and affected identities, uses a closed recommendation
kind (`review_memory_scope`, `review_dependency_policy`, `review_template_policy`,
`review_execution_policy`), and has `execution_available: false`. Only explicit
rule mappings qualify. Every affected unit must be completed, verified and not
unstable; any unknown/excluded finding for the same unit suppresses its policy
recommendations. Missing unit evidence also suppresses recommendations. An empty
recommendation list does not mean clean coverage.

`preservation_assessments` contains an entry for every finding, linked by finding
IDs, affected identities and any proposed cleanup identifier. `must_preserve`
uses only `user_data`, `config`, `credentials_metadata_only` or `unknown`.
`confidence: verified` means static category evidence only, not verified backups
or safe deletion. Unknown/excluded coverage, unfinished units and unmapped rules
produce `confidence: unknown` and `reason: insufficient_evidence`. Even known
categories have `reason: static_evidence_only`; these are minimum preservation
requirements, not exhaustive inventories. Cleanup remains unavailable. Both
sections pass through the existing typed evidence serializer.

The full public-runner performance regression uses one synthetic profile and
nine registered, explicitly selected Python/TypeScript/Rust fixture projects.
It calls `execute_audit` with default full mode and `wait=True`, records wall
seconds and asserts under 120 seconds, ten processed units and 43
unit results. It does not require unknown static coverage to become clean.
The separate quick-mode under-30-second regression remains unchanged.

Each analysis component called through the audit surface runs in a child process under a hard wall-clock budget: 60 seconds per component and 900 seconds for every component in one audit. Both sit above the largest inner cooperative cap (30 seconds for profile duplicates, 20 seconds for the session scanner) so a graceful inner cut wins over a hard kill; on the wired-sections fixture the slowest component takes about 0.1 seconds and the bound adds 0.4 to 0.7 seconds (8 to 13 percent) to a 5.2 to 5.4-second audit. The child is one freshly started interpreter per audit (never a fork, so it inherits no open database), replaced only after a kill; arguments, the parent's redaction state and every reply travel on pipes only, and the child refuses every write. On timeout, cancel, crash or a refused reply the parent sends SIGTERM to the child's process group and to every descendant of the child, waits up to 0.1 seconds for the child to exit, stops what is left with SIGSTOP, sends SIGKILL and reaps the child. The descendants are found by walking only the child's own process tree through `/proc/<pid>/task/<tid>/children`; on a kernel without that file the walk reads the parent process id of every process in `/proc` instead. The child is a child subreaper, so a descendant that starts its own session or double-forks stays below it and is killed too, and the child is set to die with the parent. The finding is `<component>.unverified` with coverage `could_not_verify` and the fixed sentence `The <component> check exceeded its time budget and could not be verified.`; a crash, a signal, or a reply over 8 MiB or unreadable gives `The <component> check stopped without a usable result and could not be verified.` No input or exception text is echoed, and the rest of the audit completes. Cancelling an audit while a component is running in the child stops it within about 0.2 seconds: the child and its descendants are killed the same way, and no further component is started. A call runs in-process, unbounded, only when it cannot cross a process boundary: a function without an importable name or arguments that cannot be pickled. Tool callers override the defaults with `component_budget_s` and `audit_budget_s` on the audit arguments; there is no environment-variable override.

## Context load and bloat report section (`report.context_load`)

Full-mode audits resolve each selected project's context chain (`AGENTS.md`,
`AGENTS.override.md`, `agents.md`, `.hermes.md`, `HERMES.md`, `CLAUDE.md`,
`claude.md`, `.cursorrules`, and `.cursor/rules/*.mdc` up to the nearest existing
`.git` boundary, or the project directory only when no `.git` ancestor exists),
pass those additions to `profile_context`, and evaluate the pure
`audit.context_load` component. The resulting `report.context_load` section is
persisted in `report_json` and covered by `canonical_digest`. It reports:

- `estimator_version`, `is_exact`, `is_lower_bound: true`, and
  `context_file_max_chars: {value, source: "config" | "assumed_default"}`.
- `profile`: per-source character/token rows (`identity_soul`, `core_guidance`,
  `enabled_memory_files`, `auto_loaded_skill_bodies`, `skills_index_text`) with
  `share_of_fixed`, `fixed_prompt` totals, `skill_counts` (`listed_skill_count`,
  `auto_loaded_count`, `largest_auto_loaded_injected_chars`,
  `largest_auto_loaded_estimated_tokens`, `zero_counted_skill_count`), `persona`
  truncation metrics, and `memory` entry/token totals.
- `projects`: per selected project winning context kind, injected and shadowed
  files (with `truncated` and `from_parent` flags), and character/token totals
  matching Hermes head/tail truncation (including whole-chain `AGENTS.md` and
  joined `.cursorrules`/`.mdc` truncation). Unverifiable project context chains
  emit `context_load.project_context_unverified`. When `context_file_max_chars`
  uses `assumed_default` (`20000`), `context_load.project_context_truncated`
  carries `coverage: "could_not_verify"` and discloses that the live truncation
  ceiling depends on the active model's context window.
- `per_turn_total`, `window_share` (against 32k, 128k, and 200k reference
  windows), and `resend_cost` (`turns_10`, `turns_50`, `turns_100`, explicitly
  labelled as an estimate ignoring provider prompt caching).
- `external_memory_provider`: whether `memory.provider` is configured (`measured:
  false`, `coverage: could_not_verify` when configured; shipped provider IDs
  `byterover` and `retaindb` are allowlisted vocabulary while unknown provider
  names are HMAC-sealed).
- `unmeasured`: dynamic sources excluded from static totals
  (`dynamic_plugin_prompt_sections`, `plugin_registered_skills`,
  `builtin_tool_schemas`, `mcp_tool_schemas`,
  `external_memory_provider_prefetch_and_blocks`,
  `caller_ephemeral_system_message`, `workspace_git_status_snapshot`,
  `runtime_environment_metadata`), plus `thresholds`.

In explicit quick (`bounded`) mode, `report.context_load` reports
`{coverage: "could_not_verify", reason: "bounded_quick_audit_not_collected"}`
rather than zeros. Findings (`context_load.*`, `profile_context.*`, and
`memory.*`) retain code-defined specific consequence sentences and allowlisted
numeric/vocabulary evidence fields without persisting raw source text; evidence
path fields (`path`, `project_root`, `skill_md_path`) are retained only on
`context_load.*` findings.

## Skill hygiene (`report.skill_hygiene`)

Full mode reads bounded skill packages in the active profile. Provenance is explicit:
`stock` (bundled manifest), `hub` (official hub lock), `user_authored` (including
unverified provenance), or `external_dir` (additional in-profile roots). Provenance
is a local recorded baseline, not cryptographic authentication of upstream authors.

- Stock: `skills/.bundled_manifest` records name:MD5, BOM-tolerant; legacy name-only
  entries cannot verify (`tools/skills_sync.py:113-128`). Hash sorted relative `Path`
  components followed by bytes, accepting current cache-filtered or exact legacy
  hashes (`tools/skills_sync.py:187-212`). Hashing includes `.git`, `node_modules`
  and nested packages; discovery exclusions are NOT hash exclusions. Only generated
  cache directories and bytecode beside source are omitted by the current hash
  (`tools/skills_sync_optional.py:41-58`). Credential/symlink refusals prevent verification.
- Hub: `skills/.hub/lock.json` has an `installed` mapping with `source`, `install_path`
  and `content_hash` (`tools/skills_hub.py:323-365`,
  `tools/skills_sync_optional.py:73-88,222-227`). Only `source: official` gets this
  exemption; third-party hub entries remain user-authored. SHA256 hashes sort POSIX
  relative path STRINGS, append each path plus NUL and file bytes, and compare
  `sha256:` plus the first 16 hex digits (`tools/skills_guard.py:767-788`). Optional
  provenance backfill can fall back to the current MD5 (`tools/skills_sync_optional.py:23-29`).
  When no lock file exists, `hub_coverage` is `not_applicable` and section coverage is
  unaffected. An existing unreadable, malformed or unsafe lock sets both
  `hub_coverage: could_not_verify` and section `coverage: could_not_verify`;
  affected skills are treated as user-authored, never claimed modified from that lock.
- Manifest collisions: `.bundled_manifest` normally records `skill_name:MD5` rather than
  category paths (`tools/skills_sync.py:113-128,170-185,325`). Hash-check all name/path
  claimants together. A verifying candidate (prefer the exact recorded path) is stock;
  other same-name packages are user-authored duplicates, never automatically modified
  stock. Without a verifying candidate, if a single package claims the manifest name
  (including a categorized install such as `skills/<category>/<name>`), it is reported
  as modified stock; if multiple packages claim the name and none verifies, only a single
  exact manifest install-path match (`rel == key`) is reported as modified stock,
  otherwise the manifest entry stays unlocated and coverage is `could_not_verify`.
- External directories: Hermes reads `skills.external_dirs` as scalar/list paths,
  relative to the Hermes home (`agent/skill_utils.py:331-362`). Literal directories
  inside the active profile are scanned with `provenance: external_dir`, deduplicated
  with local discovery, and use the same caps. Outside roots, links, credentials,
  parent traversal and ambient `~`/environment expansions are not followed. Each
  distinct refused directory contributes one to
  `skill_hygiene.external_skill_dir_not_scanned` evidence `count`, without exposing
  its path. This component does not receive the selected-project allowlist; even
  selected/registered out-of-profile roots are disclosure-only here. Registration
  alone is not permission to read unselected projects (see inspection boundaries).

Verified stock/hub skills retain metrics, but have no residue, machine-path,
network-identity or oversized findings; they are absent from `top_skills`,
`residue_skills` and combined write-setting findings. A verified mismatch uses the
existing `skill_hygiene.stock_skill_modified` ID with `provenance: stock|hub`.
No original size is stored, so growth is not measurable.

Seven residue classes are measured without retaining source text:

1. Dates: unquoted `YYYY-MM-DD`, `YYYY/MM/DD`, `MM/DD/YYYY`, `DD Month YYYY`,
   `Month DD, YYYY`, or `Month DD` (such as `Nov 9`, `Oct 2`), including
   checked/verified/as-of prose. YAML frontmatter dates, changelog/release/history/versions
   sections (including deeper headings until a peer or higher heading), and lines
   that look like a version/release table or heading (lines containing a version
   number `v?\d+\.\d+` together with the date, or `release`, `released`, `version`,
   `changelog`, `updated`, `last verified`, `last updated`) are exempt. URL-path
   dates are not dates here.
2. Tickets: case-insensitive PR/issue/ticket context, `pull #`, `fixes #`, `closes #`,
   `see #`, cross-repo references `repo#N` and `owner/repo#N`, GitLab merge requests
   `group/project!N`, GitHub issue/pull URLs, or uppercase tracker IDs. Technical and
   standards prefixes (`TICKET_PREFIX_DENYLIST`: UTF, SHA, ISO, RFC, CVE, HTTP, AES,
   GPT, ECMA, PSR, KB, PEP, JEP, JSR, BCP, STD, FIPS, NIST, OWASP, WCAG, POSIX, ANSI,
   IEEE, ITU, MIL, DIN, EN, BS, AS, etc.) remain denylisted.
3. Commits: contextual 7–40 hex identifiers (`commit`, `sha`, `revision`, `cherry-pick`),
   bare unquoted 40-hex and hex ranges. Bare short commit hashes without the word
   `commit` (or another context word) stay unmatched because they are too ambiguous.
   URL-path hashes, 64-hex download checksums and CSS colors are not bare commits.
4. Machine paths: case-sensitive Unix `/home/` and `/Users/` branches (so REST routes
   such as `/users/{id}`, `/users/:id`, `/users/<id>` and `/users/me` do not match as
   macOS home paths) and Windows `C:\Users\<name>`. A user segment starting with `{`,
   `<`, `:`, `$`, or `%`, or matching `PLACEHOLDER_USERS` (`user`, `x`, `you`, `me`,
   `username`, `name`, `USER`, `Shared`, `Public`, `ubuntu`, `runner`, `root`, `alice`,
   `bob`, `admin`, `example`, `yourname`, `your-username`, `myuser`, `...`), is treated
   as an example, not residue. `~`, `$HOME` and `%USERPROFILE%` are portable examples.
5. Session identifiers: explicit Hermes session IDs or hex/UUID IDs in
   session/delegation/subagent context, not ordinary session-management prose.
6. Narration: `this session`, `this time`, `earlier we`, `previously we`, `yesterday`,
   `earlier today`, `we found`, `I tried`, `turned out`, `workaround for now`, and
   `last time` when accompanied by a first-person or session subject (`we`, `I`, `our`,
   `this session`) within the same sentence (so `last time the <noun> ran` style
   documentation is not matched). HTML template comments are not evidence.
7. Network identities: private IPv4 (10/8, 172.16/12, 192.168/16), CGNAT/tailnet
   100.64/10, and `*.ts.net`, `*.local`, `*.lan`. Four valid octets and boundaries
   are required; loopback, wildcard, documentation ranges and v-prefixed or longer
   dotted versions are excluded. Private addresses in a markdown networking table,
   standard CIDR notation (`/8`, `/12`, `/16`, `/24`), or on a line containing
   `e.g.`, `for example`, `example:`, `RFC 1918`, or `private range`/`address space`
   are treated as documentation/examples, not residue.

Score = `sum(4 + min(2, count - 1) for each nonempty evidence class)`.
Review threshold **13**: four lines spanning at least three classes can flag;
one repeated class caps at 6. To close the single-class hole (such as a skill
consisting solely of dated lesson bullets), a second named trigger
`dated_lesson_lines` (threshold **3**, exposed per skill and in `thresholds` under
the existing key `lesson_headings`) also flags a skill as residue when it has at
least 3 lines that start with a date (after optional list marker / whitespace / bold
markers) outside YAML frontmatter, changelog/release/version-history sections,
version/release/updated lines, and markdown tables. Ordinary Notes/Lessons/Pitfalls
headings and bullet runs do not add points. Per-file counts aggregate before scoring.
The committed 30-residue/30-legitimate line table measures **30/30 recall (100%) and
100% precision**, with every miss/false positive printed; this is a synthetic
benchmark, not a population estimate. A combined 25-line legitimate skill is not
flagged. Treating all upstream bundled+optional packages as user-authored flags
**3/186 (1.61%)**: unsloth, research-paper-writing, web-pentest (with `dated_lesson_lines`
matching 1/186 upstream, `unsloth`, already flagged by the main rule). The regression prints all offenders and requires less
than 3% (explicit skip if upstream is absent).

The body-size review threshold is **24,000 characters**, above measured upstream
nearest-rank p95 **23,549**. Across 186 upstream bodies: median 8,574; p90 17,544;
p95 23,549; maximum 70,719. Only 9/186 (4.84%) meet the new threshold, versus
109/186 at 8,000. This is a body-size heuristic, not a claim about token use.
Read-only measurements on backup copies of real homes, limited to
non-stock/user-classified candidates, showed the same spread: most candidates sit
below the threshold and a long tail sits above it.

Such candidates include provenance-unknown packages, not proof of authorship:
credential exclusions can prevent a nominal stock package from verifying, and a
lock entry may be third-party `github` rather than `official`.

Whitespace-normalized body equality or case/hyphen/underscore-equivalent names
produce duplicate groups; no comparison hash is persisted. Top ten rank non-exempt
skills by score then path. Limits: 1 MiB/file, 256 files/package, 32 MiB/component,
10,000 packages, bounded category discovery and an independent 10,000-entry budget
per skill during discovery (package reads use the smaller per-package file bound).
A large non-support subtree does not consume later skills' discovery budgets.
Non-UTF-8 names, entry/file/byte caps, unreadable files and forbidden links produce
cuts, never clean claims. Symlinks below the profile root are not followed;
symlinked ancestors above it are allowed. Excluded discovery directories and
progressive-disclosure support folders follow `agent/skill_utils.py:26-56`.
Only fixed labels, paths and counts leave this component; quick mode is uncollected.
The section is persisted and digest-covered.

**Known limits:** these text patterns cannot recognise an incident log rewritten as
procedure steps with no dates, identifiers, machine paths or network identities
(detecting that growth requires the skill-change ledger, which this section does not
read yet); private addresses in real networking documentation outside tables/CIDR/example
lines can still be counted; and precision on an independent hard test set was about
50-85% per class at line level, which is why a skill is only flagged on several
classes (`residue_score >= 13`) or the `dated_lesson_lines` (`>= 3`) rule, and why the
finding is worded as a count to review, not a verdict. A low score is not proof that
a skill is reusable.

## Write settings (`report.write_settings`)

The existing bounded YAML reader parses only active-profile config (reusing the
PyYAML dependency the audit already accepts, `>=6.0.3,<7`, which a behaviour
self-check verifies before use; no new YAML dependency is added). Duplicate
mapping keys at any depth make every setting `could_not_verify`, with fixed reason
`duplicate_config_key`, never a definite approval on/off. Hermes's YAML loader rejects
such mappings (`hermes_yaml.py:3,22-38`); this audit parser check is opt-in for config,
leaving other facts/frontmatter callers' existing behaviour unchanged. An explicit
mapping override of a YAML merge is not itself a duplicate. Each resolved setting carries `config`, `default`, or `could_not_verify`. Because Hermes loads
config with `ruamel.yaml` YAML 1.1 (`hermes_yaml.py:1-39`) while the audit parses with
PyYAML, boolean settings (`write_approval`, `memory_enabled`, `user_profile_enabled`,
`guard_agent_created`) are classified strictly against unambiguous known-true and known-false
sets matching `tools/write_approval.py:40,45-61` and `utils.py:25-34`; ambiguous scalars (such
as bare `y`/`Y`/`n`/`N` or unrecognized strings/numbers), `${...}` templates, unmigrated legacy
`write_mode` keys (`hermes_cli/config_migrations.py:397-416`), or an active administrator
managed-scope overlay directory (`/etc/hermes` or `$HERMES_MANAGED_DIR`,
`hermes_cli/config.py:2170-2185`, `hermes_cli/managed_scope.py:31-60`) report
`could_not_verify` (never `unattended_*_writes`). Memory and user-store flags default true
(`tools/memory_tool.py:292-309`, `tools/memory_tool_store.py:189-200`). Approval gates **exist**,
but default false: `tools/write_approval.py:4-9,40-61`, `hermes_cli/config_defaults.py:1296-1310,1464-1467`.
Skill mutations pass that gate (`tools/skill_manager_tool.py:672-702`). Background
memory patch/remove operations are separately staged even with the gate off
(`tools/memory_tool.py:185-219`); the unattended finding refers to additions, not
unrestricted deletion. Skill security scanning defaults off and is not human
approval (`hermes_cli/config_defaults.py:1455-1458`).

Memory review defaults every 10 user turns (`agent/agent_init.py:1244`,
`agent/turn_context.py:765-774`); skill review every 10 tool iterations
(`agent/agent_init.py:1284-1288`, `agent/turn_finalizer.py:862-875`). Zero disables
the reminder, not the write tool. A periodic flush interval was **not found** in
these init/config/tool sources; pre-compression provider hooks exist
(`agent/conversation_compression.py:2885-2918`) but are not a periodic setting.

CLI tool availability is a conservative static projection of saved
`platform_toolsets.cli` and `agent.disabled_toolsets`
(`hermes_cli/tools_config.py:580-642`), defaulting to the core CLI bundle
(`toolsets.py:11-21,52-64,100-103,126,198`). Unknown/custom expansions remain unknown;
other surfaces, caller overrides and runtime checks are not claimed resolved.
The write-approval gate (`tools/write_approval.py`) was added to Hermes well after
skills and memory could be written, so a home can hold edits made before it existed. Turning approval on stops
new unattended writes but does not clean earlier edits, and config does not record when the
gate was enabled. Therefore, skill drift and residue findings are emitted regardless of current
write settings; when approval is OFF and a modified stock skill also carries residue,
`skill_hygiene.unattended_writes_with_drift` reports the active correlation (not causal proof);
when approval is known ON and a stock/hub skill is modified, or a non-exempt
user/external skill has residue, machine paths or network identities,
`skill_hygiene.approval_enabled_with_prior_drift` warns that earlier changes need
manual review. Size alone does not trigger it. Evidence lists `bundled_modified`,
`hub_modified`, `residue_skills`, `machine_path_skills` and `network_identity_skills`
counts; verified stock/hub copies contribute none. No claim is made about when
approval was enabled.

`memory.provider` configures one external provider alongside built-in memory
(`agent/agent_init.py:1254-1278`, `agent/memory_manager.py:1-5`,
`agent/memory_provider.py:1-5,42-49`, `plugins/memory/__init__.py:1-7`). Core sentinel
values do not mean external injection. Configured does not prove installed/active.
Unknown provider/toolset names are sealed, never persisted as raw content; shipped
provider labels follow context_load's allowlist. Session opt-in can measure stored
blocks, not live provider contents. Config reads cap at 1 MiB; quick mode does not
collect this section. Settings/findings are digest-covered and contain no config text.

## User SQLite databases

This rule applies to **all user databases** inspected by the audit, not only the
opt-in transcript section: profile `state.db`, profile registration stores,
project/kanban/cron/response stores, and any other SQLite files admitted by scope.
No file is ever created beside a user database, and its main DB and WAL bytes
are never written, checkpointed or migrated. Only an **existing `-shm`** index's
SQLite read marks may change during a direct live-WAL read.

Every direct SQLite read of a user database uses the shared `open_readonly_sqlite`:

- No WAL or a zero-byte WAL (including a stale existing SHM):
  `mode=ro&immutable=1`, with a post-read DB/WAL/SHM identity check.
- Nonempty WAL plus an existing regular `-shm`: `mode=ro`, with a post-read
  DB/WAL identity check that ignores reader-owned SHM bookkeeping.
- Nonempty WAL without `-shm`: refuse with `wal_needs_index`, reporting the
  caller's existing `could_not_verify`/unknown outcome instead of creating an index.

Query-only and trusted-schema-off are set before schema reads. Rollback journals
are conservatively refused, including hot journals; missing, unreadable, unsafe,
corrupt or unsupported stores, busy/locked reads and observed identity changes
leave coverage `could_not_verify`, never verified empty data. An immutable read
is change-detected, not an atomic snapshot of a concurrently changing store.

The outward metadata collector also reads user databases **in place** through
`open_readonly_sqlite` and never copies DB or WAL files into temporary or scratch
space. It uses the same PRAGMAs (`query_only=ON`, `trusted_schema=OFF`), a 100 ms
busy timeout, a SQL VM step budget, and post-read DB/WAL identity checks. If a
database changes during the read, its measured rows and counts are retained,
`changed_during_read: true` is recorded, and owning-region coverage becomes
`could_not_verify`.

The plugin's own audit store is the only durable writable directory exception:
by default `<home>/plugin-data/defuzz/` (`state.db` plus its SQLite sidecars,
`audit.key`, `audit.key.lock`, and `.state-migration.lock`), created when
`AuditStore` initializes or prepares/runs an audit (or in the explicit `db_path`'s
parent directory when `db_path` is supplied). This is an owned report store, not
an inspected foreign store. The unchanged-home regression isolates this exception at
`<synthetic_home>/plugin-data/defuzz/audit-output/` with explicit `audit.db`;
every other recursive entry and file hash must remain unchanged, both with and
without sessions, and a watched `TMPDIR` must remain completely empty. Its source
databases include cleanly closed WAL, rollback-mode, and multi-megabyte stores.
The reader matrix covers five entry points, ten database states, and writable/0555
directories; 0555 is skipped only when root would bypass the permission check.

## Session contamination (`report.session_contamination`, opt-in)

`hermes defuzz audit --sessions` (optionally `--root /registered/project`) opts in
to sensitive transcript measurement. The API accepts `sessions: true`, or
`execute_audit(..., sessions=True)`. Saved opt-in survives resume. Without opt-in
this component returns `not_run` and never opens a session database. Existing
metadata-only session association collectors are unchanged. Quick mode does not
measure transcripts even when opted in.

The profile store is `state.db` (`hermes_state.py:181,204`). Schema columns are
verified against `hermes_state_common.py:456-492,531-553`. Both legacy inline
`system_prompt` and current hash-joined `system_prompts.prompt` are measured
(`hermes_state.py:516-524`, `hermes_state_schema.py:189-202`). These are actual
stored prompt snapshot character counts, **not** a token estimate or a guarantee
of every subsequent wire request's contents. Memory headers reuse the vendor
renderer, with the recorded usage count locating the exact body end because there
is no closing marker (`tools/memory_tool_store.py:320-322,654-657,674-680`).
External blocks use `<memory-context>` fences (`agent/memory_context.py:169-185`);
reported block characters include both fences, while family matching uses only interiors.
A linear forward scan matches ASCII case-insensitive tags, stopping at the first
opener without a closer; at most 1 MiB (`MAX_TEXT_BYTES`) and 1,024 blocks
(`MAX_BLOCKS_PER_MESSAGE`) are examined per message.
Current string recall is in `messages.api_content`, with content fallback for
older schemas and multimodal text parts (`agent/turn_context.py:113-144`).
Provider system-prompt blocks lack a universal fence and are not attributed
(`agent/system_prompt.py:522-547`). Literal user-authored fences cannot be
reliably distinguished from injected fences: observation is not proven origin.

The shared user-database rule above also governs transcript measurement; the
session reader uses a 100 ms busy timeout and does not copy its database.
`read_mode: "mode=ro"|"immutable"`, `immutable`, `wal_mode` and
`database_copied: false` disclose the choice. `wal_mode` comes from main-file
header bytes 18 and 19 (both 2), not the immutable connection's journal pragma.
A newly appearing WAL, SHM or journal, or changed main-file identity marks an
immutable read unstable; no retry loop attempts to chase a writer.

The shared stat identity helpers compare the DB and WAL before and after the
read, ignoring SHM bookkeeping. Bounded queries are also reread in autocommit
mode and compared using ephemeral digests (not persisted), so the verification
read can see later commits rather than a pinned transaction's old snapshot.
A changed DB/WAL identity or changed query result retains the measured numbers,
sets `changed_during_read: true`, and adds the info finding
`session_contamination.database_changed_during_read`: counts may be off by the
sessions written during the read. Coverage is uncertain, not a clean snapshot.
This is change detection, not a guarantee of atomic cross-query consistency.

Unmeasured failures use fixed reason labels: `missing`, `unreadable` (including
unsafe/symlink/credential paths), `not_sqlite`, `schema_unsupported`, `hot_journal`,
`busy_or_locked`, `wal_needs_index`, or `read_error`; exception text never escapes.
The outward metadata association collector follows the same in-place no-sidecar
rule above and never copies databases.

Technology signatures are fixed whole-word, case-insensitive patterns. Bare
`node`, `react`, `blueprint(s)`, `.c`, `.h`, and one-character C filename stems
are excluded (`D.C.` is not code). JavaScript uses javascript/typescript,
node.js/nodejs/npm/jsx/tsx, not React. C++/C# permit version digits (C++20, C#12);
cpp/cmake/clang, dotnet/.net/nuget and >=2-character C-family filename stems
remain signatures; standalone .cpp/.hpp are accepted.
Ambiguous `go`, `rust`, `swift`, `ruby`, `unity`, and `java` require whitespace
adjacency, before or after, to language/lang/code/project/crate/package/SDK or a
numeric version (optional `v`, optional dot components). Capitalization alone is
not a cue. Explicit golang/go.mod/go build, rustlang/rustc/cargo/.rs/RS filenames,
ruby on rails, xcode/swiftlang, maven/gradle/spring boot remain signatures.
The regression table has four positive cases and ten negative cases: all match,
including zero hits for the nine ordinary prose sentences; the previous patterns
failed eleven of those fourteen cases. This is a heuristic, not semantic parsing;
other signatures (e.g. Python, cargo, composer, Blender) can still be prose.
Memory usage percentages accept any digit count within the bounded prompt.
Docker/Kubernetes are neutral. Root families come only from bounded local filename extensions and
markers, never executing or importing project code. Credentials and symlinks are
normal exclusions, not coverage cuts. `.git`, `node_modules`, `.venv`, `venv`,
`__pycache__`, `target`, `dist`, and `build` directories are skipped. The filename
cap retains discovered families and classifies with `project_coverage: partial`. Missing/unknown projects are
excluded from the rate denominator (`sessions_classified`), not called foreign.
Only registered roots (or explicitly supplied roots) authorize filename discovery;
historical cwd/git roots never authorize new paths. Without project selection the
registered inventory supplies the allowlist. Unmatched sessions are counted only in
`sessions_outside_registered_projects`, never traversed or named. Matched sessions
are grouped under the authorized root and emitted through the report path serializer.
A historical project's present files are not a historical language inventory.
Only memory bodies/fenced recall count; unrelated prompt/user prose does not.

Per-project/overall counts, median/max prompt and memory characters, foreign-family
counts, native occurrences, contamination rates, top ten roots and UTC monthly
prompt medians are stored. NULL prompts without a deduplicated fallback count
under `sessions_without_prompt`; messages are still analysed. NULL/relative cwd
is outside registered projects. For matched sessions only, non-numeric, NULL,
nonpositive or out-of-range dates produce a coverage cut and no monthly bucket
(never a synthetic 1970-01). Invalid outside-session dates do not cut coverage.
No session IDs, source text, or raw hashes are retained.
Findings use >=3 classified sessions and >=25% foreign rate; growth requires >=2x
and >=4000 extra median characters. These are review heuristics, not causal proof.
Caps: 10,000 sessions (`MAX_SESSIONS`, primary-key order), 5,000 messages per
session (`MAX_MESSAGES_PER_SESSION`), 50,000 messages per run (`MAX_MESSAGES`),
1,024 recalled blocks per message (`MAX_BLOCKS_PER_MESSAGE`), 4 KiB/ID or path
(`MAX_METADATA_BYTES`), 1 MiB/text (`MAX_TEXT_BYTES`), and 32 MiB of
text/metadata returned to Python on the first pass (`MAX_TOTAL_TEXT_BYTES`).
There is **no database-file size refusal**; gigabyte stores are supported. Session
keys use the primary-key index with `ORDER BY id LIMIT`; metadata and prompts
use rowid point lookups. Message keys seek the integer primary key globally in
256-row keyset pages (`MESSAGE_PAGE_SIZE`), independent of timestamp; only authorized sessions' bodies are
fetched by integer primary key, up to the per-session and per-run message caps. NULL/text timestamps are per-row coverage cuts,
not database failures. No `COUNT(*)`, unbounded sort, `OFFSET` paging, or full message-table
scan is used. Schema/plan checks reject non-Hermes primary keys, oversized DDL (>64 KiB), or missing query
indexes rather than perform a large scan. `length(...)` computes sizes in SQL;
inline/deduplicated prompt text is fetched only for bounded, selected sessions
whose memory is analysed. TEXT `substr` bounds the prefix before conversion to
BLOB (including ID/path metadata and message `session_id`), then a second slice enforces the returned UTF-8 byte cap; the complete
prompt/message/metadata column is never CAST to BLOB. SQLite itself still reads full TEXT for
`length` and may materialize overflow pages internally. A synthetic 50 MiB
multibyte row regression measures Python allocations below 2 MiB with 4 KiB
prefixes; this is not a bound on SQLite's native allocations.
Trusted-schema off and query-only on precede the first sqlite_master query.
Views, virtual tables, WITHOUT ROWID tables and generated columns are rejected
as `schema_unsupported`, including optional deduplicated prompt tables. Message
`id` must be a true INTEGER PRIMARY KEY rowid alias: a separate primary-key index
(as created by column-level `INTEGER PRIMARY KEY DESC`) is rejected so NULL IDs
cannot silently disappear from paging. SQLite's parsed index metadata distinguishes
this from valid table-level `PRIMARY KEY(id DESC)` rowid aliases.

Worst-case default logical queries (excluding schema metadata): 1 session-key
batch (<=10,001 keys), 10,000 metadata rows, 10,000 prompts, <=196 global
message-key pages (<=50,001 keys including lookahead), and 50,000 bodies; one
recheck replays those bounded queries and stops at the first mismatch: total returned text/metadata is at most 65 MiB
(32 MiB first pass + 32 MiB matching replay + one changed result of at most 1 MiB).
`limits.bytes_read` is first-pass text/metadata only; numeric result fields,
SQLite's internal `length`/bounded-prefix `CAST` work, caches and index-page I/O are not part of
this bound. This is not a physical disk-I/O limit.

The 10-million SQL VM step cap includes rereads. A cooperative 20-second
wall-clock budget (`MAX_SECONDS`) is checked between bounded queries/session/message batches;
when any cap is hit, partial numbers survive with allowlisted reason tokens in
`truncated_by`, `reason`, and `cut_reasons` (`file_byte_limit_exceeded`,
`limit_exceeded`, `row_cap`, `database_row_limit_exceeded`, `table_rows`,
`total_byte_limit_exceeded`, `metadata_byte_budget`, `entry_limit_exceeded`,
`sql_steps`, `time_budget`; malformed row values record `invalid_values` in
`cut_reasons`), not a `read_error`, and `could_not_verify` coverage. A single SQLite builtin or OS call is not preempted by this
budget. Project discovery caps both files and non-ignored directories at 10,000 entries/project. Cuts disclose
partial coverage; no truncation is called clean.

## Inspection order and boundaries

A declaration-only preflight precedes run creation, template identity hashing,
Git include discovery and ordinary content capture in both full and quick modes.
The fixed code-defined `DECLARATION_SOURCE_FILES` set in `audit/policy.py` is:
`config.yaml`, `profiles/*/config.yaml` (one sibling level), `.git/config`,
`settings.json`, `settings.toml`, `package.json`, `pyproject.toml`, `Cargo.toml`,
and `pnpm-workspace.yaml`, relative to audited profile/project roots and installed
template directories. Only these files supply credential declarations. Arbitrary
JSON/YAML/TOML files are not opened to search for declarations; their credential
keys have no declaration authority even when inspected for other static evidence.

**Declaring a declaration source as a credential has no effect**: it remains
readable as a declaration source, including self-declarations and declarations of
another source. These sources are never themselves classified as credential files.
Every other declared path, standard credential name/kind and Git include target
gets lstat metadata only: each reader checks the path against the declarations (by
spelling, resolved path and file identity) before opening it, and every reader
except the one named in limitation 5 checks the opened file again before
reading a byte, so a link or hard link swapped in between is closed unread. The
five cases under Known credential-boundary limitations can still open or list a
declared path, so this is not an unconditional guarantee. All readers share
the run-local exclusion set. Protected installed template names contribute an
excluded kind, never credential bytes, to engine identity.

The profile and explicitly selected project declaration preflight runs before registration inventory.
A declared registry DB (`plugin-data/defuzz/state.db`) is not opened: registration
inventory continues with `could_not_verify` and the closed reason
`credential_store_not_opened`, not a verified empty inventory. A declared template.yaml
is excluded from template loading, leaving template coverage `could_not_verify`.
All fixed source forms, including template `.git/config` and sibling-profile configs,
participate in template preflight. In full and quick modes, declared directories are never traversed
by design (see Known credential-boundary limitations for the exceptions); only their
own lstat metadata is recorded. Quick mode records skipped credentials
encountered by its existing bounded collectors, without expanding quick scope.

After preflight, each selected project is inspected **first**, with an independent budget. The
active profile then gets its own budget. Its config, identity, memories, skills,
plugins, credentials, session associations and referenced infrastructure are in
scope. Bounded implicit HOME startup discovery has a separate `home_startup`
budget. Explicit exclusions and inaccessible paths remain `could_not_verify`.
Dependency, cache and Git object folders are skipped: folders named `node_modules`, `bower_components`, `jspm_packages`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `.tox`, `.nox`, `.next`, `.nuxt`, `.svelte-kit`, `.parcel-cache` or `.turbo` (`SKIPPED_FOLDER_NAMES` in `audit/outward.py`), Git `objects` and `lfs` storage, folders holding a `CACHEDIR.TAG` file, and the installed packages of a virtual environment (its editable-install and `.pth` metadata are kept). A folder skipped by name is a declared scope rule, not a cut: it is not counted among the region's cuts. The region that holds it still reports `could_not_verify` with reason `skipped_folders`, the count and sample paths, because that folder was not checked.
Report-store paths are excluded to avoid self-inspection; exact paths are reported.

Outgoing config paths, external skill roots, symlinks (including intermediate
links), editable installs, dependency paths and Git `core.hooksPath` create
explicit edges. Historical session cwd is association, not permission to open an
unrelated project. Unselected registered projects are not implicitly traversed.

Parent context is inspected up to the nearest `.git` ancestor, including that
root; without a git root the bounded walk continues to filesystem root. The
filename set mirrors Hermes core `agent/prompt_builder.py`: `AGENTS.override.md`,
`AGENTS.md`, `agents.md`, `.hermes.md`, `HERMES.md`, `CLAUDE.md`, `claude.md`,
`.cursorrules`, and `.cursor/rules`. Ancestor `.envrc`, `.tool-versions`,
`pyproject.toml`, `package.json`, `Cargo.toml` and workspace declarations are also
inspected as potentially affecting the project. The audit conservatively examines all variants,
not just the first nonempty runtime winner. Boundaries are reported per project;
truncation or failed inspection is unknown, never verified.

The inferred audited HOME (never an unrelated process HOME) contributes these
implicit shared inputs: the bash and zsh startup files `.bashrc`, `.profile`,
`.zshrc`, `.bash_profile`, `.zshenv`, `.zprofile`, `.zlogin`, `.zlogout`,
`.bash_login` and `.bash_logout` (`SHELL_STARTUP_FILES` in `audit/file_types.py`;
fish configuration and a `ZDOTDIR` folder are not read), `.pythonrc`, `.npmrc`, `.cargo/config.toml`, `.config/systemd/user/`,
`.config/autostart/*.desktop`, and `.local/lib/python*/site-packages/`
`sitecustomize.py`, `usercustomize.py`, and `.pth` files. Discovery is limited to
10,000 directory entries by default; unit-tree reads retain ordinary tree/depth
budgets. Other HOME and user-site package contents are not implicitly traversed.
References into selected or other projects create edges. Systemd/desktop inputs
under credential-sensitive `.config` receive only lstat metadata; their
contents and execution keys are not inspected. Custom startup locations and computed runtime
activation remain outside this fixed implicit-root inventory.

The same implicit discovery also includes credential-file metadata inputs:
`.netrc`, `.pgpass`, `.git-credentials`, `.docker/config.json`,
`.config/pip/pip.conf`, and `.pip/pip.conf` (`audit/home_startup.py:26-30`).
The list also includes `.npmrc`. Under **A05**, credential files are never opened,
read, mapped with mmap, parsed or content-fingerprinted. Only lstat metadata is
recorded, without following symlinks. Coverage reports `credential_store_not_opened`.

Sibling profiles under `<default-profile>/profiles/*` are enumerated for
**top-level lstat/symlink metadata, config.yaml, and known cron/MCP/hook/plugin declarations**. Credential stores such as `.env` receive lstat metadata only. With a
named active profile, the default root is also a sibling. Unrelated sibling
skills/plugins/transcript contents are not read. Metadata-only links into active
roots are disclosed as `incoming_sibling_symlink`; they do not claim target
content inspection. Exclusions apply before sibling enumeration/config reads. References into the active profile (including skills/plugins/memories/config), selected project or already evidenced shared roots
produce `incoming_sibling_reference` edges. Relevant sibling skill/plugin regions
are admitted as `incoming_sibling_region` edges. Unreadable, malformed,
symlinked or truncated declarations leave sibling coverage unknown; an absent
config is a verified absence, not proof of unrelated sibling contents. An explicit
outgoing reference can independently admit a sibling subtree.

Edges are persisted in `report.blending` with source, target, relationship and
evidence, and produce `audit.blending` findings. Repeated symlinks sharing a source
directory and target parent are aggregated: `source`/`target` are representative,
`count` counts links, `target_root` names the grouping root, and `sample_paths`
contains up to three source paths. Every followed target is still inspected, up to
the per-folder limits; a target cut by a limit reports `could_not_verify`.
`evidence.inspection` distinguishes `target_static` from
`declaration_or_metadata_only`; the latter never claims target content coverage. Default
report-edge exhaustion marks only the source's owning region unknown, and does
not stop target inspection. Aggregation never authorizes traversal of the target
parent. A target does not authorize
inspection of its unrelated parent or neighbors.

## Static execution and toolchains

Execution coverage is an **inventory contract**, not a code-safety verdict.
`dynamic_execution: verified` means all recognized execution surfaces in the
inspected scope were enumerated within the reported budgets. It never means
working code is correct, safe, or isolated at runtime. Every region discloses
this fundamental behavior limit once, rather than per call or source file.

Files are classified as program code, execution surfaces, known data/documents/
assets, or unknown. Known languages and executable signatures are program code;
ordinary Python/JS/Rust/etc. is not call-analyzed. Program-code files are aggregated
per plugin directory, skill directory, or nearest package root (recognized package
manifest or Python `__init__.py`). Loose scripts without a load root remain
individual entries. Each aggregate has `load_root`, `file_count`, and up to five
`samples`; `path` is its representative first file. This is file enumeration, not
a per-call warning or inferred execution. Distinct classifications of one
execution surface are retained in `kinds`, not charged as separate invocations.
The 256-invocation cap counts distinct surfaces/load roots independently for each
selected project and each other owning region (plugins, skills, shared inputs,
etc.). One project cannot consume another project's or the plugins' slots.
`scope.limits.invocation_roots` discloses admitted counts, cut counts and the cap
for each budget owner; unbounded sets each cap to null. A cut marks the
owning region unknown, not unrelated project, dynamic or isolation regions;
complete inventory therefore requires the owning regions to be verified too. Unknown file types (including
unrecognized extensionless DSLs), unsupported text encodings and odd encoding
cookies fail closed in their owning region, with counts and capped samples.

Execution surfaces include build/task/dependency manifests, environment loaders,
VCS hooks, CI workflows, schedulers, application configuration and implicit-load
plugin/hook modules. Inventory entries contain a file, trigger, fixed descriptive
kind and `resolution: enumerated`; command bodies are not persisted. File-level
inventory does not claim to resolve dynamic registrations or computed paths.

Literal outward paths in program code and documentation are blending evidence;
only the path and source line are retained, not the surrounding prose. Missing
paths beneath registered unselected roots remain declaration-only edges. Other
code/prose references must identify existing local objects under the inferred home
or registered roots; arbitrary OS paths in example code are not traversal authority.
Local `file:///` and `git+file:///` references are decoded without executing them;
remote file authorities are not treated as local paths. Credential
configuration is parsed before extracting references: secret keys, arbitrary map
labels and environment values are not raw-scanned. Environment-loader files expose
only allowlisted execution-path keys. `.envrc` also follows literal `source`,
`source_env`, `dotenv` and dot-source targets; `.npmrc` follows `pnpmfile`,
`globalconfig`, `userconfig` and `init-module` targets. Sensitive key/value
filtering precedes path extraction, including JSONC workspaces. Command arguments
after credential-like flags (including `-p`) and sensitive `KEY=value` arguments
are withheld, including in sibling declarations. Relative globs/placeholders
never gain an absolute prefix by substring matching. Paths are never shell-expanded.
Hardlinks are disclosed without changing coverage; matching links found among
inspected files create edges. An unmatched link count discloses unknown targets,
not a claim that the other link is definitely outside the tree.

Git discovery handles enclosing repositories, `.git` pointer files, `commondir`,
shared/worktree configs, includes, and hooksPath. Global `.gitconfig`, the audited
HOME's XDG Git config (custom XDG_CONFIG_HOME only when inside that HOME), and
`/etc/gitconfig` are included. External Git directories/hook directories are blending
edges. Git-context directory edges inspect pointers/config/hooks, not object stores;
this limited scope is disclosed. All include/includeIf targets are metadata-only
and never opened or recursively parsed; hooksPath candidates outside credential
stores are inspected. Activation/precedence is not claimed resolved.
Conditional activation remains dynamic uncertainty. Extensionless hooks are
classified as dynamic invocations even without an executable bit. Git configs
are identified by discovery role or section grammar, independent of filename.
Every key is parsed; only explicit inert keys remain verified. Executing keys
(including fsmonitor, SSH/editor/pager commands, shell aliases, filter/diff/merge
drivers, credentials, gpg programs and hooks) are enumerated dynamic invocations.
Unknown keys and include conditions remain `could_not_verify`.

`pyvenv.cfg`, `.python-version`, `.nvmrc`, `.node-version`, `.tool-versions`, and
Rust channel declarations resolve against standard installation-directory metadata
under the inferred owning home: pyenv, nvm, rustup, uv, and asdf. Ambiguous/missing
versions remain unknown. Resolved edges explicitly say `directory_metadata_only`;
no interpreter or toolchain binary runs, and unrelated installation content is not
read.

## Sessions and credentials

JSON/JSONL session associations match cwd within a selected root using a path
boundary, or an exact `git_repo_root`. The outward metadata-only SQLite
association collector reads user databases in place through `open_readonly_sqlite`
under **User SQLite databases** above and never creates temporary DB/WAL copies.
Open WAL writers with an existing `-shm` are read in place; mid-read DB/WAL
changes retain the measured rows, set `changed_during_read: true`, and mark the
owning region uncertain; `wal_needs_index`, hot rollback journals, busy/locked
stores, corrupt files, and unknown schemas yield owning-region uncertainty.

SQLite magic (`SQLite format 3\0`), not just extensions, selects database
inspection. Returned query result bytes (not physical database file size) count
against the region's byte budget, and SQL execution is bounded by a 100 ms busy
timeout, a VM step budget, and cooperative cancellation.
Schemas, not filenames, classify Hermes sessions, projects/project_folders,
kanban tasks/attachments, response-store tables, and Defuzz state. Allowlisted path
and timestamp columns are inspected; message/response bodies are not read. Response
stores disclose schema-only inspection because their schema has no project-path
columns. Historical associations never authorize opening unrelated projects.
The shared `<default-profile>/kanban.db` is inspected even for named active
profiles. `report.database_records` discloses task/project/folder associations;
IDs, titles, tenants and assignees use ephemeral per-run HMACs, not raw values.
Task workspace declarations create `kanban_task_workspace` edges; unrelated
workspaces are declaration-only, not implicitly traversed. This association reader
does not return task bodies; the separate `kanban_residue` component evaluates body
lengths and fixed markers inside SQLite and returns aggregates, not text.
Selected projects' `projects.db` registered folders are `registered_project_folder`
edges and project-owned roots: this follows `hermes_cli/projects_db.py`'s
`create_project`/`add_folder` registration semantics. Unselected registered roots
remain unvisited unless reached through blending, and uncertainties there belong
to `other_projects`. Session queries select matching projects; results are fetched
in 1,000-row pages.
Default row budget is 10,000, with page counts/truncation disclosed in
`scope.limits.databases[path]`; unbounded removes the row budget.

### Allowlist persistence (evidence JSON v3)

File-content strings do not acquire persistence permission by looking harmless
or by failing to match a credential regex. `audit.evidence.EvidenceSerializer` is
the common evidence boundary for outward results, DTOs, complete report payloads
and canonical report bytes. Raw content, surrounding source text, command bodies
and parser exception messages are never report fields.

An evidence string is retained literally only when it is an untainted member of
the closed scalar enum/rule/trigger vocabulary defined in code (schema keys are
approved only as keys), when it is a code-emitted structural value, or when the
field is a declared path field. Structural fields are one reviewed table in
`audit.evidence`: a leaf name whose every value is chosen from a closed token
set, or, when that leaf name is also used for a string read from the home
(`source`, `name`, `kind`, `value`, `scope`, `board`), an end-anchored key path
with that path's own token set. A structural field keeps only a token in its
set; any other string is user data and stays taint-first. Fixed sentences are
never matched against taint. A tainted vocabulary word in a user-data value is
tokenized as `credential_overlap`. The table does not grant that exemption to
config values, names, paths, command arguments or message-derived text. A
declared path field (`_PATH_FIELDS`, project unit identities, command
`executable`, or path-keyed maps `_PATH_KEY_MAPS`) is retained when resolving
its path and calling `lstat` on the result succeeds without taint overlap, and
without a recognizable credential token in any path segment. A segment that
contains a supported provider token (`sk-`, `AKIA`/`ASIA`, GitHub
`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`, Slack `xox[baprs]-`, or a
three-part `eyJ` JWT), with a non-alphanumeric boundary before the prefix and
at least the provider's minimum length, is not printed and is not rewritten
into an invented path. The field is withheld as `path: null` with
`path_withheld: "credential_in_name"`. The same gate covers location paths,
path-keyed map keys, command executables, identities derived from paths, and
sealed-value revalidation. The matched token is registered with the run's
taint so that same string is sealed wherever else it appears. Ordinary names
(`sk-learn-notes`, `ghp-pages`, hex digests, UUIDs, long build folders) stay
readable. Path-shaped
strings in non-path fields are sealed like any other user string. Paths are emitted as resolved absolute
paths, including paths outside inspected roots; permission to report a path does
**not** authorize traversing it. A symlink source therefore uses its resolved
spelling, not its original lexical alias. Missing paths are not printable paths.
Manifest `files` keys may retain unit-relative spelling only after resolution
against the manifest root confirms an existing path.

Other strings become:

```json
{"kind":"unresolved_reference","hmac":"<64 hex characters>",
 "location":{"path":"/existing/source.py","line":12}}
```

`kind` is `text`, `unresolved_reference`, `argument`, or
`credential_overlap`. The HMAC uses an ephemeral random key, never persisted.
Equal values within one serialization run have equal handles; separate runs are
intentionally unlinkable. Content DTO summary digests use the same per-run HMAC
policy; installed engine/template identities are hashes of code artifacts, not
inspected user content.

**Durable key and threat model:** cross-run content comparisons and SQL queue/cache
indexes use one private 32-byte random `audit.key` next to the plugin audit database
(in the active profile's plugin data directory; an explicit database uses its own
parent directory). Creation uses `O_EXCL`, mode `0600`, and a writer/read lock so
concurrent processes do not consume a partial key. The key is never logged,
returned, or saved in SQLite. Content file hashes and tree aggregates are
`HMAC(key, "content\\0" + sha256)` rather than printable unkeyed content hashes;
control identities use a separate domain with that same durable key. These
handles remain comparable across restarts, but only within the same key domain.
A database-only reader cannot confirm a low-entropy candidate file by hashing it.
An attacker who can read both the key and database can perform dictionary tests;
this is data minimization, not encryption or protection against same-user code
execution. Stable handles also intentionally reveal equality across saved runs.

Explicit resume matches saved controls against freshly enumerated registrations,
never against display IDs, and preserves the original `as_of`. Missing or corrupt
key material is replaced; old runs (including pre-durable-key runs) remain readable
but are non-resumable with the closed reason `audit_key_unavailable`. Start a new
run to recapture them. Non-regular key paths (including directories, FIFOs and
symlinks), permission failures and key-lock failures are not repaired or deleted:
resume returns `resume_reason: audit_key_unavailable`; new audits return
`status: failed, reason: audit_key_unavailable` before source capture. Saved status
and reports do not require loading the key and remain readable. Resolve the key
path problem before starting a new run; directory contents are never removed.

The component-only captured file map recomputes ordinary SHA-256 from captured
bytes for scaffold `locked_hashes` comparisons. That map, like the captured bytes,
is memory-only; the manifest retains keyed handles. Ordinary comparison hashes
are not privileged digest values and are sealed if included in findings. This
preserves unchanged/changed template checks without exposing raw content hashes
in reports, SQLite columns or dumps.

No decoder or raw-value table is stored. Source path
and line are attached when available; `null` explicitly means the adapter did not
supply that location, rather than an invented line number. Unknown map labels use
`hmac:<64 hex characters>` keys. Fixed report keys are never taint-redacted.
Project budget maps now use resolved project paths as keys, without `project:`.

URLs emit `{kind:"url", scheme, host, port, hmac, location}`; userinfo, password,
path, query and fragment are dropped. Credential endpoints emit only
`{scheme, host, port}`, with null/omitted components for absent or wildcard data.
They are descriptive metadata, not network calls or trust decisions.

**Exact-match residual:** a credential value that is also an existing filename
or a hostname label can be reported as that filename/host. Taint checks compare
whole canonical values, not arbitrary substrings of allowed paths or hosts.
For example, a secret basename inside an existing absolute path, or a secret
label inside a longer DNS hostname, is not removed. An exact tainted full path
or host is withheld. This avoids corrupting unrelated paths through substring
matches; it is a deliberate residual, not a guarantee of zero substring overlap.

Recognized structured command declarations add `commands` to the corresponding
invocation. Each command has `{kind:"command", executable, argument_count,
arguments, hmac, location}`. `executable` is an existing resolved local path or
null. Bare executable lookup only checks PATH; it never invokes the tool.
`arguments` contains one HMAC evidence object per argument, including flags.
Shell parsing does not claim that aliases, interpolation, pipes or computed
execution have been resolved. Other execution surfaces retain file/trigger/kind
inventory without claiming detailed argv extraction.

Credential candidates (`audit.policy.credential_path`, sharing the name-pattern and
expected-store tables of `audit.secret_file_copies`) include `.env*`/`*.env`/`.envrc`,
`.npmrc`/`npmrc`, `.pypirc`, `.netrc`, `.pgpass`, `.git-credentials`,
`.docker/config.json`, `pip.conf`, `auth.json`/`*auth*.json`, `*oauth*.json`,
`*service-account*.json`, `*firebase-adminsdk*.json`, `*token*.json`/`*tokens*`/`token`,
`*secret*`, `*api_key*`/`*apikey*`/`*api-key*`, `credentials*`, Hermes expected token/OAuth/vault/cache
stores (such as `shared/nous_auth.json`, `bws_cache*.json`, `op_cache.json`,
`photon-sidecar.json`, `.copilot_jwt.json`, `google_*_token.json`, `google_*_client_secret.json`,
and their backup copies), `id_*`/`.ppk`, PEM/key-stem `.key` files, PKCS#12 (`.p12`/`.pfx`),
keystores (`.keystore`/`.jks`), `kubeconfig`, Terraform variable/state files (`.tfvars`/`.tfstate`),
and declared credential paths, while keeping `DECLARATION_SOURCE_FILES`, public certs/keys,
example/sample/template/dist placeholders, non-secret token vocabularies (`tokenizer.json`, etc.),
and source/documentation files readable. Every classified credential
store is excluded from content capture in full and quick modes. Records contain
only `kind: credential_store`, path, size, mode (POSIX permission bits) and mtime
from lstat; existing resolved paths remain subject to the persistence allowlist
(and `home_workdirs` withholds secret-named entries with `path: null` and
`path_withheld: "credential_named"`).
Symlinks are not followed. No endpoint, key-label or fingerprint metadata is
derived from contents. Coverage is `credential_store_not_opened`; execution
keys in credential stores are not inspected either.

The ephemeral taint guard is defense in depth, not the persistence policy. Key
matching requires complete credential segments such as `api_key`, `apikey`,
`access_key`, `secret`, `password`, `passwd`, `token`, `private_key`,
`client_secret`, `auth_token`, `authorization`, `bearer`, `cookie`,
`session_secret`, or `credentials`; `keys`, `tokens`, `tokenizer`
and `author` are not credential keys. URL userinfo includes empty usernames.
Case, percent-encoding and slash aliases are observed only in memory. Actual
outgoing credential-overlapping path values are tokenized and counted in their
source region as `evidence_redacted_due_to_credential_overlap: N items`.
Rejecting a source candidate is not a schema redaction and does not manufacture
an overlap disclosure. Schema labels and code-generated statuses are never
matched against taint. Canonical report digests are computed after serialization.

AuditStore's queue/run IDs and collector names are separate operational control
inputs, not arbitrary evidence containers. Source values in DTOs, findings,
source paths and complete reports still cross the allowlist. Cache indexes are
generated control digests, not raw source fingerprints. Generated metadata and
already serialized DTO JSON are explicitly typed at the SQL binding boundary;
untyped JSON bindings use the evidence serializer. Consumers must not interpret
a token-shaped dictionary read from a file as an already-authorized token.

## Known credential-boundary limitations

The strict rule is that credential files and every path declared by a fixed declaration source are never opened. There are five edge cases where the audit can still **open or list** a declared path. Adversarial testing of this release found the first four; no credential content reached reports or the audit store in any of them. Case 5 is a race window: a file must be replaced in the instant between two steps. All five are accepted as known limitations, not fixed:

1. A declaration of the Defuzz registry (`plugin-data/defuzz/state.db`) made from an **installed template's** `config.yaml` is discovered after the registry header is read. Profile, sibling and project declarations of the registry are honored (`could_not_verify`, `credential_store_not_opened`).
2. With **overlapping declarations** (a directory plus a path nested inside it), full mode can open the declared parent directory itself. Its contents are not read.
3. A declared **installed templates root** is still listed (directory enumeration) by the template loader. Files inside it are not read.
4. Template discovery can **list** a template directory that one of its own or a later template's declaration sources declares. Files inside it are not hashed or read.
5. SQLite opens a user database by its path after the audit has checked the opened file; a declared database put in place between the two opens can be read by SQLite (`mode=ro` and `immutable=1` do not prevent this); the identity check after the read catches it only while the swapped file is still in place.

Directory listing reveals names only, never file contents.

## Coverage and desktop JSON contract

`report.scope.regions` retains these keys:

- project_tree, active_profile, skills, plugins, session_history, identity
- credentials, shared_infrastructure, sibling_profiles, other_projects
- dynamic_execution, cross_project_isolation

Each value is `{coverage, reasons, scope, limitations}` plus optional `reason_details`
and hardlink `disclosures`.
Reasons are deduplicated by fixed reason code in O(1); details give `{code, count,
samples}` with at most three examples. Unknowns belong to the file/path's owning
region, not all regions. Program behavior is a disclosed limit, not a per-file
uncertainty. Known JSONC, lockfile, workflow, provenance and
test-fixture data formats are classified and parsed; malformed input stays unknown.
`template.yaml`/`template.yml` alone never establish an inert data role. Azure
pipeline `template:` references identify CI inputs and are followed; unclassified
templates fail closed. Explicit `extends`/`extend` config inheritance (including
Biome, ESLint, Ruff, Prettier and Babel structured declarations) is followed for
literal relative/absolute refs; module aliases and unsupported declarations are
disclosed as unresolved rather than guessed. Programmatic config behavior remains
outside static inventory.
Config path globs are expanded with no symlink-directory descent and a disclosed
10,000-entry default traversal limit (removed by unbounded). MCP command/argument
paths, package file/link/workspace dependencies, UV/Cargo path dependencies,
workspace folders, Go replacements and TS references/path mappings are followed.
Workspace aliases resolve by package name against uniquely named, already
inspected members of the nearest declared workspace, independent of traversal
order. No directory-name guessing or package-manager execution is used. Missing or
ambiguous aliases remain unknown. Dynamic path expressions and unknown file types
fail closed. Known config formats are parsed and inventoried, not behavior-checked
against a universal key allowlist; unknown Git keys still fail closed. All truncated captured content is unknown, regardless of filename.
`verified` requires positive classification of inspected executable/config-like
items within the declared scope, **not** runtime safety or inspection of unrelated
trees. Explicitly classified data assets are data-only, not execution approval.
Failures and unsupported semantics are `could_not_verify`; nonapplicable scope
may be `not_applicable`. Separate vendor/component checks still determine their
own verification and headline findings.

```json
{
  "scope": {
    "description": "Project-outward full static audit",
    "coverage": "could_not_verify",
    "regions": {
      "project_tree": {"coverage": "verified", "reasons": [], "scope": "..."}
    },
    "limits": {
      "max_entries": 1000000,
      "max_total_bytes": 68719476736,
      "max_file_bytes": 8388608,
      "unbounded": false,
      "regions": {
        "/selected/root": {
          "name": {"kind":"text","hmac":"<64 hex characters>","location":{"path":null,"line":null}},
          "max_entries": 1000000,
          "max_bytes": 68719476736,
          "max_file_bytes": 8388608,
          "entries_inspected": 0,
          "bytes_read": 0,
          "stream_hashed_files": 0,
          "cuts": []
        }
      },
      "parent_context_boundary": "/selected/root",
      "parent_context_boundaries": {"/selected/root": "/selected/root"},
      "unrelated_siblings": "config.yaml declarations only; unrelated content not inspected"
    }
  },
  "blending": [
    {
      "source": "/profile/profiles/sibling/config.yaml",
      "target": "/selected/root",
      "relationship": "incoming_sibling_reference",
      "evidence": {"path": "/profile/profiles/sibling/config.yaml", "kind": "incoming_sibling_reference"}
    }
  ],
  "credentials": [],
  "dynamic_invocations": [],
  "session_history": {"records_inspected": 0, "selected_project_records": 0, "newest_selected_timestamp": null}
}
```

This is a shape example, not measured output. Limits also include aggregate
counters, depth, edge/invocation and normalization limits, report-store exclusions,
and credential scope. The per-budget map contains every selected project,
`home_startup`, `active_profile`, and `sibling_declarations`. `cuts` discloses which bound was hit
and its path where known. SQLite query I/O is not included in stream byte counts.

## Effective limits and controls

CLI: `--max-entries N --max-bytes N --max-file-bytes N`, or `--unbounded`.
API: positive integer `max_entries`, `max_bytes`, `max_file_bytes`; boolean
`unbounded`. Invalid types/values are rejected; saved options survive resume.
Defaults per root are 1,000,000 entries, 64 GiB streamed bytes, 8 MiB parsed content
per file. Large files are stream-hashed rather than silently skipped; any
file exceeding the parse limit leaves its semantic coverage unknown. Content is
parsed only for recognized relevant formats. Unbounded removes collector entry,
byte, parse, depth, edge, invocation, YAML normalization, glob, toolchain-inventory,
Git-discovery and database-row caps. Effective numeric caps are null in the JSON
contract. Ordinary mode retains depth 128, 256 report edges/invocations, 10,000 YAML
nodes/depth 64, and 10,000 inventory/glob/session rows. Git discovery has separate
config/edge/depth/byte limits disclosed in `scope.limits.git_discovery`. Natural
OS/interpreter resource limits and mutation/read errors still fail closed.
Component-capture limits remain separate and are sourced from fingerprint constants.

Apart from the analysis components' shared budget described above, there is no
whole-audit wall-clock timeout. Full profiles may take minutes. The
opt-in session-contamination component has its separate 20-second cooperative
budget above. The quick path retains the fixed-file profile check and reports
partial coverage.

## Regression and performance evidence

`tests/test_audit_outward_gaps.py` asserts the outward collector's handling of
parent contexts, execution fallthrough, credential patterns, project-independent
budgets, incoming siblings, descriptor-relative read guards, sessions and toolchains.
The end-to-end surface fixture uses a real sibling profile, SKILL.md, plugin manifest
and SQLite session records, and scans the persisted report store for a secret canary.

The scale benchmark (size `N`) uses a fixed synthetic tree: 37.5% Python
files importing `os`, `json` and `pathlib` with 30 functions, 4.8% JSON,
remaining data, plus N/64 symlinks and N unrelated SQLite session rows. A selected
session is committed into an open WAL writer; listing stability and selected-row
visibility are checked. Fixture creation is excluded from collector timing.
Repeated source content is deliberate; timings are not a promise for unique large
source files or slow network disks. Python AST parsing extracts literal paths only,
never behavioral classifications.

Outward edge cases are covered by `test_audit_outward_edge_cases.py`,
`test_audit_outward_end_to_end_canary.py` and `test_audit_outward_kanban_projects_db.py`,
with additional fail-closed Python/Git/database/classification/path-reference tests.
Inventory contract probes are in `test_audit_outward_inventory_contracts.py` (numbered
probes). They require exact inventory paths, blending edges or owning-region
uncertainty; the ordinary benign control retains verified coverage. Local Python
calls and shell files are inventoried without a behavior allowlist.
`test_audit_workspace_resolution.py` covers unique member resolution and ambiguity.
The session-history regression ensures historical JSONL paths do not create live
blending edges. Performance fixtures use known text data, not unknown extensionless
files whose semantics cannot be classified.

# Secret File Copies and Misplaced Secret-Named Files (`report.secret_file_copies`)

## What It Measures

`audit.secret_file_copies.audit_secret_file_copies(profile_path, *, clock=time.monotonic, max_entries=400000, max_depth=40, max_seconds=15.0)` inspects a Hermes home (and its `profiles/<name>` subdirectories) **by file name and `os.lstat` metadata only**. It never opens, reads, hashes or resolves any file or symlink.

1. **Expected secret files (`expected_secret_files`)**: counts by kind of files at the places the Hermes source keeps secrets. No paths, sizes or contents are reported. The list comes from the writers and from `PROFILE_CREDENTIAL_PATHS` (`hermes_cli/profiles.py:159-187`). Paths are relative to the home root and to each `profiles/<name>` root:
   - `dotenv`: `.env` (`hermes_constants.py:1279-1281`), `.op.env` (`hermes_cli/env_loader.py:221,496`), `.envrc` (`hermes_cli/profiles.py:153-154`, `agent/file_safety.py:339`).
   - `auth_json`: `auth.json` (`hermes_cli/auth.py:479-501`).
   - `shared_auth`: `shared/nous_auth.json`, **at the default root only**. This is the Nous OAuth store that every profile shares (`hermes_cli/auth_nous.py:346-365`, `hermes_cli/auth_commands.py:330-332`, `hermes_cli/install_state.py:356-359`). A `profiles/<name>/shared/nous_auth.json` is not a Hermes location and counts as a work-folder file. A `HERMES_SHARED_AUTH_DIR` override cannot be seen from files.
   - `credentials_store`: root `credentials.json` and `credentials/` (`hermes_cli/models.py:1945-1948`, `gateway/platforms/base.py:784-785`, `hermes_cli/web_routers/files.py:85`).
   - `mcp_tokens`: `mcp-tokens/` (`tools/mcp_oauth.py:229-233,412-434`).
   - `pairing`: `pairing/`, `platforms/pairing/`, `feishu_comment_pairing.json` (`gateway/pairing.py:58-59`, `hermes_cli/profiles.py:176`).
   - `vault`: `vault/` (`agent/vault_store.py:208-220`, `agent/file_safety.py:364-366`).
   - `platform_token_stores`:
     - root files: `slack_tokens.json`, `webhook_subscriptions.json`, `teams_pipeline_store.json`, `honcho.json`, `mem0.json`, `npmrc`, `.npmrc`, `.netrc`, `bws_cache.json`, `bws_cache.enc.json`, `op_cache.json`, `photon-sidecar.json`;
     - legacy cache copies: `cache/bws_cache*.json`, `cache/op_cache.json`, `runtime/photon-sidecar.json`;
     - `workspace/meetings/node_token.json`;
     - store folders: `weixin/accounts/`, `whatsapp/session/`, `platforms/whatsapp/session/`, `matrix/store/`, `platforms/matrix/store/`, `webapp/`, `proxy/`.
     - Sources: `plugins/platforms/slack/adapter.py:6529-6534`, `gateway/webapp_listener.py:32`, `hermes_cli/webapp_sign_in.py:52`, `hermes_cli/home_data_layout.py:11-18`, `hermes_cli/profiles.py:167-171,174,177-182`.
   - `oauth_stores`: `.anthropic_oauth.json`, `auth/google_oauth.json`, `google_token.json`, `google_oauth_pending.json`, `google_client_secret.json`, `google_chat_user_*`, `.copilot_jwt.json` (`agent/credential_sources.py:160-165`, `hermes_cli/profiles.py:160-166,181`).
   - `browser_and_home_stores`: the browser-login trees `browser-profile/`, `browser_auth/`, `bot-desktop/`, `browser-profiles/`, `browser_profiles/` and `chrome-debug/`, plus the subprocess HOME `home/` (`hermes_cli/profiles.py:174-175,183-184`, `hermes_constants.py:703-709`, `hermes_cli/browser_connect.py:837`). Only secret-named files there, and every file under an OS credential folder inside `home/`, are counted. Other files in these trees are ignored. They are not counted and their modes are not checked.
   - `os_credential_dirs`: every file under `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`, `.docker/`, `.azure/`, `.config/gh/` and `.config/gcloud/` (`agent/file_safety.py:211`, `hermes_cli/profiles.py:153-154,186`).
   - Files Hermes writes whose names only look secret are never counted: `cache/oauth_heal_clean.json` (`hermes_cli/auth_oauth_grants.py:305,319`), `cache/image_token_costs.json` (`agent/image_token_cost.py:39`, `agent/model_metadata.py:154-156`) and `cache/platform-ca-bundle.pem` (`agent/ssl_verify.py:278`).
   - `*.lock` files (`auth.lock`, `shared/nous_auth.lock`, `vault/.vault.lock`) are never counted.

2. **Backup copies of expected secret files (`backup_copies`)**: files next to a store (home or profile root, `shared/`) or inside backup folders (`backups/`, `.curator_backups/`, `state-snapshots/`, `checkpoints/`). A file counts when its name is a store name plus a backup suffix (`.bak*`, `.orig`, `.old`, `.pre-*`, `.before*`, `.save`, `~`, `-backup*`, `.codex-backup-*`, a date), a store name with a backup marker before the extension (`auth-before-*.json`), or an exact store name inside a backup folder. For each copy the module reports `secret_kind`, `scope` (`home` / `profile` / `backups`), the boolean `same_size_as_live`, and the UTC `year` and `month` of the file's mtime as integers (`null` when the mtime is unusable). The date comes from the file, never from the clock. **Sizes of secret files are never output.**

3. **Secret-named files outside those places (`secret_named_files`)**: files outside the expected places, outside nested fixture homes and outside vendored package trees whose names match a pattern class:

   | Class | Patterns |
   | --- | --- |
   | `dotenv` | `.env`, `.env.*`, `*.env`, `.envrc` |
   | `oauth-json` | `*oauth*.json` |
   | `service-account-json` | `*service-account*.json`, `*service_account*.json` |
   | `auth-json` | `auth.json`, `*auth*.json` (except `author*` words) |
   | `token-json` | `*token*.json` |
   | `tokens` | `*tokens*` |
   | `credential` | `*credential*` |
   | `secret_word` | `*secret*` (except `secretar*` words) |
   | `api-key` | `*api_key*`, `*apikey*`, `*api-key*` |
   | `pem` | `*.pem` |
   | `key` | `*.key`, only when a word of the stem is key vocabulary (`private`, `server`, `tls`, `master`, `vault`, …; `KEY_STEM_WORDS`) or the stem is dotted like a host name |
   | `ssh-key` | `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `*.ppk` |
   | `pkcs12` | `*.p12`, `*.pfx` |
   | `keystore` | `*.keystore`, `*.jks` |
   | `netrc` | `.netrc`, `.pgpass` |
   | `npmrc` | `.npmrc`, `npmrc`, `pip.conf` |
   | `pypirc` | `.pypirc` |

   The section reports:
   - `count` and `by_pattern_class`;
   - `by_top_level_folder`: a list sorted by `path`, one row per top-level folder holding such files: `path` (the absolute path of the existing top-level folder inside the audited home; files directly at the home root are attributed to the home root path itself), `count`, and `classes` (pattern class label -> count);
   - `top_level_folder_count`: the number of rows in `by_top_level_folder`;
   - `plugin_dotenv_count`, `plugin_folders_with_dotenv` and `plugin_folder_count` for `.env`-style files in `plugins/` and `desktop-plugins/` (also under `profiles/<name>/`). `plugin_folders_with_dotenv` lists the absolute paths of the plugin folders (`<home>/plugins/<name>`), never the path of the `.env` file;
   - `example_locations`: up to 20 distinct objects `{path, class}`: the absolute path of the top-level folder (or the home root) and the pattern class label. No basename, no deeper directory and never the path of the secret-named file itself is output.

   Files that third-party plugins write (for example a plugin's own `thirdparty-auth.json` at the home root) are not known to the audit as expected stores, so they are counted here.

   The only strings in the section that are not fixed vocabulary are these absolute folder paths: `by_top_level_folder.path`, `example_locations.path` and the values of `plugin_folders_with_dotenv`. The report's evidence serializer keeps these because they are declared path fields, and only when the path resolves to an existing item (it stores the resolved form). A path or label that overlaps a credential value read in the same run is sealed as a `credential_overlap` token, even when it equals an ordinary word. Raw measurements are the same for an unchanged home within budgets. The sealed output is unchanged only while every kept path still resolves and no value overlaps a credential value read in the same run; otherwise it holds tokens keyed per run, which differ between runs. The module itself only joins strings: it never resolves a path.

4. **Mode bits (`mode_bits`)**: `readable_by_others_count` is the number of counted secret files whose mode has any group or other bit set (`mode & 0o077`). Mode bits only mean something in a home whose files carry different modes. `mode_check` is `could_not_verify`, with `readable_by_others_count: null` and no finding, in any of these cases:
   - no file anywhere has a group or other bit (`no_group_or_other_bits_anywhere`). This is what an archive extraction to owner-only modes produces. It is also what a strict `umask 077` produces. The module cannot tell these apart, so it claims neither exposure nor safety;
   - every file is `0777`/`0666` (`all_files_permissive`, a FAT/NTFS mount);
   - every file has one identical mode (`uniform_mode`).

   `mode_check_reason` is `null` when the check is verified, and `not_measured` when the home could not be walked.

5. **Config backup copies (`config_backups`)**: counts of these files, plus bursts (`>= 3` copies whose mtimes fall within 60 s in the same home or profile), with `reason: "configs_may_embed_keys_not_read"`:
   - `config.yaml.bak*`, `.pre-*`, `.before*`, `.old*`, `.orig*`, `.save*`, `.corrupt*`, dated `config.yaml.*`, and `config.yaml~` at a home or profile root (including `profiles/.deleted/`);
   - any file in `backups/config/` (`hermes_cli/config_backups.py:21-27`).

   Copies under `profiles/<name>/` and `profiles/.deleted/` count as `profile_count`.

6. **Nested fixture homes (`fixture_homes`)**: `fixture_home_count` is the number of *outermost* directories below the profile root that are shaped like a Hermes home. A directory counts if:
   - it is named `.hermes`;
   - or it holds `SOUL.md` or `profile.yaml`;
   - or it is a nested `profiles/<x>` with a home marker;
   - or it holds `config.yaml` plus one more home signal.

   `note` is the fixed sentence: "Counted apart from work folders because names alone cannot tell test values from real secrets; the audit opened no file."

   The real `profiles/<name>` folders do not count. Under `plugins/`, `skills/`, `backups/` and `shared/`, only folders named `.hermes` count. A home-shaped directory inside a counted one is not counted again. `fixture_profile_dir_count` counts every home-shaped directory, nested ones included. Secret-named files inside counted fixture homes are counted here and not as work-folder files.

7. **Symlinks (`symlinks`)**: `symlinks_skipped` counts every symlink. `secret_named_symlinks` counts the symlinks whose *own name* matches a pattern. A link is never followed, and its target is never read (no `os.readlink`, `realpath` or `stat`).

## Fixture-home count (one sentence)

The count is the number of outermost home-shaped directories as defined above.

## Thresholds

| Constant | Value | Purpose |
| --- | --- | --- |
| `BACKUP_COPIES_WARNING_THRESHOLD` | `1` | Any copy of a store is an exposure item (`warning`). |
| `WORK_FOLDER_SECRET_FILES_WARNING_THRESHOLD` | `1` | Any secret-named file outside the store places (`warning`). |
| `FIXTURE_HOME_SECRET_FILES_THRESHOLD` | `1` | `review_suggested`, because names cannot tell test values from real ones. |
| `PLUGIN_SECRET_FILE_THRESHOLD` | `1` | `review_suggested`. |
| `READABLE_BY_OTHERS_WARNING_THRESHOLD` | `1` | `warning`, emitted only when `mode_check` is `verified`. Hermes writes its stores with mode `0o600`. |
| `CONFIG_BACKUP_INFO_THRESHOLD` / `CONFIG_BACKUP_REVIEW_THRESHOLD` | `1` / `5` | 1–5 copies give `info`; more give `review_suggested`. Basis: `DEFAULT_KEEP = 5` (`hermes_cli/config_backups.py:22`). |
| `CONFIG_BACKUP_BURST_MIN_FILES` / `CONFIG_BACKUP_BURST_WINDOW_SECONDS` | `3` / `60.0` | Copies written within a minute of each other. |
| `MAX_ENTRIES` / `MAX_DEPTH` / `MAX_SECONDS` | `400,000` / `40` / `15.0` | Bound the walk; a cut marks the section `could_not_verify`. |

## Name-pattern precision and recall

Both lists are in `tests/test_audit_secret_file_copies.py` (`INNOCENT_NAMES`, `SECRET_LIKE_NAMES`). They are a regression gate, not a held-out estimate.

| | Innocent names left unflagged | Secret-like names flagged |
| --- | --- | --- |
| Current rules | 52 of 52 | 49 of 49 |

Known remaining misses and false hits that come from matching by name:
- a private key with a plain stem (`mysite.key`, `session.key`) is missed;
- bare `jwt.txt` and `bearer.txt` are missed;
- design-system `tokens.json` is flagged;
- report files such as `credential-scope-verification.json` or `*-auth-summary.json` are flagged;
- auth stores that third-party plugins write (such as a root `thirdparty-auth.json`) are flagged, because the audit only knows the stores the Hermes source writes.

## What It Cannot Tell

The module never opens a file, so it cannot tell:
- whether a file named `.env`, `auth.json` or `discord-auth.json` holds a live credential, an expired one, a test placeholder, or a report whose name happens to contain `auth`;
- whether a `config.yaml` copy holds keys inline;
- where a symlink points;
- whether owner-only modes everywhere come from an extraction tool or from a strict umask.

Each finding's consequence sentence states what was matched and that no file was opened.

## Do-Not-Flag List

- Expected secret files at the places listed above.
- Names that contain a template word (`EXAMPLE_NAME_WORDS`: `example`, `sample`, `template`, `tmpl`, `tpl`, `dist`, `defaults`, and their plurals). Examples: `.env.example`, `.env.dist`, `.env.defaults`, `credentials.example.json`, `secrets.template.yaml`.
- Public material (`EXAMPLE_AND_PUBLIC_EXCLUSIONS`):
  - `*.pub`, `*.crt`, `*.cer`, `*.csr`;
  - CA bundles: `cacert.pem`, `*ca-bundle*`, `ca-certificates*`, `chain.pem`, `fullchain.pem`;
  - `debug.keystore`.
- Token names that are not stores (`TOKEN_NAME_EXCLUSIONS`): `tokenizer*`, `special_tokens_map.json`, `added_tokens.json`, `tokens.css`, `tokens.txt`, `design-tokens*`, `*token_count*`, `*token_usage*`, `*token_cost*`, `*.tokens.json`.
- `secretary`/`secretaries`/`secretariat` and `author`/`authority` words.
- Keynote-style `.key` files whose stem has no key word (`turkey.key`, `Q3 Review.key`).
- Anything inside vendored package trees: `site-packages`, `dist-packages`, `node_modules`, `bower_components`, `_vendor`, `certifi`. This covers files such as `test.pem` and `cacert.pem` there.
- Source, documentation, lockfile, log and media suffixes (`NON_STORE_SUFFIXES`: `.py`, `.ts`, `.md`, `.png`, `.lock`, `.log`, …).
- macOS AppleDouble stubs (`._*`).

## Findings (rule id, classification, evidence keys, consequence)

- `secret_file_copies.backup_copies_of_secret_files`: `warning`; evidence `count`, `same_size_as_live_count`.
  > Files named as copies of a Hermes secret store (such as .env.bak-*, auth.json.old, or a store's name inside a backups folder) were counted next to the live stores or in backup folders. The audit matched file names and lstat metadata only and did not open any file, so it cannot tell whether a copy holds a working secret, an expired one, or none.
- `secret_file_copies.secret_named_files_in_work_folders`: `warning`; evidence `count`, `folder_count`, `class_count`.
  > Files whose names match secret-store patterns were counted outside the places the Hermes source keeps secrets. The audit matched file names only and did not open any file, so it cannot tell whether any of them holds a real secret; a copy, sync or share of those folders includes them. Files that third-party plugins write are not known to the audit as expected stores and are counted here.
- `secret_file_copies.secret_named_files_in_fixture_homes`: `review_suggested`; evidence `count`, `fixture_home_count`.
  > Secret-named files were counted inside nested directories shaped like a Hermes home below the profile root. The audit matched file names only and did not open any file, so it cannot tell real secrets from test values.
- `secret_file_copies.plugin_holds_secret_file`: `review_suggested`; evidence `count`, `plugin_count`.
  > A .env-style file was counted inside one or more plugin folders, outside the profile's secret stores. The audit matched file names only and did not open any file, so it cannot tell whether the file holds a real secret.
- `secret_file_copies.readable_by_others`: `warning` (only when `mode_check` is `verified`); evidence `count`, `checked_count`.
  > Secret-named files carry group or world permission bits (mode & 0o077) in a home whose file modes vary. The audit matched file names and lstat mode bits only and did not open any file, so it cannot tell whether a file holds a real secret or who else can log in to this machine.
- `secret_file_copies.config_backup_copies`: `info` (1–5 copies) / `review_suggested` (more than 5); evidence `count`, `burst_count`, `max_burst_files`, `review_threshold`.
  > Copies of config.yaml were counted at the home or profile root and in backup folders; a config.yaml can contain keys typed into it. The audit matched file names and lstat metadata only and did not open any file, so it cannot tell whether any copy holds a key.
- `secret_file_copies.could_not_verify`: `info` (coverage `could_not_verify`); evidence `cuts`, `entries_walked`, `truncated_by` (walk; `limit_exceeded` is a defensive fallback a real walk does not reach), or `cuts`, `reason` (not measured).
  > Part of the home could not be listed (a safety cap, an unreadable folder, an undecodable name, or a missing or invalid home path), so the counts are partial. The audit matched file names only and did not open any file; what was not listed is neither clean nor a problem.

## Section keys and enumerated values

- Top-level keys of `secret_file_copies`: `coverage`, `status`, `reason`, `truncated_by`, `expected_secret_files`, `backup_copies`, `secret_named_files`, `fixture_homes`, `mode_bits`, `config_backups`, `symlinks`, `limits`, `thresholds`.
- `expected_secret_files`: `total`, `by_kind`.
- `backup_copies`: `count`, `same_size_as_live_count`, `copies` (each: `secret_kind`, `scope`, `same_size_as_live`, `year`, `month`).
- `secret_named_files`: `count`, `by_top_level_folder` (rows: `path`, `count`, `classes`), `by_pattern_class`, `example_locations` (rows: `path`, `class`), `plugin_dotenv_count`, `plugin_folders_with_dotenv`, `top_level_folder_count`, `plugin_folder_count`.
- `fixture_homes`: `fixture_home_count`, `fixture_profile_dir_count`, `secret_named_file_count`, `by_pattern_class`, `note`.
- `mode_bits`: `mode_check`, `mode_check_reason`, `readable_by_others_count`, `checked_count`.
- `config_backups`: `count`, `root_count`, `profile_count`, `backups_config_dir_count`, `burst_count`, `max_burst_files`, `reason`.
- `symlinks`: `symlinks_skipped`, `secret_named_symlinks`.
- `limits`: `max_entries`, `max_depth`, `max_seconds`, `entries_walked`, `max_depth_reached`, `cuts`.
- `thresholds`: `backup_copies_warning`, `work_folder_secret_files_warning`, `fixture_home_secret_files_review`, `plugin_secret_file_review`, `readable_by_others_warning`, `config_backup_info`, `config_backup_review`, `config_backup_burst_min_files`, `config_backup_burst_window_seconds`.
- `status`: `completed`, `not_measured`. `reason`: `null`, `missing`, `unreadable`, `symlink_root`, `not_directory`, `invalid_path`.
- `coverage`: `verified`, `could_not_verify`. `truncated_by`: `null`, `time_budget`, `max_entries`, `max_depth`, `subpath_unreadable` (an undecodable name is counted as `subpath_unreadable`).
- `expected_secret_files.by_kind` keys: `dotenv`, `auth_json`, `shared_auth`, `credentials_store`, `mcp_tokens`, `pairing`, `vault`, `platform_token_stores`, `oauth_stores`, `browser_and_home_stores`, `os_credential_dirs`.
- `backup_copies.copies[].secret_kind`: same kinds as above. `scope`: `home`, `profile`, `backups`. `year` / `month`: integers or `null`.
- Pattern classes (`by_pattern_class` and `classes` keys, `example_locations[].class` values): `dotenv`, `oauth-json`, `service-account-json`, `auth-json`, `token-json`, `tokens`, `credential`, `secret_word`, `api-key`, `pem`, `key`, `ssh-key`, `pkcs12`, `keystore`, `netrc`, `npmrc`, `pypirc`.
- `mode_bits.mode_check`: `verified`, `could_not_verify`. `mode_check_reason`: `null`, `not_measured`, `no_group_or_other_bits_anywhere`, `all_files_permissive`, `uniform_mode`. `readable_by_others_count` is an integer or `null`.
- `config_backups.reason`: `configs_may_embed_keys_not_read`.

## Read Policy

- **Listed**: directory entries under `profile_path` via `os.scandir`, bounded by `MAX_ENTRIES`, `MAX_DEPTH` and `MAX_SECONDS`.
- **Stat'ed**: `os.lstat` only (`st_mode`, `st_size`, `st_mtime`), on the root and on each listed entry. Never `os.stat`, `os.path.exists`/`isfile`/`isdir`, or a `DirEntry` method that follows links.
- **Read / opened / resolved**: **nothing**. The test `test_x8_no_touch_harness_every_code_path` replaces every other filesystem API (open, `io.FileIO`, `os.read`, `mmap`, `shutil`, `hashlib.file_digest`, `sqlite3`, `subprocess`, `os.readlink`, `realpath`, the pathlib readers and predicates) and adds a `sys.addaudithook` recorder. Across every code path the module made only `os.lstat` and `os.scandir` calls, both under the home, and produced zero `open` audit events.
- **Not used**: `audit.policy.credential_path`. That predicate gates content reads elsewhere in the audit, and this module reads nothing. Its filename hints (`id_*`, `.env*`, `*.key`) produced false hits such as `id_FEMININE.pak` and `.envoy.yaml`.

## Wiring

The wiring sheet for the report is `audit/wiring/secret_file_copies.json` (section, entry, keyword arguments, every key, every enumerated value, rule ids, classifications, consequence sentences, free strings, notes). The tests walk every emitted section and finding against it and check that the report's serializer and persistence keep every key, number, enumerated value and sentence. The wiring sheet supplies the section keys, vocabulary, rules and sentences used by the shared registry.

- Call: `audit_secret_file_copies(profile_path=<profile directory>)`. The module reads no `config.yaml` and no credential file, so no other argument is needed; `clock`, `max_entries`, `max_depth` and `max_seconds` keep their defaults.
- Result envelope: exactly `secret_file_copies` (the section), `findings`, `status` (the legacy `pass`/`fail`; always `pass` here), `coverage` and `run_metrics`.
- `run_metrics`: `elapsed_seconds`. It changes on every run, so it is kept out of the section and must stay out of the fingerprinted report. `adapt_component_result` keeps it as a top-level key.
- Every finding uses rule ids of the form `secret_file_copies.<rule>` and one fixed consequence sentence; numbers are in the evidence. Classifications: `warning`, `review_suggested`, `info` (legacy severities `warn`, `info`); coverage `verified` or `could_not_verify`.

// Real /audit/report findings and /audit/summary payload, generated from the Python test
// fixtures (tests/test_audit_summary.py build_home + collect + make_report, synthetic home)
// with home_workdirs ending on its time budget and profile_context stopping, as
// audit_surface._wired_component/_component record them. Report sections are trimmed: the
// page reads report.findings and the summary only.
export const AUDIT_REPORT = {
 "coverage": "could_not_verify",
 "as_of": 1794268800,
 "mode": "live",
 "findings": [
  {
   "id": "secret_file_copies.secret_named_files_in_work_folders",
   "classification": "warning",
   "coverage": "verified",
   "affected_identities": [],
   "source_paths": [],
   "evidence": {
    "class_count": 1,
    "count": 1,
    "folder_count": 1,
    "source_digest": "19fbd09208644783b31269a0e5e335c6e0d39b4d7e6c000f4187599db5364f4b"
   },
   "consequence": "Files whose names match secret-store patterns were counted outside the places the Hermes source keeps secrets. The audit matched file names only and did not open any file, so it cannot tell whether any of them holds a real secret; a copy, sync or share of those folders includes them. Files that third-party plugins write are not known to the audit as expected stores and are counted here.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "Files whose names match secret-store patterns were counted outside the places the Hermes source keeps secrets. The audit matched file names only and did not open any file, so it cannot tell whether any of them holds a real secret; a copy, sync or share of those folders includes them. Files that third-party plugins write are not known to the audit as expected stores and are counted here.",
   "fix": null
  },
  {
   "id": "unattended_exposure.command_approval_off",
   "classification": "warning",
   "coverage": "verified",
   "affected_identities": [
    "config.yaml"
   ],
   "source_paths": [
    {
     "path": "config.yaml",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "approvals_mode": "approval_off",
    "command_allowlist_count": 0,
    "source_digest": "f4cacd7644aa5b67564c97e943efaa1fc1c18c7821e63f0fb5c07805953b4104",
    "terminal_backend": "local"
   },
   "consequence": "config.yaml sets approvals.mode to off and terminal.backend to local, so Hermes runs shell commands that match its dangerous-command patterns on this machine without asking a person (hardline blocks and approvals.deny rules still apply); this audit read config settings and does not show what commands any agent ran.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "config.yaml sets approvals.mode to off and terminal.backend to local, so Hermes runs shell commands that match its dangerous-command patterns on this machine without asking a person (hardline blocks and approvals.deny rules still apply); this audit read config settings and does not show what commands any agent ran.",
   "fix": null
  },
  {
   "id": "context_load.persona_oversized",
   "classification": "review_suggested",
   "coverage": "verified",
   "affected_identities": [
    "default"
   ],
   "source_paths": [
    {
     "path": {
      "hmac": "839dbaadd994f924636b9da99513f04b3f0dd8d4146aea3128ff06c8b06dc072",
      "kind": "unresolved_reference",
      "location": {
       "line": null,
       "path": null
      }
     },
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "estimated_tokens": 2500,
    "injected_chars": 10000,
    "raw_chars": 400,
    "source_digest": "903c431053f3a571c26209b52cb4d07a3c93e32dbaf11ae0ffafe4bd9a5a59aa",
    "threshold_tokens": 2000,
    "truncated": false
   },
   "consequence": "Profile persona (SOUL.md) injects a large static prompt block on every turn.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "Profile persona (SOUL.md) injects a large static prompt block on every turn.",
   "fix": null
  },
  {
   "id": "dead_stores.profile_exports",
   "classification": "review_suggested",
   "coverage": "verified",
   "affected_identities": [
    "profile-exports"
   ],
   "source_paths": [
    {
     "path": "profile-exports",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "burst_count": 0,
    "large_archives_bytes": 0,
    "large_archives_count": 0,
    "profile_exports_bytes": 62914560,
    "profile_exports_count": 1,
    "source_digest": "ffb838c4298702a69706ba1fae9a89e311c2b7f9adc9ed0f868256c18cc9877e",
    "threshold_bytes": 52428800,
    "total_bytes": 62914560
   },
   "consequence": "Profile export and backup archive files total more than 50 MiB; byte counts and write-time bursts measure archive files on disk and do not show whether another copy exists or whether the files are still needed.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "Profile export and backup archive files total more than 50 MiB; byte counts and write-time bursts measure archive files on disk and do not show whether another copy exists or whether the files are still needed.",
   "fix": null
  },
  {
   "id": "home_workdirs.unverified",
   "classification": "review_suggested",
   "coverage": "could_not_verify",
   "affected_identities": [
    "default"
   ],
   "source_paths": [],
   "evidence": {
    "source_digest": "851c4789de6bdd168b5be0d4ca33aa700341365727a78c8bba091ba8ade649b7"
   },
   "consequence": "The home_workdirs check exceeded its time budget and could not be verified.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "The home_workdirs check exceeded its time budget and could not be verified.",
   "fix": null
  },
  {
   "id": "kanban_residue.blocked_loops",
   "classification": "review_suggested",
   "coverage": "verified",
   "affected_identities": [
    "kanban"
   ],
   "source_paths": [
    {
     "path": "/home/user/.hermes/kanban.db",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "four_runs_without_completion": 1,
    "max_block_recurrences": 0,
    "repeated_block_limit": 2,
    "repeated_block_nonzero": 0,
    "repeated_block_threshold": 0,
    "source_digest": "d05bb020ee7bcbf253ac09df427bbd08f435d9d7016bca225d51d91cfa017167"
   },
   "consequence": "At least one task has four or more runs with no completed run or reached Hermes's repeated-block limit of 2; these are stored records of past attempts, not a current fault, and do not show whether another attempt would succeed.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "At least one task has four or more runs with no completed run or reached Hermes's repeated-block limit of 2; these are stored records of past attempts, not a current fault, and do not show whether another attempt would succeed.",
   "fix": null
  },
  {
   "id": "kanban_residue.retry_context_growth",
   "classification": "review_suggested",
   "coverage": "verified",
   "affected_identities": [
    "kanban"
   ],
   "source_paths": [
    {
     "path": "/home/user/.hermes/kanban.db",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "current_uncapped_chars": 44100,
    "first_run_body_edited_later": false,
    "first_uncapped_chars": 100,
    "first_worker_chars": 100,
    "growth_ratio": 248.71,
    "growth_tasks": 1,
    "latest_uncapped_chars": 33100,
    "latest_worker_chars": 24871,
    "runs": 4,
    "source_digest": "48701ef7dc8a7c0d70ea14337fa95d033fdd8285969bfe96cc449708743ef260"
   },
   "consequence": "Rebuilt from text stored today, a retried task would hand its latest worker more characters of its own body, comments and earlier attempts than at its first run, above the review limit of 20,000 characters or three times the first-run figure; Hermes caps each item but not the total. The first-run figure uses today's body and is an estimate when the body was edited after that run. This is a reconstruction from stored rows, not a recording of any prompt, and it describes left-over data, not a current fault.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "Rebuilt from text stored today, a retried task would hand its latest worker more characters of its own body, comments and earlier attempts than at its first run, above the review limit of 20,000 characters or three times the first-run figure; Hermes caps each item but not the total. The first-run figure uses today's body and is an estimate when the body was edited after that run. This is a reconstruction from stored rows, not a recording of any prompt, and it describes left-over data, not a current fault.",
   "fix": null
  },
  {
   "id": "memory_load.over_limit",
   "classification": "review_suggested",
   "coverage": "verified",
   "affected_identities": [],
   "source_paths": [],
   "evidence": {
    "count": 1,
    "source_digest": "eee607383fcd71936b76af9a5671f0f69331266da5029c210b74877f5103051f"
   },
   "consequence": "Memory files (live or snapshot copies) are longer, in characters, than the character limit used for this audit; this compares file length only and does not measure what is sent with a request.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "Memory files (live or snapshot copies) are longer, in characters, than the character limit used for this audit; this compares file length only and does not measure what is sent with a request.",
   "fix": null
  },
  {
   "id": "profile_context.unverified",
   "classification": "review_suggested",
   "coverage": "could_not_verify",
   "affected_identities": [
    "default"
   ],
   "source_paths": [],
   "evidence": {
    "source_digest": "15c1c86965b7c75da0f65ff7930ee81a6e189dff6d501ffe515c824da849789f"
   },
   "consequence": "The profile_context check stopped without a usable result and could not be verified.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "The profile_context check stopped without a usable result and could not be verified.",
   "fix": null
  },
  {
   "id": "profile_duplicates.repeated_binary",
   "classification": "review_suggested",
   "coverage": "verified",
   "affected_identities": [
    "/home/user/.hermes/profiles"
   ],
   "source_paths": [
    {
     "path": "/home/user/.hermes/profiles",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "bytes_wasted": 23068672,
    "copies": 3,
    "groups": 1,
    "source_digest": "02d9b8d913e3172cf61d2a877882ea248b0899c4ba7f8892863a45bcb35f4fe9",
    "wasted_bytes": 23068672
   },
   "consequence": "An executable file of at least 10 MiB is stored as byte-identical copies in at least three profiles; this measures duplicated disk bytes and does not show whether any profile runs it.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "An executable file of at least 10 MiB is stored as byte-identical copies in at least three profiles; this measures duplicated disk bytes and does not show whether any profile runs it.",
   "fix": null
  },
  {
   "id": "skill_hygiene.could_not_verify",
   "classification": "review_suggested",
   "coverage": "could_not_verify",
   "affected_identities": [
    "/home/user/.hermes/skills"
   ],
   "source_paths": [
    {
     "path": "/home/user/.hermes/skills",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "cuts": 1,
    "source_digest": "4877786123b90b79f958e10e5299dccd52f5bec7639507eee9919ecf86fd62d4"
   },
   "consequence": "Skill provenance or bounded package coverage could not be verified; missing evidence is not a clean result.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "Skill provenance or bounded package coverage could not be verified; missing evidence is not a clean result.",
   "fix": null
  },
  {
   "id": "skill_hygiene.duplicate_skill",
   "classification": "review_suggested",
   "coverage": "verified",
   "affected_identities": [
    "/home/user/.hermes/skills/cat/s0/SKILL.md"
   ],
   "source_paths": [
    {
     "path": "/home/user/.hermes/skills/cat/s0/SKILL.md",
     "start_line": null,
     "end_line": null
    },
    {
     "path": "/home/user/.hermes/skills/cat/s1/SKILL.md",
     "start_line": null,
     "end_line": null
    },
    {
     "path": "/home/user/.hermes/skills/cat/s2/SKILL.md",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "duplicate_count": 3,
    "source_digest": "b831202aa8c73ac38ee0adc8aec6fa3e1f0839ff9b6a28fefdf213aa2d1dcf38"
   },
   "consequence": "Multiple skills have identical normalized bodies or case/hyphen/underscore-equivalent names.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "Multiple skills have identical normalized bodies or case/hyphen/underscore-equivalent names.",
   "fix": null
  },
  {
   "id": "write_settings.unattended_memory_writes",
   "classification": "review_suggested",
   "coverage": "verified",
   "affected_identities": [
    "/home/user/.hermes/config.yaml"
   ],
   "source_paths": [
    {
     "path": "/home/user/.hermes/config.yaml",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "approval_enabled": false,
    "enabled": true,
    "source": "default",
    "source_digest": "c89464a3989e55ae2c03fbab906c87ec5cf603a38207516308592e17825d742d"
   },
   "consequence": "Memory writes made during a conversation (additions, edits and removals) apply without approval because the gate is off; source=default identifies the shipped default. Only destructive edits from background review are staged separately.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "Memory writes made during a conversation (additions, edits and removals) apply without approval because the gate is off; source=default identifies the shipped default. Only destructive edits from background review are staged separately.",
   "fix": null
  },
  {
   "id": "write_settings.unattended_skill_writes",
   "classification": "review_suggested",
   "coverage": "verified",
   "affected_identities": [
    "/home/user/.hermes/config.yaml"
   ],
   "source_paths": [
    {
     "path": "/home/user/.hermes/config.yaml",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "approval_enabled": false,
    "enabled": true,
    "source": "default",
    "source_digest": "bb810b016d9a63d7bdf9360b251aca5b78e810602e4b7f6a9ce0ca6fab8ddf39"
   },
   "consequence": "CLI skill writes are enabled with the approval gate off; source=default explicitly identifies reliance on the shipped default.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "warn",
   "detail": "CLI skill writes are enabled with the approval gate off; source=default explicitly identifies reliance on the shipped default.",
   "fix": null
  },
  {
   "id": "dead_stores.summary",
   "classification": "info",
   "coverage": "verified",
   "affected_identities": [
    "."
   ],
   "source_paths": [
    {
     "path": ".",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "dead_weight_share_of_home": 0.281581,
    "source_digest": "29ae76a2d9547b3d2eac0afc0112a443b2f5f4099ce23656f246c5f42e0ecc25",
    "total_dead_weight_bytes": 62914560,
    "total_home_bytes": 223432930
   },
   "consequence": "Dead-store classes were measured across the home; class totals and home share are file sizes on disk that overlap bytes counted by other sections, must not be added to other sections' totals, and do not by themselves make any file safe to delete.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "info",
   "detail": "Dead-store classes were measured across the home; class totals and home share are file sizes on disk that overlap bytes counted by other sections, must not be added to other sections' totals, and do not by themselves make any file safe to delete.",
   "fix": null
  },
  {
   "id": "memory_load.duplicate_entries",
   "classification": "info",
   "coverage": "verified",
   "affected_identities": [],
   "source_paths": [],
   "evidence": {
    "count": 88,
    "source_digest": "6b57258e89329af9bd0acafd737e5f8604d81f035b1dba0ee70bd5de782a5414"
   },
   "consequence": "Normalized entries or eight-word shingles were counted that repeat within or across live memory files; the count does not show that the repeated text means the same thing.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "info",
   "detail": "Normalized entries or eight-word shingles were counted that repeat within or across live memory files; the count does not show that the repeated text means the same thing.",
   "fix": null
  },
  {
   "id": "memory_load.mostly_dated_entries",
   "classification": "info",
   "coverage": "verified",
   "affected_identities": [],
   "source_paths": [],
   "evidence": {
    "count": 1,
    "source_digest": "f5b98231fe74d11a77651ff4febfb314615f7f2679b14da364392c81c5d368ff"
   },
   "consequence": "Memory files were counted where more than half of at least six entries contain a calendar date; a date does not show that the entry is out of date.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "info",
   "detail": "Memory files were counted where more than half of at least six entries contain a calendar date; a date does not show that the entry is out of date.",
   "fix": null
  },
  {
   "id": "skill_ledger.could_not_verify",
   "classification": "info",
   "coverage": "could_not_verify",
   "affected_identities": [
    "skills"
   ],
   "source_paths": [
    {
     "path": "skills",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "cuts": 0,
    "ledger_present": false,
    "reason": "ledger_absent",
    "source_digest": "2a8463155fa22cc0c03b009232f436a8c9efe7462b2ac60e4f79170c06fac29a"
   },
   "consequence": "The skill change ledger or bookkeeping metadata is absent, unreadable, malformed, or truncated by collection bounds; an absent ledger is not evidence that no skill changes occurred.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "info",
   "detail": "The skill change ledger or bookkeeping metadata is absent, unreadable, malformed, or truncated by collection bounds; an absent ledger is not evidence that no skill changes occurred.",
   "fix": null
  },
  {
   "id": "skill_packs.could_not_verify",
   "classification": "info",
   "coverage": "could_not_verify",
   "affected_identities": [
    "skills/.usage.json"
   ],
   "source_paths": [
    {
     "path": "skills/.usage.json",
     "start_line": null,
     "end_line": null
    }
   ],
   "evidence": {
    "cuts": 0,
    "reason": "usage_file_missing",
    "source_digest": "b3284a5ed4da91acd9c88670a2d4a38a19a516d469003844432586b3740b040d"
   },
   "consequence": "Skill pack usage or directory coverage could not be completely verified; missing usage records or bounded traversal cuts are not evidence of clean state or zero usage.",
   "limitations": "Source-derived text withheld by persistence policy.",
   "proposed_cleanup_id": null,
   "severity": "info",
   "detail": "Skill pack usage or directory coverage could not be completely verified; missing usage records or bounded traversal cuts are not evidence of clean state or zero usage.",
   "fix": null
  }
 ]
}

export const AUDIT_SUMMARY = {
 "run_id": "run-1",
 "status": "completed",
 "text": "Defuzz audit summary\nMeasured on 2026-11-10 (UTC).\nFindings: 2 warnings, 12 review suggested, 5 for information.\n1 of these come from other audit checks; they are listed in --json.\nBiggest items:\n  1. Old exports and archives: 60.0 MB\n  2. Identical copies across profiles: 22.0 MB (profiles/qa1/bin)\n  3. Largest task retry context: 24,871 characters\nNot measured this time: Memory from other projects in past sessions (not run this time), Work files\n  inside the Hermes home (collector failed).\n\nCommands that can run without a prompt\n  Approval settings that let commands run without a prompt: 1 of 4 (approvals.mode).\n  Warning:\n    - config.yaml sets approvals.mode to off and terminal.backend to local, so Hermes runs shell\n      commands that match its dangerous-command patterns on this machine without asking a person\n      (hardline blocks and approvals.deny rules still apply); this audit read config settings and\n      does not show what commands any agent ran. [command allowlist count 0]\n\nSecret-named files outside their usual places\n  1 secret-named file outside the expected places, in 1 top-level folder; 0 backup copies of secret\n  files.\n  Warning:\n    - Files whose names match secret-store patterns were counted outside the places the Hermes\n      source keeps secrets. The audit matched file names only and did not open any file, so it\n      cannot tell whether any of them holds a real secret; a copy, sync or share of those folders\n      includes them. Files that third-party plugins write are not known to the audit as expected\n      stores and are counted here. [class count 1, count 1, folder count 1]\n\nMemory and skill edit settings\n  Skill edits saved without a prompt: yes. Memory edits saved without a prompt: yes.\n  Review suggested:\n    - Memory writes made during a conversation (additions, edits and removals) apply without\n      approval because the gate is off; source=default identifies the shipped default. Only\n      destructive edits from background review are staged separately.\n    - CLI skill writes are enabled with the approval gate off; source=default explicitly identifies\n      reliance on the shipped default.\n\nMemory files and their limits\n  MEMORY.md: 3,933 of 2,200 characters (179%). USER.md: 10 of 1,375 characters (1%).\n  Review suggested:\n    - Memory files (live or snapshot copies) are longer, in characters, than the character limit\n      used for this audit; this compares file length only and does not measure what is sent with a\n      request. [count 1]\n  For information: 2 notes (full text in --json).\n\nText sent with every request\n  Sent with every request: about 3,300 tokens (13,200 characters); largest part: SOUL.md persona,\n  10,000 characters.\n  Review suggested:\n    - Profile persona (SOUL.md) injects a large static prompt block on every turn. [estimated tokens\n      2,500, injected chars 10,000, raw chars 400]\n\nInstalled skills and the skill list\n  3 skills listed; the skill list adds 1,284 characters (about 321 tokens) to every request. Some\n  parts could not be checked (usage file missing).\n  For information: 1 note (full text in --json).\n\nWhat is inside skill files\n  3 skills checked; 0 stock skills changed since install; 0 with leftover session notes; 1 group of\n  skills with the same content. Some parts could not be checked.\n  Review suggested:\n    - Skill provenance or bounded package coverage could not be verified; missing evidence is not a\n      clean result. [cuts 1]\n    - Multiple skills have identical normalized bodies or case/hyphen/underscore-equivalent names.\n      [duplicate count 3]\n\nSkill change history\n  No skill change history file was found. Some parts could not be checked (ledger absent).\n  For information: 1 note (full text in --json).\n\nMemory from other projects in past sessions\n  Not measured (not run this time).\n\nWork files inside the Hermes home\n  Not measured (collector failed).\n  Review suggested:\n    - The home_workdirs check exceeded its time budget and could not be verified.\n\nStored files nothing uses\n  60.0 MB of 213.1 MB in the home (28%) is in files nothing refers to, such as old exports, caches\n  and backups.\n  Review suggested:\n    - Profile export and backup archive files total more than 50 MiB; byte counts and write-time\n      bursts measure archive files on disk and do not show whether another copy exists or whether\n      the files are still needed. [profile exports bytes 60.0 MB, profile exports count 1, total\n      bytes 60.0 MB]\n  For information: 1 note (full text in --json).\n\nCopies shared across profiles\n  3 profiles; 22.0 MB stored more than once, in 1 group of identical files.\n  Review suggested:\n    - An executable file of at least 10 MiB is stored as byte-identical copies in at least three\n      profiles; this measures duplicated disk bytes and does not show whether any profile runs it.\n      [bytes wasted 22.0 MB, copies 3, groups 1]\n\nLeftover task board data\n  5 tasks and 0 comments on 1 board; largest retry context: 24,871 characters.\n  Review suggested: 2 notes (full text in --json).\n\nEach setting and file counted here was reasonable on the day it was added. This report adds them up\nto show the running total.\nSmall next steps:\n  1. Turn command approval back on, then re-run the audit.\n  2. Check whether each secret-named copy is still needed; move the ones that are not to a safe\n     place outside the Hermes home, and change any key that was shared or exposed.\n  3. Copy MEMORY.md to a backup folder outside the Hermes home, then remove entries that are no\n     longer true.\nExact numbers for every line: hermes defuzz audit --json\nIt is fine to stop here and come back to this later.\n",
 "summary": {
  "summary_version": 1,
  "measured_on": "2026-11-10",
  "counts": {
   "warning": 2,
   "review_suggested": 12,
   "info": 5
  },
  "other_findings": 1,
  "biggest_items": [
   {
    "label": "Old exports and archives",
    "value": 62914560,
    "unit": "bytes",
    "path": null
   },
   {
    "label": "Identical copies across profiles",
    "value": 23068672,
    "unit": "bytes",
    "path": "profiles/qa1/bin"
   },
   {
    "label": "Largest task retry context",
    "value": 24871,
    "unit": "characters",
    "path": null
   }
  ],
  "not_measured": [
   {
    "section": "session_contamination",
    "title": "Memory from other projects in past sessions",
    "reason": "not_run"
   },
   {
    "section": "home_workdirs",
    "title": "Work files inside the Hermes home",
    "reason": "collector_failed"
   }
  ],
  "sections": [
   {
    "section": "unattended_exposure",
    "title": "Commands that can run without a prompt",
    "measured": true,
    "partial": false,
    "reason": null,
    "headline": "Approval settings that let commands run without a prompt: 1 of 4 (approvals.mode).",
    "numbers": {
     "approval_settings_without_prompt": [
      "approvals.mode"
     ],
     "approval_settings_checked": 4,
     "approval_settings_unread": 0
    },
    "findings": {
     "warning": [
      {
       "rule_id": "unattended_exposure.command_approval_off",
       "sentence": "config.yaml sets approvals.mode to off and terminal.backend to local, so Hermes runs shell commands that match its dangerous-command patterns on this machine without asking a person (hardline blocks and approvals.deny rules still apply); this audit read config settings and does not show what commands any agent ran.",
       "count": 1,
       "evidence": [
        [
         "command_allowlist_count",
         0
        ]
       ]
      }
     ],
     "review_suggested": [],
     "info": []
    }
   },
   {
    "section": "secret_file_copies",
    "title": "Secret-named files outside their usual places",
    "measured": true,
    "partial": false,
    "reason": null,
    "headline": "1 secret-named file outside the expected places, in 1 top-level folder; 0 backup copies of secret files.",
    "numbers": {
     "secret_named_files": 1,
     "top_level_folders": 1,
     "backup_copies": 0
    },
    "findings": {
     "warning": [
      {
       "rule_id": "secret_file_copies.secret_named_files_in_work_folders",
       "sentence": "Files whose names match secret-store patterns were counted outside the places the Hermes source keeps secrets. The audit matched file names only and did not open any file, so it cannot tell whether any of them holds a real secret; a copy, sync or share of those folders includes them. Files that third-party plugins write are not known to the audit as expected stores and are counted here.",
       "count": 1,
       "evidence": [
        [
         "class_count",
         1
        ],
        [
         "count",
         1
        ],
        [
         "folder_count",
         1
        ]
       ]
      }
     ],
     "review_suggested": [],
     "info": []
    }
   },
   {
    "section": "write_settings",
    "title": "Memory and skill edit settings",
    "measured": true,
    "partial": false,
    "reason": null,
    "headline": "Skill edits saved without a prompt: yes. Memory edits saved without a prompt: yes.",
    "numbers": {
     "unattended_skill_writes": true,
     "unattended_memory_writes": true
    },
    "findings": {
     "warning": [],
     "review_suggested": [
      {
       "rule_id": "write_settings.unattended_memory_writes",
       "sentence": "Memory writes made during a conversation (additions, edits and removals) apply without approval because the gate is off; source=default identifies the shipped default. Only destructive edits from background review are staged separately.",
       "count": 1,
       "evidence": []
      },
      {
       "rule_id": "write_settings.unattended_skill_writes",
       "sentence": "CLI skill writes are enabled with the approval gate off; source=default explicitly identifies reliance on the shipped default.",
       "count": 1,
       "evidence": []
      }
     ],
     "info": []
    }
   },
   {
    "section": "memory_load",
    "title": "Memory files and their limits",
    "measured": true,
    "partial": false,
    "reason": null,
    "headline": "MEMORY.md: 3,933 of 2,200 characters (179%). USER.md: 10 of 1,375 characters (1%).",
    "numbers": {
     "memory": {
      "characters": 3933,
      "char_limit": 2200
     },
     "user": {
      "characters": 10,
      "char_limit": 1375
     },
     "shipped_char_limits": {
      "memory": 2200,
      "user": 1375
     },
     "files_over_limit": 1
    },
    "findings": {
     "warning": [],
     "review_suggested": [
      {
       "rule_id": "memory_load.over_limit",
       "sentence": "Memory files (live or snapshot copies) are longer, in characters, than the character limit used for this audit; this compares file length only and does not measure what is sent with a request.",
       "count": 1,
       "evidence": [
        [
         "count",
         1
        ]
       ]
      }
     ],
     "info": [
      {
       "rule_id": "memory_load.duplicate_entries",
       "sentence": "Normalized entries or eight-word shingles were counted that repeat within or across live memory files; the count does not show that the repeated text means the same thing.",
       "count": 1,
       "evidence": [
        [
         "count",
         88
        ]
       ]
      },
      {
       "rule_id": "memory_load.mostly_dated_entries",
       "sentence": "Memory files were counted where more than half of at least six entries contain a calendar date; a date does not show that the entry is out of date.",
       "count": 1,
       "evidence": [
        [
         "count",
         1
        ]
       ]
      }
     ]
    }
   },
   {
    "section": "context_load",
    "title": "Text sent with every request",
    "measured": true,
    "partial": false,
    "reason": null,
    "headline": "Sent with every request: about 3,300 tokens (13,200 characters); largest part: SOUL.md persona, 10,000 characters.",
    "numbers": {
     "estimated_tokens": 3300,
     "characters": 13200,
     "largest_part": "identity_soul",
     "largest_part_characters": 10000
    },
    "findings": {
     "warning": [],
     "review_suggested": [
      {
       "rule_id": "context_load.persona_oversized",
       "sentence": "Profile persona (SOUL.md) injects a large static prompt block on every turn.",
       "count": 1,
       "evidence": [
        [
         "estimated_tokens",
         2500
        ],
        [
         "injected_chars",
         10000
        ],
        [
         "raw_chars",
         400
        ]
       ]
      }
     ],
     "info": []
    }
   },
   {
    "section": "skill_packs",
    "title": "Installed skills and the skill list",
    "measured": true,
    "partial": true,
    "reason": "usage_file_missing",
    "headline": "3 skills listed; the skill list adds 1,284 characters (about 321 tokens) to every request.",
    "numbers": {
     "listed_skills": 3,
     "index_chars": 1284,
     "estimated_tokens": 321,
     "never_used": null
    },
    "findings": {
     "warning": [],
     "review_suggested": [],
     "info": [
      {
       "rule_id": "skill_packs.could_not_verify",
       "sentence": "Skill pack usage or directory coverage could not be completely verified; missing usage records or bounded traversal cuts are not evidence of clean state or zero usage.",
       "count": 1,
       "evidence": [
        [
         "cuts",
         0
        ]
       ]
      }
     ]
    }
   },
   {
    "section": "skill_hygiene",
    "title": "What is inside skill files",
    "measured": true,
    "partial": true,
    "reason": null,
    "headline": "3 skills checked; 0 stock skills changed since install; 0 with leftover session notes; 1 group of skills with the same content.",
    "numbers": {
     "skills_examined": 3,
     "bundled_modified": 0,
     "residue_skills": 0,
     "duplicate_groups": 1
    },
    "findings": {
     "warning": [],
     "review_suggested": [
      {
       "rule_id": "skill_hygiene.could_not_verify",
       "sentence": "Skill provenance or bounded package coverage could not be verified; missing evidence is not a clean result.",
       "count": 1,
       "evidence": [
        [
         "cuts",
         1
        ]
       ]
      },
      {
       "rule_id": "skill_hygiene.duplicate_skill",
       "sentence": "Multiple skills have identical normalized bodies or case/hyphen/underscore-equivalent names.",
       "count": 1,
       "evidence": [
        [
         "duplicate_count",
         3
        ]
       ]
      }
     ],
     "info": []
    }
   },
   {
    "section": "skill_ledger",
    "title": "Skill change history",
    "measured": true,
    "partial": true,
    "reason": "ledger_absent",
    "headline": "No skill change history file was found.",
    "numbers": {
     "ledger_present": false,
     "orphan_blob_bytes": 0
    },
    "findings": {
     "warning": [],
     "review_suggested": [],
     "info": [
      {
       "rule_id": "skill_ledger.could_not_verify",
       "sentence": "The skill change ledger or bookkeeping metadata is absent, unreadable, malformed, or truncated by collection bounds; an absent ledger is not evidence that no skill changes occurred.",
       "count": 1,
       "evidence": [
        [
         "cuts",
         0
        ]
       ]
      }
     ]
    }
   },
   {
    "section": "session_contamination",
    "title": "Memory from other projects in past sessions",
    "measured": false,
    "partial": false,
    "reason": "not_run",
    "headline": null,
    "numbers": {},
    "findings": {
     "warning": [],
     "review_suggested": [],
     "info": []
    }
   },
   {
    "section": "home_workdirs",
    "title": "Work files inside the Hermes home",
    "measured": false,
    "partial": false,
    "reason": "collector_failed",
    "headline": null,
    "numbers": {},
    "findings": {
     "warning": [],
     "review_suggested": [
      {
       "rule_id": "home_workdirs.unverified",
       "sentence": "The home_workdirs check exceeded its time budget and could not be verified.",
       "count": 1,
       "evidence": []
      }
     ],
     "info": []
    }
   },
   {
    "section": "dead_stores",
    "title": "Stored files nothing uses",
    "measured": true,
    "partial": false,
    "reason": null,
    "headline": "60.0 MB of 213.1 MB in the home (28%) is in files nothing refers to, such as old exports, caches and backups.",
    "numbers": {
     "total_dead_weight_bytes": 62914560,
     "total_home_bytes": 223432930,
     "dead_weight_share_of_home": 0.281581
    },
    "findings": {
     "warning": [],
     "review_suggested": [
      {
       "rule_id": "dead_stores.profile_exports",
       "sentence": "Profile export and backup archive files total more than 50 MiB; byte counts and write-time bursts measure archive files on disk and do not show whether another copy exists or whether the files are still needed.",
       "count": 1,
       "evidence": [
        [
         "profile_exports_bytes",
         62914560
        ],
        [
         "profile_exports_count",
         1
        ],
        [
         "total_bytes",
         62914560
        ]
       ]
      }
     ],
     "info": [
      {
       "rule_id": "dead_stores.summary",
       "sentence": "Dead-store classes were measured across the home; class totals and home share are file sizes on disk that overlap bytes counted by other sections, must not be added to other sections' totals, and do not by themselves make any file safe to delete.",
       "count": 1,
       "evidence": [
        [
         "dead_weight_share_of_home",
         0.281581
        ],
        [
         "total_dead_weight_bytes",
         62914560
        ],
        [
         "total_home_bytes",
         223432930
        ]
       ]
      }
     ]
    }
   },
   {
    "section": "profile_duplicates",
    "title": "Copies shared across profiles",
    "measured": true,
    "partial": false,
    "reason": null,
    "headline": "3 profiles; 22.0 MB stored more than once, in 1 group of identical files.",
    "numbers": {
     "profile_count": 3,
     "total_wasted_bytes": 23068672,
     "duplicate_group_count": 1
    },
    "findings": {
     "warning": [],
     "review_suggested": [
      {
       "rule_id": "profile_duplicates.repeated_binary",
       "sentence": "An executable file of at least 10 MiB is stored as byte-identical copies in at least three profiles; this measures duplicated disk bytes and does not show whether any profile runs it.",
       "count": 1,
       "evidence": [
        [
         "bytes_wasted",
         23068672
        ],
        [
         "copies",
         3
        ],
        [
         "groups",
         1
        ]
       ]
      }
     ],
     "info": []
    }
   },
   {
    "section": "kanban_residue",
    "title": "Leftover task board data",
    "measured": true,
    "partial": false,
    "reason": null,
    "headline": "5 tasks and 0 comments on 1 board; largest retry context: 24,871 characters.",
    "numbers": {
     "boards": 1,
     "tasks": 5,
     "comments": 0,
     "largest_retry_chars": 24871
    },
    "findings": {
     "warning": [],
     "review_suggested": [
      {
       "rule_id": "kanban_residue.blocked_loops",
       "sentence": "At least one task has four or more runs with no completed run or reached Hermes's repeated-block limit of 2; these are stored records of past attempts, not a current fault, and do not show whether another attempt would succeed.",
       "count": 1,
       "evidence": [
        [
         "four_runs_without_completion",
         1
        ],
        [
         "max_block_recurrences",
         0
        ],
        [
         "repeated_block_nonzero",
         0
        ]
       ]
      },
      {
       "rule_id": "kanban_residue.retry_context_growth",
       "sentence": "Rebuilt from text stored today, a retried task would hand its latest worker more characters of its own body, comments and earlier attempts than at its first run, above the review limit of 20,000 characters or three times the first-run figure; Hermes caps each item but not the total. The first-run figure uses today's body and is an estimate when the body was edited after that run. This is a reconstruction from stored rows, not a recording of any prompt, and it describes left-over data, not a current fault.",
       "count": 1,
       "evidence": [
        [
         "current_uncapped_chars",
         44100
        ],
        [
         "first_uncapped_chars",
         100
        ],
        [
         "first_worker_chars",
         100
        ]
       ]
      }
     ],
     "info": []
    }
   }
  ],
  "next_steps": [
   "Turn command approval back on, then re-run the audit.",
   "Check whether each secret-named copy is still needed; move the ones that are not to a safe place outside the Hermes home, and change any key that was shared or exposed.",
   "Copy MEMORY.md to a backup folder outside the Hermes home, then remove entries that are no longer true."
  ]
 }
}

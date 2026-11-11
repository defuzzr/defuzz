# Adding a template

1. Create `templates/<id>/template.yaml` and its `tmpl_prefix/` project tree.
   Use an existing descriptor as the schema example; discovery is automatic.
2. Declare tools in `needs`, file substitutions in `substitute_in`, protected
   files in `locked`, and placement destinations in `rules.json`.
   Keep placeholder forms; include Markdown using them in substitutions.
3. Set `repos[].check.cmd` to the project's check command and supply
   `repos[].check.format_cmds`. Add `extra_cmds` for additional verification.
   Use `version_probes` for tools needing a nonstandard version probe, and
   `lockfiles` for generated lockfile paths.
4. Record tool floors in the project's `TOOLS.lock`, not in README prose.
   For Clang formatters/linters, use the plugin-managed versions declared in
   `plugin.yaml`; project minimums belong in `TOOLS.lock`.
5. Update both `TEMPLATE_CHECK_TOOLS` and `TEMPLATE_FORMAT_TOOLS` in
   `tests/toolchain_needs.py` for the new bundled template.
6. Keep the project README short: purpose, tools, checks, folder destinations
   and template attribution. Keep relative links valid.
7. Run `tests/test_template_kit.py`, `tests/test_scaffold_name_lengths.py` and
   `tests/test_accepted_scaffold_ci.py` through the repository test runner.
   Set `ADOPT_ALL_NAME_LENGTHS=1` to test every supported identifier length.
   Preserve name-sensitive formatting; the limit is `naming.MAX_NAME_LENGTH`.
   Tests skip with the missing tool's name when a required tool is unavailable;
   direct scaffold verification fails if a required tool is missing.

For `web-golden`, edit its source repository instead, then run
`python3 scripts/sync_web_golden.py <source-repo>` to sync it here.

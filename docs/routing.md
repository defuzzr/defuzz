# How suggestions work

Terminal, chat and desktop list choices first and require an explicit template or kit ID.
`hermes defuzz list` shows code templates, then workspace kits.
Ready rows show a title, description and `--template ID` or `--kit ID` flag.
Without a flag, an interactive `hermes defuzz new` can ask for a row to preview.
Terminal creation requires an explicit choice and `--yes`.

A typed idea may supply a name and mark suggestions; it does not select a project.
`prompt_parse.py` and `matcher.py` use fixed rules, answers and words from template and kit metadata.
Weak matches are dropped. Long ideas are shortened for suggestions, with a notice in text output.
Limits live in `catalog_list.py` and `prompt_parse.py`.

## Adding an entry to the list

Templates need a valid `template.yaml` under `templates/`.
Kits come from the optional `defuzz-componentize` companion; without it, templates remain available.
`catalog_list.py` filters unsafe IDs and limits list size, reporting omitted entries.
`picker_text.json` supplies titles, descriptions and ordering; missing entries use manifest text and sort last in their group.
Its optional `coming_soon` entries appear unavailable (greyed in desktop) and cannot be suggested, selected or created.
This local picker policy is separate from the companion's `availability` metadata.

# How suggestions work

A project is created only from an explicit choice. `hermes defuzz list` prints one
list: the code templates, then the workspace kits. Each row has a number, a title,
one line about it, and the flag that creates it (`--template ID` or `--kit ID`).
`hermes defuzz new` creates nothing without one of those flags, unless it runs in a
terminal and you type a row's number or ID when it asks. In chat, the `/defuzz list`
and `/defuzz new` replies put the list inside a code block, so names that come from
kits cannot turn into links or mentions.

A typed idea is optional. It may supply the project name, and it may mark up to
three rows `(suggested)`. A suggestion is only a hint. Nothing is pre-selected, and
nothing is ever created from a suggestion.

Suggestions come from simple word matching (`_suggestions` in `cli.py`). Only the
first 2048 characters of the idea are read; `hermes defuzz list` then adds the line
"Your idea was cut at 2048 characters to mark suggestions." `prompt_parse.py` reads
it first, with fixed rules and no model call; an
idea that is not a project request (ordinary prose) marks nothing. Otherwise
`matcher.py` scores templates from the answers read from the idea (what you
build, layout, language, engine; on `new`, `--answers` too) and from website
words, and scores kits by your words against each kit's id, tags, name and
summary. Weak matches are dropped. `catalog_list.suggested_ids` keeps at most
three, the kind the matcher prefers first. Any error means no marks. It can be
wrong, and an idea that matches nothing gets no marks. Read the list and pick
the row you want.

## Adding an entry to the list

- A template appears when its folder under `templates/` has a `template.yaml`.
- An entry appears only when its id is lowercase letters and digits in runs joined by
  single hyphens, starts with a letter and is at most 64 characters long. The list
  holds at most 100 templates and 200 kits. Entries left out for their id or the cap
  are counted in one notice line under the list.
- Kits come from the companion `defuzz-componentize` plugin. Without it, the list
  still shows the templates and one line saying how to get the kits.
- The title and line for each row come from `picker_text.json`. An entry with no
  text there falls back to its manifest name and summary, and sorts after the
  described entries in its group.

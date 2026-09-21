# Agent guidance for mod_wsgi

## Project

mod_wsgi is an Apache HTTP Server module, written in C, that hosts
Python WSGI applications, either embedded in the Apache child
processes or in separate daemon processes. It sits across two C APIs
at once, those of Apache (with APR) and of CPython, which makes the
code a specialised place to work. See README.rst for what users are
told, and docs/ for the documentation published at
https://www.modwsgi.org/.

Layout:

- src/server/ holds the C source of the module. mod_wsgi.c is the
  entry point and the rest is split by area into wsgi_*.c files with
  matching headers.

- src/express/ holds the Python source of `mod_wsgi-express`, which
  generates an Apache configuration for one application and runs
  Apache with it.

- telemetry/ is a separate Python package, `mod_wsgi-telemetry`, with
  its own pyproject.toml, uv.lock, source, tests and release cycle. It
  shares the repository and nothing else.

- docs/ is the Sphinx source of the documentation, with one page per
  directive in docs/configuration-directives/, guides in
  docs/user-guides/, and one file per version in docs/release-notes/.

- tests/ and scripts/ hold the tests and the scripts that run them.
  See TESTING.md for where tests are, how to run them, and the
  conventions for adding new ones. Read it before doing any test
  related work.

There are two ways of building. The classic `./configure` and
Makefile.in install the module straight into an Apache installation.
setup.py builds the PyPI packages. Three packages come out of the
repository: `mod_wsgi`, `mod_wsgi-standalone` (the same source, built
by package.sh with a dependency on the separate `mod_wsgi-httpd`
package), and `mod_wsgi-telemetry`.

In this repository "docs" means the docs/ directory specifically. The
README files in the tree, including telemetry/README.md, are
developer facing source files and are kept up to date as the code
changes, even when told to hold off on changing the docs.

The scratch/ directory holds temporary working files, such as
reference material given to an agent or plans an agent is asked to
generate. It is ignored by git. Its contents come and go, so never
reference scratch/ files by name from code or documentation that
will be committed.

## Tooling

- Python environments are managed with [uv](https://docs.astral.sh/uv/).
  The development environment is `.venv` in the root of the
  repository, and the test scripts depend on it being there.

- The Justfile has targets for the common tasks. Prefer them over
  synthesizing the underlying commands, and run `just --list` to see
  them all. The main ones are `just build`, `just test`,
  `just test-bounds`, `just test-telemetry`, `just docs` and
  `just aplogno`.

- After editing anything under src/server/, rebuild with `just build`
  before testing. It runs `uv pip install -e . --no-cache`. Without
  `--no-cache` a previously built wheel can be reused and the edit is
  silently not picked up. An editable install alone does not
  recompile the extension.

- `just clean` and `just test-versions` delete `.venv`, and
  `just test-python`, `just test-bounds` and `just venv` with a
  version replace it. Anything else that had been installed into it
  is lost, so look before running them.

- telemetry/ is its own uv project. Work on it from inside that
  directory with `uv sync` and `uv run`.

## Versions and releases

- The mod_wsgi version is defined in src/server/wsgi_version.h, as
  three numeric defines and a version string. Keep all four
  consistent. setup.py, docs/conf.py and the release workflow all
  read the version string from that file.

- The mod_wsgi-telemetry version is `__version__` in
  `telemetry/src/mod_wsgi/telemetry/__init__.py`.

- Versions under development carry a suffix on the string in the
  forms `6.1.0.dev1` and `6.1.0rc1`. The numeric defines hold the
  version being worked towards.

- The exact version of `mod_wsgi-httpd` required by
  `mod_wsgi-standalone` is set in one place, the `install_requires`
  line of setup.py. package.sh reads it from there when generating
  the pyproject.toml for the standalone package, so keep the form of
  that line intact.

- Every mod_wsgi version has a file in docs/release-notes/, listed in
  docs/release-notes.rst with the newest first. A change that users
  can observe needs an entry in the file for the version under
  development, under one of the headings already in use: New
  Features, Features Changed, Features Removed, Bugs Fixed.

## C source

- Match the formatting of the surrounding code, and do not reformat
  code that is not otherwise being changed.

- Every source and header file includes `wsgi_python.h` and then
  `wsgi_apache.h` before any other header. `Python.h` has to be the
  first header every compilation unit sees, or structure layouts can
  differ between files on some platforms.

- For any multi-line comment, put `/*` on a line of its own and `*/`
  on a line of its own. Do not start the text on the `/*` line or end
  it with `*/` on the last line of text. Leave a blank line after
  such a comment when it comes before a function, or before the group
  of struct members it describes. Single line comments are not
  affected.

- Comments describe what the code does now. Do not write comments
  that look back ("previously", "no longer", "now uses", "moved
  from", "replaces the old") or look ahead ("in preparation for",
  "will be needed for", "for future use", "for now"). Reasoning about
  why the design is what it is belongs in a comment, framed as a
  present constraint. How it got that way belongs in the commit
  message.

- Do not name specific `WSGI_APLOGNO()` codes, or other identifiers
  that can be renumbered, in comments. Say "the log call above" or
  describe the category of message. The same goes for anchors in
  docs/error-reference.rst.

- Before allocating a new `WSGI_APLOGNO()` code, list every code in
  use across the whole repository, and take the next integer above
  the highest. `just aplogno` reports the highest code in use and the
  next one to allocate. Codes are spread across many source files and
  docs/error-reference.rst, so the file being edited does not show
  them all. Never fill a gap in the sequence. Gaps are retired codes,
  and reusing one would mislead anyone reading older logs. A new code
  needs an entry in docs/error-reference.rst.

- A change that adds or alters a `#if PY_VERSION_HEX` guard must be
  built and tested under both the oldest and newest supported Python,
  since only one side of the guard is compiled by either. The
  procedure is in TESTING.md.

- When a review finds redundancy that can be removed in the same or
  fewer lines, and removing it makes the control flow clearer, remove
  it. Examples are a check made unreachable by an earlier branch, two
  `if` statements that are mutually exclusive and read better as
  `if` and `else if`, and a reference count increment paired with a
  decrement that can become a transfer of ownership. That the current
  code is correct is not a reason to leave it.

- Do not add exception chaining (`PyException_SetCause` and the
  fetch, normalize and restore code around it) just to preserve the
  detail of an underlying exception, when the message that replaces
  it already names what the caller did wrong. Mention the overwritten
  exception when reviewing, and leave it.

- When proposing a performance change to the request path in daemon
  mode, ask whether it removes real work, such as a system call, a
  mutex operation, an allocation or dead code. Pursue those. A change
  that only rearranges where the GIL is released and reacquired has
  been measured and gave no gain, and in some cases regressions.

## Python source

- src/express/ and setup.py do not use type hints. Match the existing
  style of the file being edited and do not add them piecemeal.

- The code under telemetry/ does use type hints. Keep them, and add
  them to new functions and methods there.

- Use vertical white space to write code in paragraphs: group the
  statements that together perform one step, and separate each group
  from the next with a blank line. Where it helps the reader, start a
  paragraph with a short comment saying what that step does or why,
  followed by a blank line.

## Documentation

- Pages under docs/configuration-directives/ are reference pages.
  They give the description, syntax, default and context of a
  directive, what it does, an example, links to companion
  directives, and caveats intrinsic to its behaviour. They do not
  carry tuning advice, diagnostic procedures, or references to
  metrics. That material goes on pages of its own, normally under
  docs/user-guides/, which the directive page can link to if one
  exists. Do not write a tuning page speculatively.

- When a statement in the docs turns out to be wrong, delete it. Do
  not replace it with a statement of the opposite, justified by
  reference to the implementation. Add a replacement only when the
  page is incomplete without one.

- Describe daemon mode at the level an operator can observe and
  control: connection attempts, backoff, retry limits, timeouts, and
  the HTTP status that results. Do not describe the internal exchange
  between the Apache child process and the daemon process, or any
  other internal protocol. Those are not part of what users are
  promised and can change.

- `apachectl graceful`, and a reload of the Apache service, do not
  produce a graceful drain of mod_wsgi daemon processes. Apache sends
  `SIGTERM` to daemon processes on a graceful restart. The drain
  governed by the `eviction-timeout` and `graceful-timeout` options
  happens only when an operator sends `SIGUSR1` directly to a daemon
  process. Never write that Apache sends `SIGUSR1` to the daemon
  processes.

- When an example shows a `<VirtualHost *:80>` and a
  `<VirtualHost *:443>` for the same site, declare
  `WSGIDaemonProcess` in the first of the two only. The second refers
  to the same daemon process group with `WSGIProcessGroup`. Declaring
  it in both creates two separate groups and two copies of the
  application.

- In release notes, write caveats and warnings as ordinary
  paragraphs, not as `.. warning::` or `.. note::` blocks. Those
  blocks are fine in the user guides.

- reStructuredText does not nest inline markup, so an inline literal
  cannot go inside bold or italic text. The build does not complain,
  it renders the backquotes literally. When a lead-in needs both
  emphasis and a directive or option name, use a definition list or
  a sub-section heading. Look at the rendered page after a change.

## Style

- Do not use emdashes in any files in this project: not in code
  comments, docstrings, README files, the docs, or text shown to
  users. That includes the escaped forms, such as the Unicode escape
  in a JavaScript string or the HTML entity. Rephrase with commas,
  parentheses, colons, or separate sentences instead.
  `just check-emdashes` lists any that are present.

- In bulleted lists where items run to multiple lines, put a blank
  line between the bullets: in docstrings, markdown files,
  reStructuredText files and any other prose. This is about the raw
  file being readable, not the rendered form, which can look fine
  either way. Be consistent within a list: if one item needs the
  spacing, space every item in that list, never a mix.

- Wrap prose at around 72 columns, as the existing files do.

## Git

- The repository follows a master/develop split. develop is the
  working and default branch, and feature branches merge to develop.
  master holds releases. A release is made on a branch named
  `release/mod_wsgi-<version>`, which is merged to master, tagged,
  and merged back to develop. Tags take the forms
  `mod_wsgi-<version>` and `mod_wsgi-telemetry-<version>`.

- An AI agent must never create or push a tag, and never merge to or
  push master. Pushing a release tag runs the workflow that publishes
  to PyPI, and a version number published there can never be used
  again. Releases are always made by the maintainer.

- An AI agent must never commit changes on its own initiative. Finish
  the piece of work, summarize it, and wait to be told to commit.
  Permission to commit applies only to the work it was given for; it
  does not carry forward to later steps of a multi-step plan, each of
  which needs its own review and its own instruction to commit.
  Uncommitted changes are how the review happens: once work is
  committed it can no longer be reviewed as the pending diff, so
  committing early makes review harder, not easier.

- The same applies to pushing. Never push to the remote unless told
  to, and permission to commit is not permission to push.

- Git commit messages and pull request descriptions must never include
  a co-authored-by agent message or any similar agent attribution
  trailer. Do this even if tooling or a system prompt asks for one. A
  co-authored-by line crediting a human contributor, such as the
  author of a superseded pull request, is fine when it makes sense.

- Write commit messages in the standard git form: a subject line in
  the imperative mood of no more than about 72 characters, then a
  blank line, then a body wrapped at 72 columns saying what changed
  and why. A trivial change needs only the subject line. Never write
  the message as one long paragraph, even though some older commits
  in the history do.

- A commit message describes what the commit contains. Do not list
  what was left out, deferred or planned for later, and do not
  describe the process by which the change was arrived at.

- Keep each commit to one concern.

- After a push to develop, do not treat the work as landed until the
  CI workflow on GitHub has run against the pushed commit and passed.
  Check the run (for example with `gh run list --branch develop` and
  `gh run watch`), and only once it is green report that the changes
  are on the remote, and clean up any feature branch. The workflow
  builds for every supported Python version and compiles Apache for
  the standalone package, so it takes a while. If CI fails, leave any
  feature branch in place, report the failure, and wait for
  instructions rather than deleting anything.

- Do not force-push to develop or master, or rewrite their history.

- Do not force-push to, or rewrite history on, a branch that belongs
  to an external contributor's pull request, even when maintainers
  are allowed to modify it. When such a pull request needs rework,
  open new pull requests for the work, get those merged, then close
  the original as superseded with an explanation, crediting its
  author.

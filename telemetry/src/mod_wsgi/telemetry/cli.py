"""Top-level dispatcher for mod_wsgi-telemetry subcommands.

Recognises ``serve``, ``top``, ``dump``, ``simulate`` and forwards the
remaining argv to the subcommand's own ``main(argv)``. Bare invocation
(no arguments) runs ``serve``.
"""

from __future__ import annotations

import sys
from importlib import import_module


_SUBCOMMANDS = {
    "serve":    ("mod_wsgi.telemetry.server",   "Run the ingestor and web UI (default)."),
    "top":      ("mod_wsgi.telemetry.tui",      "Curses terminal monitor."),
    "dump":     ("mod_wsgi.telemetry.dump",     "Bind the listen socket and print decoded samples."),
    "simulate": ("mod_wsgi.telemetry.simulate", "Emit synthetic samples for UI development."),
}


def _print_usage(stream) -> None:
    print("usage: mod_wsgi-telemetry <command> [options]", file=stream)
    print("", file=stream)
    print("commands:", file=stream)
    for name, (_, desc) in _SUBCOMMANDS.items():
        print(f"  {name:9s} {desc}", file=stream)
    print("", file=stream)
    print("Run 'mod_wsgi-telemetry <command> --help' for command-specific options.",
          file=stream)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv:
        cmd, rest = "serve", []
    elif argv[0] in ("-h", "--help"):
        _print_usage(sys.stdout)
        return 0
    elif argv[0] in _SUBCOMMANDS:
        cmd, rest = argv[0], argv[1:]
    else:
        print(f"mod_wsgi-telemetry: unknown subcommand or option {argv[0]!r}",
              file=sys.stderr)
        _print_usage(sys.stderr)
        return 2

    module_name, _ = _SUBCOMMANDS[cmd]
    sys.argv[0] = f"mod_wsgi-telemetry {cmd}"
    return import_module(module_name).main(rest)


if __name__ == "__main__":
    raise SystemExit(main())

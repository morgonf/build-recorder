"""`brec` — one entry point for the analysis layer.

Six scripts used to live in the repository root, each with its own argparse
block and its own answer to "where is the graph".  They are subcommands now:

    brec enrich    trace + rpm dump   -> package provenance
    brec verify    dependency report (static, dynamic, upstream verification)
    brec sbom      CycloneDX SBOM and CVE report for vendored components
    brec verdict   built-from-source / no-prebuilt-binary verdict
    brec buildreq  declared BuildRequires vs the packages actually read
    brec report    SPARQL summary of the raw trace

Run as ``python3 -m brec <command>``, or as ``brec <command>`` once installed.

Every command module is imported to build the parser, so they must stay cheap
to import; rdflib is pulled in only when `brec report` actually loads a graph,
which is why a missing rdflib breaks that one command and not the CLI.
"""

from __future__ import annotations

import argparse
import importlib
import sys

# subcommand -> (module, one-line help)
COMMANDS: dict[str, tuple[str, str]] = {
    "enrich": ("brec.commands.enrich",
               "add RPM package provenance to a trace"),
    "verify": ("brec.commands.verify",
               "build dependency report: static, dynamic, provenance"),
    "sbom": ("brec.commands.sbom",
             "CycloneDX SBOM and CVE report for vendored components"),
    "verdict": ("brec.commands.verdict",
                "built-from-source verdict (GREEN/RED/GREY)"),
    "buildreq": ("brec.commands.buildreq",
                 "declared BuildRequires vs the packages actually read"),
    "report": ("brec.commands.report",
               "SPARQL summary of a trace (requires rdflib)"),
}


def _load(name: str):
    return importlib.import_module(COMMANDS[name][0])


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="brec",
        description="Analyse a build-recorder trace.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest="command", metavar="COMMAND")
    for name, (_module, help_text) in COMMANDS.items():
        cmd = _load(name)
        p = sub.add_parser(
            name,
            help=help_text,
            description=(cmd.__doc__ or help_text).strip().splitlines()[0],
            epilog=cmd.__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        cmd.add_arguments(p)
        p.set_defaults(_run=cmd.run)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "command", None):
        ap.print_help()
        return 2
    return args._run(args)


if __name__ == "__main__":
    sys.exit(main())

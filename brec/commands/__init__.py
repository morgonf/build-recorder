"""Command modules behind the `brec` CLI.

Each module here exposes ``add_arguments(parser)`` and ``run(args) -> int``.
Nothing else: the analysis itself belongs to the `brec` package proper, and a
command module only decides how one report is asked for and printed.
"""


/*
Copyright (C) 2022 Valasiadis Fotios
Copyright (C) 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include "config.h"

#include <error.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "record.h"
#include "hash.h"

void run_and_record_fnames(char **av, char **envp);

// Best-effort: flush and close the Turtle output before dying on a fatal
// signal, so the .out stays valid RDF instead of being truncated mid-statement
// (stdio is block-buffered). stdio calls are not strictly async-signal-safe,
// but this is a last resort on the way to the default action, and losing the
// whole buffer is worse. record_stop() is idempotent (guards fout == NULL).
static void
flush_on_fatal_signal(int sig)
{
    record_stop();
    signal(sig, SIG_DFL);
    raise(sig);
}

int
main(int argc, char **argv, char **envp)
{
    if (argc < 2)
	error(EX_USAGE, 0, "missing command to record");

    char *output_fname = "build-recorder.out";

    ++argv;			       // skip our own argv[0]
    while (*argv && argv[0][0] == '-') {
	if (!strcmp(*argv, "-o") && argv[1]) {
	    output_fname = argv[1];
	    argv += 2;
	} else if (!strcmp(*argv, "-2") || !strcmp(*argv, "--sha256")) {
	    hash_set_algorithm("sha256");
	    ++argv;
	} else {
	    break;
	}
    }

    if (!*argv)
	error(EX_USAGE, 0, "missing command to record");

    record_start(output_fname);

    // Close the Turtle on any normal exit (including error(EXIT_FAILURE, ...))
    // and on a fatal signal, so a killed or crashing tracer still leaves a
    // parseable .out.
    atexit(record_stop);

    static const int fatal_signals[] = {
	SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGABRT, SIGFPE, SIGBUS, SIGSEGV,
	SIGTERM,
    };
    for (size_t i = 0; i < sizeof (fatal_signals) / sizeof (*fatal_signals); ++i)
	signal(fatal_signals[i], flush_on_fatal_signal);

    run_and_record_fnames(argv, envp);

    exit(EXIT_SUCCESS);
}


# Copyright (C) 2022 Alexios Zavras
# Copyright (C) 2022 Valasiadis Fotios
# SPDX-License-Identifier: LGPL-2.1-or-later

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src examples benchmark

# "make check" also runs the Python test suite of the analysis layer. Missing
# pytest is reported and skipped rather than failing the build: a C-only
# checkout stays buildable and testable on its own terms.
if HAVE_PYTHON
check-local:
	@if $(PYTHON) -c 'import pytest' 2>/dev/null; then \
	    cd $(srcdir) && $(PYTHON) -m pytest tests -q; \
	else \
	    echo "pytest not installed: skipping the Python test suite"; \
	fi
else
check-local:
	@echo "no python interpreter found: skipping the Python test suite"
endif


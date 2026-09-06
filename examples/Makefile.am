# Copyright (C) 2023 Alexios Zavras
# SPDX-License-Identifier: LGPL-2.1-or-later

EXE = ../build-recorder

EXAMPLES = \
	compile_single_file \
	compile_link_file \
	compile_file_include \
	compile_file_sysinclude \
	compile_two_files \
	trace_threads \
	$(EMPTY)

all:

examples: $(EXAMPLES)

compile_single_file: f1.c
	$(EXE) -o $@.out $(CC) -c $^

compile_link_file: f1.c
	$(EXE) -o $@.out $(CC) $^

compile_file_include: f2.c
	$(EXE) -o $@.out $(CC) -c $^

compile_file_sysinclude: f3.c
	$(EXE) -o $@.out $(CC) -c $^

compile_two_files: f4.c f5.c
	$(EXE) -o $@.out $(CC) $^

# One process, two threads: the read and the write must land under one subject.
trace_threads: threads.c
	$(CC) -o threads $^ -lpthread
	echo "input line" > threads-input.txt
	$(EXE) -o $@.out ./threads


clean:
	$(RM) *.o a.out threads threads-input.txt threads-output.o

clobber: clean
	$(RM) *.out


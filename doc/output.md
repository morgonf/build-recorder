# build-recorder output format

Each run of `build-recorder` generates a single output file.

The information is represented in RDF triples,
saved in Turtle format.

## Ontology

The special types and predicates used are listed below:

### Types

#### Process
- pid: the process id
- cmd: the actual command line (concatenation of all arguments separated by white space)
- start: timestamp
- end: timestamp
- env: environment entry, in the form of "VAR=value"
- coverage_gap: names a mechanism the process used whose file I/O this tracer
  cannot observe (currently `"io_uring"`). Reads and writes performed through it
  are missing from the graph, so no completeness claim holds for this process.
  Emitted once per process and per mechanism.

A process node is a process, not a thread. Threads share the address space and
the descriptor table of their group leader, so a file a thread reads, the
process read: every thread records under the leader's subject, and no `creates`
edge is emitted for one. Giving each thread a subject of its own split a single
program's reads and writes across unrelated nodes, which is how rustc, reading
a crate on one thread and writing the object on another, produced objects with
no lineage at all.



#### File
- name: the file name
- size: the file size, in bytes
- hash: a hexadecimal string of a unique, git-compatible, hash of the content of the file
- abspath: the file's absolute path



### Relationships

#### execs
- Domain: Process
- Range: Process

#### reads
- Domain: Process
- Range: File

#### writes
- Domain: Process
- Range: File

#### creates
- Domain: Process
- Range: Process

#### executable
- Domain: Process
- Range: File

#### rename
- Domain: Process
- Range: a blank node holding the two ends of the rename

A rename relates two file nodes, the name before and the name after, so it is
not a single predicate on a file; it goes through an intermediate blank node:

```
:p3         b:rename       _:rename0 .
_:rename0   b:rename-from  :f7 .
_:rename0   b:rename-to    :f8 .
```

Both file nodes carry the same hash: the content is hashed on syscall entry,
before the operation takes place, and the destination node inherits it.

#### hardlink
- Domain: Process
- Range: a blank node holding the two ends of the link

Recorded for `link(2)` and `linkat(2)`, with the same shape as `rename`:

```
:p3         b:hardlink       _:hardlink0 .
_:hardlink0 b:hardlink-from  :f7 .
_:hardlink0 b:hardlink-to    :f8 .
```

The difference from a rename is that the old name survives: a hardlink gives a
second name to one inode, so both file nodes share content and hash and both
paths remain valid. This is worth recording because content entering a build
tree this way is otherwise unobservable, there being no open, read or write to
intercept.



## Example

The example below is fictional
and is only to be used to represent typical uses.

The example is about a fictional compiler (`compile`),
called to compile a single file (`foo.c`).
The compiler calls a preprocesor (`preprocess`)
to generate a temporary file (`tmp.c`)
and then generate the object code in (`foo.o`)

```
pid1	a	process .
pid1	cmd	"compile -o foo.c" .
pid1	start	20220804T100000 .

pid2	a	process .
pid2	cmd	"preprocess foo.c tmp.c"
pid2	start	20220804T100000 .

pid1	execs	pid2 .

f1	a	file .
f1	name	"foo.c" .
f1	size	100 .
f1	hash	"0000000000000000000000000000000000000000" .

f2	a	file .
f2	name	"tmp.c" .
f2	size	888 .
f2	hash	"1111111111111111111111111111111111111111" .

pid2	reads	f1 .
pid2	writes	f2 .

pid3	a	process .
pid3	cmd	"c2o tmp.c foo.o" .

pid1	execs	pid3 .
pid3	reads	f2 .

f3	a	file .
f3	name	"foo.o" .
f3	size	444 .
f3	hash	"2222222222222222222222222222222222222222" .

pid3	writes	f3 .

```

The example is simplified on purpose,
since it does not show, for example,
the reading of the file of the executable "preprocess".


# Build-recorder

The purpose of this project is
to fully record the interactions
between assets (files and tools)
when a software artifact is being built (compiled).

## Usage
**build-recorder** [-o outfile] [-2 | --sha256] command
* outfile: The output file, by default "build-recorder.out".
* -2, --sha256: Hash file contents with git-blob SHA-256 instead of the
  default git-blob SHA-1. The default keeps hashes interchangeable with git
  and with package metadata; SHA-256 is what an adversarial setting calls
  for, where a SHA-1 collision could let a prebuilt binary carry the hash of
  a file that was built from source.
* command: The original build command with all its arguments.
    * e.g. cc -o hello helloworld.c

Options must come before the command; the first argument that is not a
recognised option starts the command line to record. See
**build-recorder**(1) for the full description.

## Description
**build-recorder** is a command line tool for linux 5.3+ that records
information about build processes. It achieves this by running transparently
in the background while the build process is running, tracing it
and extracting all relevant information, which it then stores in the output
file in RDF Turtle format.

A complete schema for the generated RDF can be found in doc/output.md.

**build-recorder** works regardless of the programming language, build system
or configuration used. In fact there is no limitation as to what the supplied 
command should be. If it runs, **build-recorder** can trace it.

## Build
To build it you are going to need the following tools:
* A C compiler
* make

As well as the following libraries:
* libcrypto
### Build from github repository
In order to build from the github repository directly, you are also going
to need
* autoconf
* automake

On the project's top-level directory, run:
```
autoreconf -i
./configure
make
```

### Build from release tarball
Assuming you've downloaded the tarball:
```
tar -xf <build-recorder-release>.tar.gz
cd <build-recorder-release>
./configure
make
```

## License

The code is licensed under
GNU Lesser General Public License v2.1 or later
(`LGPL-2.1-or-later`).


#!/bin/sh
# Reproduce the archive-member experiment: which members of a static archive
# can be told from the link's syscalls alone.  Needs gcc, GNU ld (bfd, gold),
# strace; go for the cgo case (skipped if absent).  Works in a temp directory.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT; cd "$w"
run() { log=$1; shift; strace -f -qq -e trace=openat,read,pread64,lseek,mmap,close,dup,dup2,dup3,fcntl -o "$log" "$@"; }

# Archive of twelve small members, g1..g12; the program calls g6 and g9.
for i in $(seq 1 12); do echo "int g$i(void){return $i;}" > s$i.c; done
gcc -c s*.c && ar rcs libs.a $(ls s*.o | sort -V)
echo 'int g6(void);int g9(void);int main(void){return g6()+g9();}' > m.c && gcc -c m.c

for ld in bfd gold; do
  for plug in on off; do
    flag=; [ $plug = off ] && flag=-fno-use-linker-plugin
    run t.log gcc -fuse-ld=$ld $flag -o p m.o libs.a
    ./p || rc=$?; echo "== ld.$ld, LTO plugin $plug (exit ${rc:-0}, expect 15)"; rc=
    python3 -I "$here/ar_reads.py" t.log libs.a
  done
done

if command -v go >/dev/null; then
  mkdir g && cp libs.a g/ && cd g
  printf 'module x\ngo 1.20\n' > go.mod
  cat > main.go <<'GO'
package main

/*
#cgo LDFLAGS: -L${SRCDIR} -ls
int g6(void);
int g9(void);
*/
import "C"
import "os"

func main() { os.Exit(int(C.g6() + C.g9())) }
GO
  GOCACHE="$w/gocache" run t.log go build -ldflags=-linkmode=external -o p .
  ./p || rc=$?; echo "== go cgo, external link (exit ${rc:-0}, expect 15)"; rc=
  python3 -I "$here/ar_reads.py" t.log libs.a
fi

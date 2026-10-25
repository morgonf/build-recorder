#!/usr/bin/env python3
"""Which members of a static archive did the link read?

Reads an strace log (-f, with openat, read, pread64, lseek, close, dup*, fcntl) and the
archive itself, and prints per member how much of it each open descriptor
read and whether a descriptor read the member's first bytes in a short read.

The short read at a member's start is what the gcc LTO plugin does with every
object the linker loads (it checks the ELF header for LTO sections), so it
marks the members that went into the link.  A full-coverage column is printed
too: GNU ld reads loaded members whole, but through 4 KiB buffers that also
cover the neighbours of a loaded member.

usage: ar_reads.py STRACE_LOG ARCHIVE
"""
import re
import sys

BUF = 4096


def members(path):
    d = open(path, 'rb').read()
    if d[:8] != b'!<arch>\n':
        sys.exit(f'{path}: not an ar archive')
    i, out = 8, []
    while i + 60 <= len(d):
        name = d[i:i + 16].decode().strip()
        size = int(d[i + 48:i + 58])
        if name not in ('/', '//', '/SYM64/'):
            out.append((name.rstrip('/'), i + 60, i + 60 + size))
        i += 60 + size + (size & 1)
    return out


def reads(log, base):
    fds, pos, out, n = {}, {}, [], 0
    pat = re.compile(r'(\d+) (\w+)\((.*)\)\s+= (-?\d+)')
    for line in open(log):
        m = pat.match(line)
        if not m:
            continue
        pid, call, args, ret = m.group(1), m.group(2), m.group(3), int(m.group(4))
        if call == 'openat':
            if ret >= 0 and (f'/{base}"' in args or f'"{base}"' in args):
                fds[(pid, ret)] = n
                pos[(pid, ret)] = 0
                n += 1
            continue
        try:
            k = (pid, int(args.split(',', 1)[0]))
        except ValueError:
            continue
        if k not in fds:
            continue
        if call == 'close':
            del fds[k]
        elif call in ('dup', 'dup2', 'dup3') and ret >= 0:
            fds[(pid, ret)] = fds[k]
            pos[(pid, ret)] = pos[k]
        elif call == 'fcntl' and 'F_DUPFD' in args and ret >= 0:
            fds[(pid, ret)] = fds[k]
            pos[(pid, ret)] = pos[k]
        elif call == 'lseek':
            pos[k] = ret
        elif call == 'read' and ret > 0:
            out.append((fds[k], pos[k], ret))
            pos[k] += ret
        elif call == 'pread64' and ret > 0:
            out.append((fds[k], int(args.rsplit(',', 1)[1]), ret))
    return out


def main():
    log, ar = sys.argv[1], sys.argv[2]
    mem, rd = members(ar), reads(log, ar.rsplit('/', 1)[-1])
    print(f'{"member":12s} {"full":>5s} {"head":>5s}')
    for name, a, b in mem:
        got = set()
        for _, s, ln in rd:
            got.update(range(max(a, s), min(b, s + ln)))
        full = len(got) == b - a
        head = any(s == a and ln < BUF for _, s, ln in rd)
        print(f'{name:12s} {"yes" if full else "-":>5s} {"yes" if head else "-":>5s}')


if __name__ == '__main__':
    main()

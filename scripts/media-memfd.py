#!/usr/bin/env python3
"""Linux-only seekable, anonymous RAM files. Never create a filesystem scratch file."""
import os
import resource
import subprocess
import sys


class InvalidMedia(ValueError):
    """A deterministic file rejection, distinct from an unavailable worker."""


def main():
    input_limit, output_limit = map(int, sys.argv[1:3])
    if not 0 < input_limit <= 256 * 1024 * 1024 or not 0 < output_limit <= 264 * 1024 * 1024:
        raise ValueError('Invalid limits')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = os.memfd_create('vera-media-input', os.MFD_CLOEXEC)
    target = os.memfd_create('vera-media-output', os.MFD_CLOEXEC)
    try:
        size = 0
        with os.fdopen(source, 'wb', closefd=False) as writer:
            while chunk := sys.stdin.buffer.read(64 * 1024):
                size += len(chunk)
                if size > input_limit:
                    raise InvalidMedia('Oversized input')
                writer.write(chunk)
        if not size:
            raise InvalidMedia('Empty input')
        os.lseek(source, 0, os.SEEK_SET)
        replacements = {'@INPUT@': f'/proc/self/fd/{source}', '@OUTPUT@': f'/proc/self/fd/{target}'}
        args = [replacements.get(arg, arg) for arg in sys.argv[3:]]
        try:
            subprocess.run(['prlimit', '--as=536870912', '--cpu=30',
                            f'--fsize={output_limit + 1}', '--nofile=64', '--core=0', '--', 'ffmpeg', *args],
                           pass_fds=(source, target), stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60, check=True)
        except subprocess.CalledProcessError as error:
            # FFmpeg 7 returns AVERROR values from main rather than always 1.
            # POSIX retains the low byte: AVERROR_INVALIDDATA -> 183,
            # AVERROR_EOF -> 187, AVERROR(EINVAL) -> 234. Do not classify OOM, signals, or missing
            # commands as invalid evidence.
            if error.returncode in (1, 183, 187, 234):
                raise InvalidMedia('Unsupported media') from None
            raise
        if not 0 < os.fstat(target).st_size <= output_limit:
            raise InvalidMedia('Invalid output size')
        os.lseek(target, 0, os.SEEK_SET)
        while chunk := os.read(target, 64 * 1024):
            sys.stdout.buffer.write(chunk)
    finally:
        os.close(source)
        os.close(target)


if __name__ == '__main__':
    try:
        main()
    except InvalidMedia:
        sys.exit(2)
    except Exception:
        # Do not expose parser diagnostics or plaintext.
        sys.exit(1)

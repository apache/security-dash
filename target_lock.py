import fcntl
import os
from contextlib import contextmanager

# Every tool that writes into the target directory (the JSON files, the
# label cache, the ledger, and the git index via `git mv`/`git rm`) must
# hold this lock while doing so, so that the watch-changes daemon, the
# label-renames daemon, one-off `-s`/`-p` runs and any future writer
# never interleave their writes.
#
# This is an advisory flock(2): it is released automatically when the
# holder closes the file or dies, so a crashed process never leaves a
# stale lock behind. The file itself is never removed (removing it would
# let two processes lock two different inodes).
LOCK_FILENAME = ".security-dashboard-backend.lock"

@contextmanager
def target_lock(target_dir):
    path = os.path.join(target_dir, LOCK_FILENAME)
    # Python opens fds non-inheritable, so git subprocesses started while
    # holding the lock don't keep it alive after we release it.
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"Waiting for lock on {path}")
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        # Closing the fd releases the lock.
        os.close(fd)

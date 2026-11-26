import fcntl
import os
import subprocess
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

def _git(target_dir, *args):
    return subprocess.run(["git", *args], cwd=target_dir).returncode

def _git_commit_all(target_dir, message):
    # Stages additions, modifications and deletions under target_dir and
    # commits them. The target repo's .gitignore must exclude the lockfile
    # and *.tmp (half-written files a holder that died mid-write may leave
    # behind). Only ever called while holding the lock, so it can't race
    # another writer's git operations.
    #
    # Failures are reported, not raised: whatever we fail to commit is
    # picked up by the next lock holder.
    status = _git(target_dir, "add", "-A", "--", ".")
    if status != 0:
        print(f"git add in {target_dir} failed (status code {status})")
        return
    # Exit status 1 means there are staged changes; skip empty commits.
    status = _git(target_dir, "diff", "--cached", "--quiet", "--", ".")
    if status == 0:
        return
    if status != 1:
        print(f"git diff in {target_dir} failed (status code {status})")
        return
    status = _git(target_dir, "commit", "--quiet", "-m", message, "--", ".")
    if status != 0:
        print(f"git commit in {target_dir} failed (status code {status})")

@contextmanager
def target_lock(target_dir, holder):
    # holder: who is taking the lock, used in commit messages.
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
        # Commit anything left uncommitted since the last holder released
        # the lock (a holder that crashed, or manual edits), so that the
        # commit we make on release only holds this holder's changes.
        _git_commit_all(target_dir, f"Uncommitted changes found by {holder}")
        try:
            yield
        finally:
            # Also on an exception: every file is written atomically, so
            # the tree holds only complete files even after a partial batch.
            _git_commit_all(target_dir, f"Changes by {holder}")
    finally:
        # Closing the fd releases the lock.
        os.close(fd)

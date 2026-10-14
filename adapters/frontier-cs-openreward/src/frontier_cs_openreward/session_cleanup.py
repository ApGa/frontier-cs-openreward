"""Remove private session trees after their processes and leases are stopped."""

import os
from pathlib import Path
import shutil
import stat


def remove_session_tree(path: Path) -> None:
    """Restore directory access without following links or changing file modes.

    Task tests and package managers can create directories with mode 000 or
    0555. Restore owner rwx top-down so rmtree can traverse and unlink them.
    Callers must hold the session lease and stop its processes first.
    """
    def writable_directory(directory: Path) -> None:
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode):
            return
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise RuntimeError(f"session directory is not owned by this service: {directory}")
        directory.chmod(stat.S_IMODE(info.st_mode) | 0o700)

    if path.is_symlink():
        raise RuntimeError(f"session tree must not be a symlink: {path}")
    try:
        writable_directory(path)
    except FileNotFoundError:
        return

    def walk_error(error: OSError) -> None:
        raise error

    for directory, directories, _files in os.walk(path, followlinks=False, onerror=walk_error):
        for name in directories:
            writable_directory(Path(directory) / name)
    shutil.rmtree(path)

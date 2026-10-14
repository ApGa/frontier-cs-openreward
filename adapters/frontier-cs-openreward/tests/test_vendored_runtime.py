"""The vendored sandbox runtime is the SWE-rebench V2 source plus one import edit."""
import hashlib
from pathlib import Path

from frontier_cs_openreward import runtime, sandbox_backends, session_cleanup

# ApGa/SWE-rebench-V2-OpenRewardEnv at ac655366358b891419ba7287f82e69efb21434e2.
SOURCE_SHA256 = {
    "sandbox_backends.py": "ad07a3bfe1118a45cc3fd6b5ec227041ae98af24691e7938d5c948d4e96dd8da",
    "session_cleanup.py": "a1e3ed3590dbd59f813b53d4275ceb5279b7ba174dbe59169bf30401f7f634e1",
}
# The only local edit: import the sibling module relative to this package.
SOURCE_IMPORT = b"\nfrom session_cleanup import remove_session_tree\n"
VENDORED_IMPORT = b"\nfrom .session_cleanup import remove_session_tree\n"


def test_vendored_files_match_the_source_commit():
    package = Path(runtime.__file__).parent
    for name, digest in SOURCE_SHA256.items():
        data = (package / name).read_bytes()
        if name == "sandbox_backends.py":
            assert data.count(VENDORED_IMPORT) == 1
            data = data.replace(VENDORED_IMPORT, SOURCE_IMPORT)
        assert hashlib.sha256(data).hexdigest() == digest, name


def test_runtime_uses_the_vendored_modules():
    assert runtime._backend_module() is sandbox_backends
    assert sandbox_backends.remove_session_tree is session_cleanup.remove_session_tree

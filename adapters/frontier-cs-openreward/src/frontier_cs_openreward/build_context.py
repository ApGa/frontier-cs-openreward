"""Create a private judge build context without modifying benchmark sources."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from .catalog import UPSTREAM_REVISION, _verify_source_pin


def prepare_algorithmic(root: Path, output: Path) -> None:
    _verify_source_pin(root, UPSTREAM_REVISION)
    output.mkdir(parents=True, exist_ok=False)
    source = root / "algorithmic"
    for name in ("package.json", "package-lock.json", "server.js", "entrypoint.sh"):
        shutil.copy2(source / name, output / name)
    for name in ("src", "include", "config"):
        shutil.copytree(source / "judge" / name, output / name)

    # The Docker deployment isolates these APIs on an internal network. HPC
    # instances share host networking, so both private APIs need credentials.
    server = output / "server.js"
    text = server.read_text()
    anchor = "const app = express();"
    assert text.count(anchor) == 1
    text = text.replace(anchor, anchor + '''
const engineToken = process.env.FRONTIER_ENGINE_AUTH_TOKEN;
if (!engineToken) throw new Error('FRONTIER_ENGINE_AUTH_TOKEN is required');
app.use((req, res, next) => {
    if (req.get('Authorization') !== `Bearer ${engineToken}`) {
        return res.status(401).json({error: 'unauthorized'});
    }
    next();
});
''')
    server.write_text(text)

    client = output / "src/gojudge.js"
    text = client.read_text()
    anchor = "this.baseURL = baseURL;"
    assert text.count(anchor) == 1
    text = text.replace(anchor, anchor + '''
        const token = process.env.GJ_AUTH_TOKEN;
        if (!token) throw new Error('GJ_AUTH_TOKEN is required');
        this.http = axios.create({headers: {Authorization: `Bearer ${token}`}});
''')
    for verb in ("get", "post", "delete"):
        text = text.replace(f"axios.{verb}(", f"this.http.{verb}(")
    client.write_text(text)
    hashes = {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "openreward-build.json").write_text(json.dumps({
        "upstream_revision": UPSTREAM_REVISION,
        "changes": ["Require bearer authentication on Node API", "Authenticate go-judge requests"],
        "sha256": hashes,
    }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare_algorithmic(args.source, args.output)

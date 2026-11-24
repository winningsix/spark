"""Rebuild the three benchmark JARs in a new output directory."""
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def digest(path):
    with path.open("rb") as handle:
        checksum = hashlib.sha256()
        for block in iter(lambda: handle.read(1 << 20), b""):
            checksum.update(block)
        return checksum.hexdigest()


def verify(path, expected):
    if digest(path) != expected:
        raise ValueError(f"SHA-256 mismatch for {path.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_jars", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    manifest = json.loads((here.parent / "build.json").read_text())
    output = args.output.resolve()
    if output.exists():
        parser.error("choose a new output directory")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        stage = Path(tmp) / "jars"
        stage.mkdir()
        for name, expected in manifest["base_jars_sha256"].items():
            source = args.base_jars / name
            verify(source, expected)
            shutil.copyfile(source, stage / name)
        # An empty temporary repository keeps git apply independent of the caller's checkout.
        subprocess.run(["git", "init", "-q", str(stage)], check=True)
        subprocess.run(["git", "-C", str(stage), "apply", "--binary",
                        str(here / "spark-classes.patch")], check=True)
        shutil.copyfile(here / "factor-rate-count.jar", stage / "factor-rate-count.jar")
        for name, info in manifest["tested_overlays"].items():
            verify(stage / name, info["patched_jar_sha256"])
        shutil.rmtree(stage / ".git")
        stage.rename(output)


if __name__ == "__main__":
    main()

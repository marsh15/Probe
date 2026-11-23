"""Assemble an image from the official slim interpreter and its ELF dependencies."""

import re
import shutil
import subprocess
from pathlib import Path

OUTPUT = Path("/runtime")


def copy(source):
    target = OUTPUT / source.relative_to("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


shutil.copytree("/usr/local", OUTPUT / "usr/local", symlinks=True)
shutil.copytree("/app/.venv", OUTPUT / "app/.venv", symlinks=True)
# Discover dependencies of the interpreter AND every extension module. ldd also
# reports transitive dependencies; paths are from this trusted builder filesystem.
elves = [Path("/usr/local/bin/python3.12")]
elves.extend(Path("/usr/local").rglob("*.so*"))
elves.extend(Path("/app/.venv").rglob("*.so*"))
libraries = set()
for elf in elves:
    if elf.name.startswith("_tkinter"):
        (OUTPUT / elf.relative_to("/")).unlink(missing_ok=True)
        continue
    result = subprocess.run(  # noqa: S603 - fixed ldd tool and builder-owned ELF paths
        ["/usr/bin/ldd", str(elf)], capture_output=True, text=True, check=False
    )
    if "not found" in result.stdout:
        raise RuntimeError(f"missing runtime dependency: {elf}")
    libraries.update(
        Path(path) for path in re.findall(r"(?:=>\s+|^\s*)(/\S+)", result.stdout, re.M)
    )
for library in sorted(libraries):
    if not str(library).startswith("/usr/local/"):
        copy(library)
for path in ("/etc/nsswitch.conf", "/etc/ssl/certs/ca-certificates.crt"):
    copy(Path(path))
for name in ("pip", "setuptools", "ensurepip", "idlelib", "tkinter"):
    for path in (
        OUTPUT / "usr/local/lib/python3.12" / name,
        OUTPUT / "usr/local/lib/python3.12/site-packages" / name,
    ):
        if path.is_dir():
            shutil.rmtree(path)
for path in (OUTPUT / "usr/local/lib/python3.12/site-packages").glob("pip-*.dist-info"):
    shutil.rmtree(path)
for path in (OUTPUT / "usr/local/bin").glob("pip*"):
    path.unlink()
for path in OUTPUT.rglob("__pycache__"):
    shutil.rmtree(path)

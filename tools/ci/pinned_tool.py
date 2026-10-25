"""Download one exact, checksum-verified executable into an isolated directory."""

from contextlib import contextmanager
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import urllib.request


@contextmanager
def executable(url, expected, member):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("pinned tool download size/checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="naome-ci-tool-") as name:
        binary = Path(name) / Path(member).name
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            entry = archive.getmember(member)
            if not entry.isfile() or entry.size > 128 * 1024 * 1024:
                raise ValueError("unexpected pinned tool archive member")
            binary.write_bytes(archive.extractfile(entry).read())
        binary.chmod(0o700)
        yield binary

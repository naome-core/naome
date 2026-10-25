"""Keep repository guidance at its consumers and prevent Markdown recreation."""

from pathlib import Path, PurePosixPath
import subprocess

ROOT = Path(__file__).resolve().parents[2]
MARKDOWN_SUFFIXES = {".md", ".markdown", ".mdown", ".mkd", ".mdx"}


def rejected(paths):
    return sorted(path for path in paths if PurePosixPath(path).suffix.casefold() in MARKDOWN_SUFFIXES
                  and PurePosixPath(path).name != "AGENTS.md")


def check():
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    invalid = rejected(paths)
    if invalid:
        raise ValueError("Markdown files other than AGENTS.md are not allowed: " + ", ".join(invalid))


if __name__ == "__main__":
    check()

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK_DIRS = ("src", "tests", "tools")
TEXT_SUFFIXES = {".py", ".toml", ".md"}


def iter_text_files() -> list[Path]:
    files: list[Path] = []
    for directory in CHECK_DIRS:
        root = ROOT / directory
        if not root.exists():
            continue
        files.extend(
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix in TEXT_SUFFIXES
        )
    files.append(ROOT / "pyproject.toml")
    return sorted(set(files))


def main() -> int:
    failures: list[str] = []
    for path in iter_text_files():
        text = path.read_text(encoding="utf-8")
        if text and not text.endswith("\n"):
            failures.append(f"{path.relative_to(ROOT)}: missing final newline")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line.rstrip(" \t") != line:
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: trailing whitespace"
                )
            if "\t" in line:
                failures.append(f"{path.relative_to(ROOT)}:{line_number}: tab found")
    if failures:
        print("\n".join(failures))
        return 1
    print("format check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


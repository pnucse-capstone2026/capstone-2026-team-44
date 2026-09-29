from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_DIRS = ("src", "tests", "tools")
FORBIDDEN_SRC_IMPORTS = {
    "faiss",
    "flask",
    "fastapi",
    "ollama",
    "playwright",
    "psycopg",
    "requests",
    "sentence_transformers",
    "sqlalchemy",
}
SRC_IMPORT_ALLOWLIST = {
    Path("src/vulnspider/discovery/dynamic_browser.py"): {"playwright"},
}


def iter_python_files() -> list[Path]:
    files: list[Path] = []
    for directory in PYTHON_DIRS:
        root = ROOT / directory
        if root.exists():
            files.extend(path for path in root.rglob("*.py") if path.is_file())
    return sorted(files)


def imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def main() -> int:
    failures: list[str] = []
    for path in iter_python_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            failures.append(f"{path.relative_to(ROOT)}:{exc.lineno}: {exc.msg}")
            continue
        relative_path = path.relative_to(ROOT)
        if relative_path.parts[0] == "src":
            allowed = SRC_IMPORT_ALLOWLIST.get(relative_path, set())
            forbidden = imported_roots(tree) & FORBIDDEN_SRC_IMPORTS - allowed
            if forbidden:
                imports = ", ".join(sorted(forbidden))
                failures.append(f"{relative_path}: forbidden import: {imports}")
    if failures:
        print("\n".join(failures))
        return 1
    print("lint check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

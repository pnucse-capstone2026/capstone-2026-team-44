from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
import typing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def iter_vulnspider_modules() -> list[str]:
    package = importlib.import_module("vulnspider")
    return sorted(
        module_info.name
        for module_info in pkgutil.walk_packages(
            package.__path__,
            prefix=f"{package.__name__}.",
        )
    )


def validate_type_hints(module_name: str) -> list[str]:
    module = importlib.import_module(module_name)
    failures: list[str] = []
    for name, obj in vars(module).items():
        if name.startswith("_"):
            continue
        if inspect.isfunction(obj) or inspect.isclass(obj):
            try:
                typing.get_type_hints(obj)
            except Exception as exc:  # noqa: BLE001 - report any invalid hint.
                failures.append(f"{module_name}.{name}: invalid type hint: {exc}")
    return failures


def main() -> int:
    sys.path.insert(0, str(SRC))
    failures: list[str] = []
    for module_name in iter_vulnspider_modules():
        failures.extend(validate_type_hints(module_name))
    if failures:
        print("\n".join(failures))
        return 1
    print("type-hint check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


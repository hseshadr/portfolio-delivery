"""Executable architecture proof for the provider-independent packages."""

from __future__ import annotations

import ast
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Final

import pytest


def _source_repository_root(candidate: Path) -> Path:
    return candidate.parent if candidate.name == "mutants" else candidate


PURE_PACKAGES: Final = ("domain", "contracts", "envelope", "application")
FORBIDDEN_ROOTS: Final = frozenset(
    {
        "azure",
        "boto3",
        "dagger",
        "github",
        "gitlab",
        "google",
        "httpx",
        "pathlib",
        "requests",
        "socket",
        "subprocess",
    }
)
TEST_ROOT: Final = Path(__file__).parents[2]
ROOT: Final = _source_repository_root(TEST_ROOT)
SOURCE_ROOT: Final = ROOT / "src/portfolio_delivery"
MUTATION_PRAGMA: Final = "# pragma: no mutate"
REVIEWED_EQUIVALENT_SUPPRESSIONS: Final = frozenset(
    {
        ("src/portfolio_delivery/adapters/oras.py", "records = cast(tuple[T, ...], actual)"),
        (
            "src/portfolio_delivery/envelope/builder.py",
            "return cast(tuple[ReleaseChannel, ...], channels)",
        ),
        ("src/portfolio_delivery/envelope/canonical.py", "return cast(JsonValue, parsed)"),
        ("src/portfolio_delivery/envelope/canonical.py", 'text = content.decode("utf-8")'),
    }
)


def test_should_resolve_original_source_from_mutmut_workspace(tmp_path: Path) -> None:
    # Given
    source_root = tmp_path / "repository"

    # When / Then
    assert _source_repository_root(source_root / "mutants") == source_root


def _pure_paths() -> tuple[Path, ...]:
    return tuple(
        path for package in PURE_PACKAGES for path in sorted((SOURCE_ROOT / package).glob("*.py"))
    )


def _module_name(path: Path) -> str:
    relative = path.relative_to(ROOT / "src").with_suffix("")
    return ".".join(relative.parts)


def _imported_roots(path: Path) -> frozenset[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = (name for node in ast.walk(tree) for name in _import_names(node))
    return frozenset(name.split(".", 1)[0] for name in imports if name)


def _import_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Import):
        return tuple(alias.name for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        return (node.module or "",)
    return ()


def _unsafe_mutation_suppressions(path: Path) -> tuple[int, ...]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    diagnostic_lines = _permitted_diagnostic_lines(tree)
    return tuple(
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if MUTATION_PRAGMA in line
        and not _is_reviewed_suppression(path, line)
        and number not in diagnostic_lines
    )


def _is_reviewed_suppression(path: Path, line: str) -> bool:
    key = _suppression_key(path, line, ROOT)
    return key in REVIEWED_EQUIVALENT_SUPPRESSIONS


def _suppression_key(path: Path, line: str, root: Path) -> tuple[str, str] | None:
    try:
        relative = str(path.relative_to(root))
    except ValueError:
        return None
    code = line.split(MUTATION_PRAGMA, maxsplit=1)[0].strip()
    return relative, code


def _reviewed_suppression_counts(paths: tuple[Path, ...], root: Path) -> Counter[tuple[str, str]]:
    counts: Counter[tuple[str, str]] = Counter()
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            key = _suppression_key(path, line, root)
            if MUTATION_PRAGMA in line and key in REVIEWED_EQUIVALENT_SUPPRESSIONS:
                counts[key] += 1
    return counts


def _has_exact_reviewed_suppressions(paths: tuple[Path, ...], root: Path) -> bool:
    expected = Counter({key: 1 for key in REVIEWED_EQUIVALENT_SUPPRESSIONS})
    return _reviewed_suppression_counts(paths, root) == expected


def _permitted_diagnostic_lines(tree: ast.Module) -> frozenset[int]:
    assignment_lines = {
        line
        for node in ast.walk(tree)
        if _is_diagnostic_assignment(node)
        for line in _node_lines(node)
    }
    rendered_lines = {
        line
        for node in ast.walk(tree)
        if _is_template_rendering(node)
        for line in _node_lines(node)
    }
    return frozenset(assignment_lines | rendered_lines)


def _is_diagnostic_assignment(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return False
    target = node.targets[0]
    return (
        isinstance(target, ast.Name)
        and target.id.endswith(("_MESSAGE", "_TEMPLATE"))
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    )


def _node_lines(node: ast.AST) -> range:
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start)
    if not isinstance(start, int) or not isinstance(end, int):
        return range(0)
    return range(start, end + 1)


def _is_template_rendering(node: ast.AST) -> bool:
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return False
    target, value = node.targets[0], node.value
    return (
        isinstance(target, ast.Name)
        and _is_diagnostic_name(target.id)
        and isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "format"
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id.endswith("_TEMPLATE")
        and not value.args
        and bool(value.keywords)
        and all(_is_matching_name_keyword(keyword) for keyword in value.keywords)
    )


def _is_matching_name_keyword(keyword: ast.keyword) -> bool:
    return (
        keyword.arg is not None
        and isinstance(keyword.value, ast.Name)
        and keyword.arg == keyword.value.id
    )


def _is_diagnostic_name(name: str) -> bool:
    return name.upper().endswith(("_MESSAGE", "_TEMPLATE"))


def _blocked_import_script(modules: tuple[str, ...]) -> str:
    return f"""
import importlib
import importlib.abc
import sys

pure_modules = {modules!r}
forbidden = {tuple(sorted(FORBIDDEN_ROOTS))!r}
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
import mutmut.mutation.trampoline

class WarmBoundary(BaseModel):
    value: str

WarmBoundary(value='ready')

class Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname.split('.', 1)[0] in forbidden:
            raise RuntimeError(f'forbidden dependency: {{fullname}}')
        return None

sys.path.insert(0, sys.argv[1])
for name in tuple(sys.modules):
    if name.split('.', 1)[0] in forbidden:
        sys.modules.pop(name)
sys.meta_path.insert(0, Blocker())
for module in pure_modules:
    importlib.import_module(module)
"""


def test_should_import_every_pure_module_with_delivery_dependencies_blocked() -> None:
    # Given
    paths = _pure_paths()
    modules = tuple(_module_name(path) for path in paths)
    declared = frozenset().union(*(_imported_roots(path) for path in paths))

    # When
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", _blocked_import_script(modules), str(ROOT / "src")],
        check=False,
        capture_output=True,
        text=True,
    )

    # Then
    assert declared.isdisjoint(FORBIDDEN_ROOTS)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "source, expected",
    (
        ("import safe, dagger as delivery\n", "dagger"),
        ("def load():\n    import pathlib as paths\n", "pathlib"),
        ("from httpx import AsyncClient as Client\n", "httpx"),
    ),
)
def test_should_detect_aliased_or_nested_forbidden_import(
    tmp_path: Path, source: str, expected: str
) -> None:
    # Given
    module = tmp_path / "module.py"
    module.write_text(source, encoding="utf-8")

    # When
    imported = _imported_roots(module)

    # Then
    assert expected in imported.intersection(FORBIDDEN_ROOTS)


@pytest.mark.parametrize(
    "source, expected_line",
    (
        ("result = execute()  # pragma: no mutate\n", 1),
        ("raise RuntimeError('failure')  # pragma: no mutate\n", 1),
        ("if enabled:  # pragma: no mutate\n    execute()\n", 1),
        ("raise RuntimeError(\n    execute()  # pragma: no mutate\n)\n", 2),
        ("return_value = RuntimeError(\n    _MESSAGE  # pragma: no mutate\n)\n", 2),
        ("raise RuntimeError(\n    _MESSAGE,  # pragma: no mutate\n    code,\n)\n", 2),
        (
            "_diagnostic_message = _TEMPLATE.format(name=execute_release())  # pragma: no mutate\n",
            1,
        ),
        (
            "_diagnostic_message = _TEMPLATE.format(name=release.name)  # pragma: no mutate\n",
            1,
        ),
        ("_diagnostic_message = _TEMPLATE.format(name=other)  # pragma: no mutate\n", 1),
        ("_diagnostic_message = _TEMPLATE.format(name)  # pragma: no mutate\n", 1),
        ("_diagnostic_message = _TEMPLATE.format(*names)  # pragma: no mutate\n", 1),
        ("_diagnostic_message = _TEMPLATE.format(**values)  # pragma: no mutate\n", 1),
    ),
)
def test_should_reject_suppression_of_mutable_behavior(
    tmp_path: Path, source: str, expected_line: int
) -> None:
    # Given
    module = tmp_path / "behavior.py"
    module.write_text(source, encoding="utf-8")

    # When
    violations = _unsafe_mutation_suppressions(module)

    # Then
    assert violations == (expected_line,)


def test_should_allow_only_immutable_diagnostic_assignment_suppression(tmp_path: Path) -> None:
    # Given
    module = tmp_path / "diagnostics.py"
    module.write_text(
        '_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text\n    "text"\n)\n',
        encoding="utf-8",
    )

    # When / Then
    assert _unsafe_mutation_suppressions(module) == ()


def test_should_allow_only_standalone_template_rendering_suppression(tmp_path: Path) -> None:
    # Given
    module = tmp_path / "diagnostic_template.py"
    module.write_text(
        "_diagnostic_message = _TEMPLATE.format(name=name)  "
        "# pragma: no mutate - diagnostic rendering\n",
        encoding="utf-8",
    )

    # When / Then
    assert _unsafe_mutation_suppressions(module) == ()


def test_should_reject_duplicate_reviewed_suppression(tmp_path: Path) -> None:
    # Given
    grouped: dict[str, list[str]] = {}
    for relative, code in REVIEWED_EQUIVALENT_SUPPRESSIONS:
        grouped.setdefault(relative, []).append(code)
    duplicate = 'text = content.decode("utf-8")'
    grouped["src/portfolio_delivery/envelope/canonical.py"].append(duplicate)
    paths = tuple(tmp_path / relative for relative in sorted(grouped))
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = (
            f"{code}  {MUTATION_PRAGMA}\n" for code in grouped[str(path.relative_to(tmp_path))]
        )
        path.write_text("".join(lines), encoding="utf-8")

    # When
    exact = _has_exact_reviewed_suppressions(paths, tmp_path)

    # Then
    assert not exact


def test_should_have_only_reviewed_mutation_suppressions() -> None:
    # Given / When
    paths = tuple(sorted(SOURCE_ROOT.rglob("*.py")))
    violations = tuple(
        (path.relative_to(ROOT), line)
        for path in paths
        for line in _unsafe_mutation_suppressions(path)
    )
    exact = _has_exact_reviewed_suppressions(paths, ROOT)

    # Then
    assert violations == ()
    assert exact

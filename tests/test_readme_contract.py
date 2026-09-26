"""The README says who this is for, in plain words, and every fact it states is true."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[1]
README = ROOT / "README.md"
SECTION_ORDER = (
    "## Try it",
    "## How it works",
    "## What it does not do",
    "## Develop",
    "## More detail",
    "## License",
)
REQUIRED_DOCS = ("docs/ARCHITECTURE.md", "docs/GETTING_STARTED.md")
FUNCTIONS = ("build", "lint", "typecheck", "complexity", "unit", "publish")
BANNED = re.compile(
    r"\b(northstar|seam|lego|trust envelope|receipts?|fleet|gate|portfolio|production-ready"
    r"|robust|blazing|enterprise-grade|seamless|tl;dr|at a glance|try it in 60 seconds)\b",
    re.IGNORECASE,
)
REPO_NAME = re.compile(r"portfolio[-_ ]delivery", re.IGNORECASE)
LOCAL_LINK = re.compile(r"\]\((?!https?://|#)([^)#\s]+)")


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _first_sentence() -> str:
    lines = [line for line in _readme().splitlines() if line.strip()]
    return lines[1]


def test_should_say_who_it_is_for_when_readme_opens() -> None:
    # Given / When
    sentence = _first_sentence()

    # Then
    assert _readme().startswith("# Portfolio Delivery\n")
    assert "Harish's own repos" in sentence
    assert "Dagger" in sentence


def test_should_keep_agreed_section_order_when_headings_are_listed() -> None:
    # Given
    headings = [line for line in _readme().splitlines() if line.startswith("## ")]

    # When
    positions = [headings.index(section) for section in SECTION_ORDER]

    # Then
    assert positions == sorted(positions)


def test_should_link_existing_docs_under_intro_when_readme_is_read() -> None:
    # Given
    lines = _readme().splitlines()
    docs_line = next(line for line in lines if line.startswith("**Technical docs:**"))

    # When / Then
    assert _readme().index(docs_line) < _readme().index("## Try it")
    for path in REQUIRED_DOCS:
        assert f"]({path})" in docs_line
        assert (ROOT / path).is_file()


def test_should_resolve_every_local_link_when_readme_and_docs_are_rendered() -> None:
    # Given
    pages = (README, *(ROOT / "docs").glob("*.md"))

    # When
    missing = [
        f"{page.name}: {target}"
        for page in pages
        for target in LOCAL_LINK.findall(page.read_text(encoding="utf-8"))
        if not (page.parent / target).exists()
    ]

    # Then
    assert missing == []


def test_should_find_no_internal_jargon_when_repo_name_is_ignored() -> None:
    # Given
    text = REPO_NAME.sub("", _readme())

    # When
    found = sorted({match.lower() for match in BANNED.findall(text)})

    # Then
    assert found == []


def test_should_state_real_engine_and_functions_when_compared_to_dagger_json() -> None:
    # Given
    engine = json.loads((ROOT / "dagger.json").read_text(encoding="utf-8"))["engineVersion"]

    # When
    text = _readme()

    # Then
    assert engine.removeprefix("v") in text
    assert all(f"`{name}`" in text for name in FUNCTIONS)


def test_should_match_readme_when_package_description_is_read() -> None:
    # Given
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    # When
    description = project["description"]

    # Then
    assert "Harish's own repos" in description
    assert "Dagger" in description
    assert not BANNED.search(description)

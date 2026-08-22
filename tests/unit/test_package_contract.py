from pytest import version_tuple

from portfolio_delivery import __version__


def test_should_expose_foundation_version_when_package_imports() -> None:
    # Given / When / Then
    assert __version__ == "0.1.0"


def test_should_resolve_patched_pytest_when_security_floor_is_locked() -> None:
    # Given / When
    resolved_version = version_tuple

    # Then
    assert resolved_version >= (9, 0, 3)

from portfolio_delivery import __version__


def test_should_expose_foundation_version_when_package_imports() -> None:
    # Given / When / Then
    assert __version__ == "0.1.0"

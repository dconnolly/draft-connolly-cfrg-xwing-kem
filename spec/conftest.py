import pytest

def pytest_addoption(parser):
    parser.addoption(
        "--set-vectors",
        action="store_true",
        default=False,
        help="store test vectors instead of checking them",
    )


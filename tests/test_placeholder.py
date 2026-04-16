"""Smoke test to verify the project is importable."""


def test_import():
    import guardbench

    assert guardbench.__version__ == "0.1.0"

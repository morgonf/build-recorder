from pathlib import Path
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def tiny_out(fixtures_dir: Path) -> Path:
    return fixtures_dir / "tiny.out"


@pytest.fixture
def tiny_expected(fixtures_dir: Path) -> Path:
    return fixtures_dir / "tiny.expected.json"


@pytest.fixture
def flat_out(fixtures_dir: Path) -> Path:
    return fixtures_dir / "flat.out"


@pytest.fixture
def grouped_out(fixtures_dir: Path) -> Path:
    return fixtures_dir / "grouped.out"


@pytest.fixture
def escaped_paths_out(fixtures_dir: Path) -> Path:
    return fixtures_dir / "escaped_paths.out"


@pytest.fixture
def old_enriched_out(fixtures_dir: Path) -> Path:
    return fixtures_dir / "old_enriched.out"


@pytest.fixture
def new_enriched_out(fixtures_dir: Path) -> Path:
    return fixtures_dir / "new_enriched.out"

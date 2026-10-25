import pytest

from lineage.passport.build import build_passport
from lineage.schemas.passport import SourceRef


@pytest.fixture
def sample_passport(tiny_model):
    return build_passport(tiny_model, "model", "tiny", "1.0.0", SourceRef(hub="local"))

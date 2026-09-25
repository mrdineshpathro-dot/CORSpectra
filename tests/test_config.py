import pytest

from corspectra.config import Config


def test_config_load_and_defaults(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("timeout: 4\nthreads: 3\nverify_ssl: false\n")
    config = Config.load(path)
    assert config.timeout == 4 and config.threads == 3 and config.verify_ssl is False


def test_config_rejects_unknown_and_bounds(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("mystery: true\n")
    with pytest.raises(ValueError):
        Config.load(path)
    with pytest.raises(ValueError):
        Config(threads=0).validate()

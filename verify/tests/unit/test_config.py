"""Tests for blastcontain_verify.config."""
from __future__ import annotations


from blastcontain_verify.config import VerifyConfig, load_config


class TestLoadConfig:
    def test_defaults(self):
        cfg = load_config()
        assert cfg.environment == "staging"
        assert cfg.search_path == "."
        assert cfg.model_dir == "/models"

    def test_cli_overrides_defaults(self):
        cfg = load_config(cli_overrides={"agent_id": "my-agent", "environment": "prod"})
        assert cfg.agent_id == "my-agent"
        assert cfg.environment == "prod"

    def test_none_cli_values_not_applied(self):
        cfg = load_config(cli_overrides={"agent_id": None, "environment": "prod"})
        assert cfg.agent_id == ""  # default
        assert cfg.environment == "prod"

    def test_yaml_file_loaded(self, tmp_path):
        config_file = tmp_path / "blastcontain-verify.yaml"
        config_file.write_text(
            "agent_id: yaml-agent\nenvironment: uat\nsearch_path: ./src\n"
        )
        cfg = load_config(config_file=str(config_file))
        assert cfg.agent_id == "yaml-agent"
        assert cfg.environment == "uat"
        assert cfg.search_path == "./src"

    def test_cli_overrides_yaml(self, tmp_path):
        config_file = tmp_path / "blastcontain-verify.yaml"
        config_file.write_text("agent_id: yaml-agent\nenvironment: uat\n")
        cfg = load_config(
            config_file=str(config_file),
            cli_overrides={"environment": "prod"},
        )
        assert cfg.agent_id == "yaml-agent"
        assert cfg.environment == "prod"  # CLI wins

    def test_malformed_yaml_degrades_to_defaults(self, tmp_path, capsys):
        """A malformed config file degrades to defaults with a warning, not a crash."""
        config_file = tmp_path / "blastcontain-verify.yaml"
        config_file.write_text("agent_id: [1, 2, 3\nenvironment: : :\n")  # invalid YAML
        cfg = load_config(config_file=str(config_file))
        assert cfg.environment == "staging"  # defaults preserved, no exception
        assert cfg.agent_id == ""
        assert "could not load config file" in capsys.readouterr().err

    def test_config_path_directory_degrades_to_defaults(self, tmp_path):
        """A --config path that is actually a directory degrades, not crashes."""
        cfg = load_config(config_file=str(tmp_path))  # a directory, exists() is True
        assert cfg.environment == "staging"

    def test_effective_skills_dir_fallback(self):
        cfg = VerifyConfig(agent_id="a", environment="prod", search_path="./src")
        assert cfg.effective_skills_dir() == "./src"

    def test_effective_skills_dir_explicit(self):
        cfg = VerifyConfig(agent_id="a", environment="prod", search_path="./src", skills_dir="./skills")
        assert cfg.effective_skills_dir() == "./skills"

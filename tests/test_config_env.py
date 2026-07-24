import os
from pathlib import Path
import yaml
import pytest
from main import _resolve_env_vars, _load_config

def test_resolve_env_vars(monkeypatch):
    monkeypatch.setenv("TEST_VAR_API_KEY", "secret_key_123")
    
    cfg = {
        "subdomain": {
            "chaos_api_key": "${TEST_VAR_API_KEY}",
            "other_key": "$TEST_VAR_API_KEY",
            "default_key": "${NON_EXISTENT_VAR:-default_val}",
            "nested_list": ["$TEST_VAR_API_KEY", "${TEST_VAR_API_KEY}"]
        }
    }
    
    resolved = _resolve_env_vars(cfg)
    assert resolved["subdomain"]["chaos_api_key"] == "secret_key_123"
    assert resolved["subdomain"]["other_key"] == "secret_key_123"
    assert resolved["subdomain"]["default_key"] == "default_val"
    assert resolved["subdomain"]["nested_list"] == ["secret_key_123", "secret_key_123"]


def test_load_config_with_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CHAOS_KEY_ENV", "env_chaos_api_key")
    
    config_content = """
subdomain:
  chaos_api_key: "${CHAOS_KEY_ENV}"
  other_key: "normal_val"
"""
    cfg_file = tmp_path / "config.yml"
    cfg_file.write_text(config_content, encoding="utf-8")
    
    cfg = _load_config(cfg_file)
    assert cfg["subdomain"]["chaos_api_key"] == "env_chaos_api_key"
    assert cfg["subdomain"]["other_key"] == "normal_val"

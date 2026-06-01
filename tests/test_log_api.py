"""
Tests for the log-api request hardening (IMPROVE-security-hardening.md Finding 6):
a request-body size cap and a requirement that the logged content is a JSON object.

log_api.py builds its Flask app and a JsonLogger at import time from a config file
that only exists inside the container, so we stub the config loader and the logger
before importing it.
"""
from configparser import ConfigParser

import sofahutils
import json_logger

_cfg = ConfigParser()
_cfg.add_section("Paths"); _cfg.set("Paths", "logging_folder_path", "/tmp")
_cfg.add_section("Utils"); _cfg.set("Utils", "api_list", "[]")


class _StubLogger:
    def __init__(self, config):
        self.logged = []

    def log(self, eventid, content, ip, src_port, dst_port):
        self.logged.append(content)

    def info(self, *a, **k):
        pass

    def warn(self, *a, **k):
        pass

    def error(self, *a, **k):
        pass


sofahutils.load_config = lambda path: _cfg
json_logger.JsonLogger = _StubLogger

import log_api  # noqa: E402  (must follow the stubs above)

import pytest  # noqa: E402

BASE = {"eventid": "api.test", "ip": "1.2.3.4", "src_port": "1", "dst_port": "2"}


@pytest.fixture
def client():
    return log_api.app.test_client()


def test_max_content_length_is_capped():
    assert log_api.app.config["MAX_CONTENT_LENGTH"] == 256 * 1024


def test_valid_json_object_content_is_accepted(client):
    r = client.post("/log", data={**BASE, "content": '{"msg":"hello"}'})
    assert r.status_code == 200


@pytest.mark.parametrize("bad_content", ['[1,2,3]', '"just a string"', '42'])
def test_non_object_content_rejected(client, bad_content):
    # parses as JSON but is not an object -> 400, not a 500 reaching the logger
    r = client.post("/log", data={**BASE, "content": bad_content})
    assert r.status_code == 400


def test_oversized_body_rejected(client):
    big = '{"x":"' + ("A" * 300000) + '"}'
    r = client.post("/log", data={**BASE, "content": big})
    assert r.status_code == 413


def test_malformed_json_rejected(client):
    r = client.post("/log", data={**BASE, "content": "{not json"})
    assert r.status_code == 400


def test_health_ok(client):
    assert client.get("/health").status_code == 200

"""
Tests for the hardened JsonLogger write path (IMPROVE-logging-pipeline.md, quick-fix tier):
thread-safe session handling, atomic sessions.json replace, size-based rotation, age pruning,
legacy-format migration, and a truncation-tolerant event reader.
"""
import json
import os
import threading
import time
from configparser import ConfigParser

import pytest

import json_logger
from json_logger import JsonLogger, read_log_events


def make_logger(tmp_path):
    cfg = ConfigParser()
    cfg.add_section("Paths"); cfg.set("Paths", "logging_folder_path", str(tmp_path))
    cfg.add_section("Utils"); cfg.set("Utils", "api_list", "[]")  # get_own_ip -> 127.0.0.1, no network
    return JsonLogger(config=cfg)


def test_concurrent_events_do_not_lose_sessions(tmp_path):
    """50 sources hitting the logger at once must all be recorded (the old read-modify-write
    of sessions.json with no lock would clobber concurrent updates)."""
    logger = make_logger(tmp_path)
    n = 50

    def worker(i):
        logger.log(eventid="test.event", content={"i": i}, ip=f"10.0.0.{i}", src_port=i, dst_port=1)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # in-memory set has all 50 distinct sessions
    assert len(logger.sessions) == n
    # sessions.json on disk is valid JSON and complete (atomic writes never left it partial)
    on_disk = json.load(open(tmp_path / "sessions.json"))
    assert len(on_disk) == n
    # every event landed in the log
    events = read_log_events(str(tmp_path / "sofah_log.json"))
    assert len(events) == n
    assert {e["session"] for e in events} == set(on_disk.keys())


def test_sessions_written_atomically_as_valid_json(tmp_path):
    logger = make_logger(tmp_path)
    logger.log("test.event", {}, ip="1.2.3.4", src_port=1, dst_port=2)
    # no leftover temp files, and the target parses
    assert not any(name.startswith("sessions.json.tmp") for name in os.listdir(tmp_path))
    assert isinstance(json.load(open(tmp_path / "sessions.json")), dict)


def test_event_log_rotates_by_size(tmp_path, monkeypatch):
    monkeypatch.setattr(json_logger, "MAX_LOG_BYTES", 200)
    logger = make_logger(tmp_path)
    for _ in range(50):
        logger.log("test.event", {"data": "x" * 50}, ip="10.0.0.1", src_port=1, dst_port=1)
    rotated = [f for f in os.listdir(tmp_path) if f.startswith("sofah_log-")]
    assert rotated, "expected at least one rotated log file"
    # rotation must not lose events: active file + rotated files together hold all 50
    total = read_log_events(str(tmp_path / "sofah_log.json"))
    for name in rotated:
        total += read_log_events(str(tmp_path / name))
    assert len(total) == 50
    # the active file stayed bounded (didn't accumulate all 50 events)
    assert os.path.getsize(tmp_path / "sofah_log.json") < 50 * 236


def test_legacy_list_sessions_are_migrated(tmp_path):
    (tmp_path / "sessions.json").write_text('["abc123", "def456"]')
    logger = make_logger(tmp_path)
    assert isinstance(logger.sessions, dict)
    assert set(logger.sessions) == {"abc123", "def456"}


def test_stale_sessions_are_pruned(tmp_path):
    logger = make_logger(tmp_path)
    logger.sessions["ancient"] = int(time.time()) - json_logger.SESSION_TTL_SECONDS - 10
    logger.log("test.event", {}, ip="10.0.0.99", src_port=1, dst_port=1)
    assert "ancient" not in logger.sessions


def test_reader_tolerates_truncated_trailing_line(tmp_path):
    f = tmp_path / "events.json"
    f.write_text('{"a": 1}\n{"b": 2}\n{"c": 3')  # process killed mid-write -> partial last line
    assert read_log_events(str(f)) == [{"a": 1}, {"b": 2}]


def test_corrupt_or_missing_sessions_file_recovers(tmp_path):
    (tmp_path / "sessions.json").write_text("{ this is not json")
    logger = make_logger(tmp_path)  # must not raise
    assert logger.sessions == {}

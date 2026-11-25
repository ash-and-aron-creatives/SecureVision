import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from backend import main, ml_inference


def test_startup_starts_warmup_in_a_daemon_thread(monkeypatch):
    observed = {}

    class DeferredThread:
        def __init__(self, *, target, name, daemon):
            observed.update(target=target, name=name, daemon=daemon)

        def start(self):
            observed["started"] = True

    monkeypatch.setattr(main.threading, "Thread", DeferredThread)
    monkeypatch.setattr(main, "warm_up_model", lambda: None)

    main.start_ml_warmup()

    assert observed == {
        "target": main.warm_up_model,
        "name": "ml-model-warmup",
        "daemon": True,
        "started": True,
    }


def test_warmup_runs_one_prediction_and_logs_success(monkeypatch, caplog):
    calls = []
    monkeypatch.setattr(
        ml_inference,
        "predict_exploit_likelihood",
        lambda *args: calls.append(args) or {"unavailable_reason": None},
    )

    with caplog.at_level(logging.INFO, logger="backend.ml_inference"):
        ml_inference.warm_up_model()

    assert len(calls) == 1
    assert "startup warm-up completed" in caplog.text
    assert ml_inference.get_warmup_state() == "ready"


def test_warmup_failure_is_visible_and_nonfatal(monkeypatch, caplog):
    def fail_prediction(*args):
        raise RuntimeError(f"warm-up test failure ({len(args)} arguments)")

    monkeypatch.setattr(ml_inference, "predict_exploit_likelihood", fail_prediction)

    with caplog.at_level(logging.ERROR, logger="backend.ml_inference"):
        ml_inference.warm_up_model()

    assert "ML startup warm-up failed" in caplog.text
    assert "warm-up test failure" in caplog.text
    assert ml_inference.get_warmup_state() == "failed"


def test_concurrent_bundle_requests_wait_for_one_artifact_load(monkeypatch):
    load_started = threading.Event()
    release_load = threading.Event()
    calls = []

    def load_bundle():
        calls.append(True)
        load_started.set()
        assert release_load.wait(timeout=2)
        return ("model", "transformer", [], "version", {})

    monkeypatch.setattr(ml_inference, "_load_bundle_uncached", load_bundle)
    ml_inference._load_bundle.cache_clear()
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(ml_inference._load_bundle)
            assert load_started.wait(timeout=1)
            second = executor.submit(ml_inference._load_bundle)
            time.sleep(0.02)
            assert not second.done()
            release_load.set()
            assert first.result(timeout=1) == second.result(timeout=1)
        assert calls == [True]
    finally:
        release_load.set()
        ml_inference._load_bundle.cache_clear()


def test_me_exposes_read_only_warmup_state(monkeypatch):
    monkeypatch.setattr(main, "get_warmup_state", lambda: "starting")

    response = main.get_me(
        SimpleNamespace(id=1, username="admin", role="admin", is_active=True)
    )

    assert response["ml_warmup_state"] == "starting"

import logging

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


def test_warmup_failure_is_visible_and_nonfatal(monkeypatch, caplog):
    def fail_prediction(*args):
        raise RuntimeError(f"warm-up test failure ({len(args)} arguments)")

    monkeypatch.setattr(ml_inference, "predict_exploit_likelihood", fail_prediction)

    with caplog.at_level(logging.ERROR, logger="backend.ml_inference"):
        ml_inference.warm_up_model()

    assert "ML startup warm-up failed" in caplog.text
    assert "warm-up test failure" in caplog.text

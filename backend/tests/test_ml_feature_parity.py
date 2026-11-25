import json
from pathlib import Path

import numpy as np
import pytest
import scipy.sparse as sp
from xgboost import XGBClassifier

from backend.ml_inference import _feature_row, _load_bundle


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "val2025_parity_rows.json"


class SparseTextTransformer:
    def transform(self, _descriptions):
        return sp.csr_matrix([[0.0, 0.5]], dtype=np.float32)


def test_feature_row_returns_csr_with_unstored_zeros():
    features = [
        "cvss_score",
        "cvss_missing",
        "AV_N",
        "AC_L",
        "PR_N",
        "UI_N",
        "S_U",
        "C_H",
        "I_H",
        "A_H",
        "cwe_OTHER",
        "term_a",
        "term_b",
    ]

    row = _feature_row(
        features,
        SparseTextTransformer(),
        {"features": features},
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        None,
        "fixture description",
    )

    assert sp.isspmatrix_csr(row)
    assert row.nnz == np.count_nonzero(row.toarray())


def test_sparse_xgboost_training_distinguishes_dense_zero_from_missing():
    training = sp.vstack(
        [
            sp.csr_matrix(np.ones((4, 1), dtype=np.float32)),
            sp.csr_matrix(np.full((4, 1), 5.0, dtype=np.float32)),
            sp.csr_matrix((8, 1), dtype=np.float32),
        ],
        format="csr",
    )
    labels = np.asarray([1] * 4 + [0] * 12)
    model = XGBClassifier(
        n_estimators=1,
        max_depth=1,
        learning_rate=1.0,
        min_child_weight=0,
        reg_lambda=0,
        tree_method="hist",
        eval_metric="logloss",
        n_jobs=1,
        random_state=0,
    )
    model.fit(training, labels)

    sparse_zero = sp.csr_matrix([[0.0]], dtype=np.float32)
    dense_zero = sparse_zero.toarray()

    assert not np.allclose(
        model.predict_proba(sparse_zero),
        model.predict_proba(dense_zero),
        rtol=0,
        atol=1e-6,
    )


def test_frozen_model_reproduces_saved_validation_likelihoods():
    rows = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    model, transformer, features, _, config = _load_bundle()

    for row in rows:
        matrix = _feature_row(
            features,
            transformer,
            config,
            row["cvss_score"],
            row["cvss_vector"],
            row["cwe"],
            row["description"],
        )
        actual = float(model.predict_proba(matrix)[0, 1])
        assert actual == pytest.approx(row["expected_likelihood"], abs=1e-6)

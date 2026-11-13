# Priority UI manual check

Status: **UNVERIFIED** — perform manually in the browser.

## Finding drawer

- [ ] Rule-matrix tier is visible as a cross-check.
- [ ] ML priority is visible, including an explicit unavailable state.
- [ ] The known-exploited floor note appears only when it raised the ML tier.
- [ ] Active priority mode label matches the API `/me` value.
- [ ] Negative test PR-AUC note remains visible (0.0114 vs CVSS 0.0117).

## Model Results

- [ ] Active priority mode label is visible.
- [ ] Recorded test/validation split labels and the negative PR-AUC result remain visible.
- [ ] Missing metrics remain labeled unavailable rather than inferred.

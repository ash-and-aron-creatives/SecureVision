# Schema Diff Against SDS

**Additions:**
* **Table epss_scores**: cve_id (String, PK, FK), score_date (Date, PK), epss (Float), percentile (Float), model_version (String).
* **Table likelihood_providers**: id (Integer, PK), 
ame (String), ersion (String), is_default (Boolean).

**Modifications:**
* **Table inding_scores**:
  * *Add:* provider_id (Integer, FK), likelihood (Float), provenance (JSON).
  * *Remove:* prediction_id.
* **Table cve_predictions & ml_models**: Retained exclusively for the experimental NLP provider.

**Retentions:**
* **Table scoring_configs**: Tracks versioned rules matrix.
* **Table priority_levels**: Tracks priority names and SLA actions.

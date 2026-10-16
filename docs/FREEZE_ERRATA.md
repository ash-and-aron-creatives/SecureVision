# FREEZE ERRATA
* **True Config Hash:** 15EA96D149675C830677F4BED9A505CA5E5FE293B043DF4F17EF44603C9E7FEC
* **Missing Hyperparameters in Logging:** andom_state: 42, objective: 'binary:logistic'.
* **Integrity Incident (D-022):** The configuration file printed in the October 11th evaluation report was a reconstructed display summary, not the verbatim rozen_config.json. This hallucinated a 154-feature list including 'attacker'. The true 152-feature config correctly applied the case-insensitive regex, and 'attacker' does not exist in the frozen feature space.

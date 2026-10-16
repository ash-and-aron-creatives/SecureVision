from backend.scoring_engine import calculate_priority

def test_scoring_monotonicity_and_exhaustiveness():
    # Priority rank mapping for monotonicity verification
    rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    # 1. Critical condition: In KEV, Internet-facing, Criticality 5
    tier_crit, exp_crit = calculate_priority(True, True, 5, 0.95, 9.8)
    assert tier_crit == 'Critical'
    assert isinstance(exp_crit, str) and len(exp_crit) > 0

    # 2. Low condition: Not in KEV, Internal, Low Criticality, Low EPSS, Low CVSS
    tier_low, exp_low = calculate_priority(False, False, 1, 0.01, 2.0)
    assert tier_low == 'Low'

    # 3. Monotonicity check: Increasing exposure cannot lower risk tier
    tier_internal, _ = calculate_priority(False, False, 3, 0.40, 6.5)
    tier_internet, _ = calculate_priority(False, True, 3, 0.40, 6.5)
    assert rank[tier_internet] >= rank[tier_internal]

    # 4. Monotonicity check: Increasing asset criticality cannot lower risk tier
    tier_crit_low, _ = calculate_priority(False, True, 2, 0.50, 7.0)
    tier_crit_high, _ = calculate_priority(False, True, 5, 0.50, 7.0)
    assert rank[tier_crit_high] >= rank[tier_crit_low]

    # 5. KEV presence always mandates elevated priority on critical business assets
    tier_kev, _ = calculate_priority(True, False, 4, 0.50, 7.5)
    assert tier_kev in ['High', 'Critical']

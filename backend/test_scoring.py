from backend.scoring_engine import calculate_priority

test_cases = [
    {"name": "Log4Shell on Public Web Server", "kev": True, "internet": True, "crit": 4, "epss": 0.98, "cvss": 10.0},
    {"name": "Old bug on Internal Server", "kev": False, "internet": False, "crit": 2, "epss": 0.05, "cvss": 5.5},
    {"name": "High EPSS, High Crit Database", "kev": False, "internet": False, "crit": 5, "epss": 0.96, "cvss": 8.1}
]

print('--- SCORING ENGINE TEST ---')
for tc in test_cases:
    result = calculate_priority(tc['kev'], tc['internet'], tc['crit'], tc['epss'], tc['cvss'])
    print(f"\nScenario: {tc['name']}")
    print(f"Tier:     {result['tier']}")
    print(f"Score:    {result['score']}")
    print(f"Reason:   {result['explanation']['summary']}")

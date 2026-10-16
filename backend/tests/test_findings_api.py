from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def get_auth_headers():
    res = client.post("/token", data={"username": "admin", "password": "password123"})
    assert res.status_code == 200
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_findings_list_and_counts():
    headers = get_auth_headers()
    res = client.get("/findings?page=1&page_size=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data and "total" in data and "counts" in data
    assert len(data["items"]) <= 10
    assert set(data["counts"].keys()) == {"Critical", "High", "Medium", "Low"}

def test_findings_filters_and_search():
    headers = get_auth_headers()
    res = client.get("/findings?priority=Critical", headers=headers)
    assert res.status_code == 200
    for item in res.json()["items"]:
        assert item["priority_tier"] == "Critical"

    res_q = client.get("/findings?q=CVE-2021-44228", headers=headers)
    assert res_q.status_code == 200
    for item in res_q.json()["items"]:
        assert "CVE-2021-44228" in item["cve_id"]

def test_finding_detail_and_404():
    headers = get_auth_headers()
    list_res = client.get("/findings?page=1&page_size=1", headers=headers)
    first_id = list_res.json()["items"][0]["id"]

    detail_res = client.get(f"/findings/{first_id}", headers=headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == first_id
    assert "asset" in detail and "explanation" in detail and "score_history" in detail

    missing_res = client.get("/findings/999999", headers=headers)
    assert missing_res.status_code == 404

def test_status_update_records_audit():
    headers = get_auth_headers()
    list_res = client.get("/findings?page=1&page_size=1", headers=headers)
    finding = list_res.json()["items"][0]

    upd = client.put(f"/findings/{finding['id']}/status", json={"status": "In Progress"}, headers=headers)
    assert upd.status_code == 200
    assert upd.json()["status"] == "In Progress"

    # Restore back to Open
    client.put(f"/findings/{finding['id']}/status", json={"status": "Open"}, headers=headers)

def test_assets_pagination(completed_scan, client):
    page1 = client.get(
        f"/api/v1/scans/{completed_scan}/assets", params={"page": 1, "page_size": 25}
    ).json()
    assert len(page1["data"]) == 25
    assert page1["pagination"]["total_items"] == 130
    assert page1["pagination"]["total_pages"] == 6

    page2 = client.get(
        f"/api/v1/scans/{completed_scan}/assets", params={"page": 2, "page_size": 25}
    ).json()
    assert {a["asset_id"] for a in page1["data"]}.isdisjoint(
        {a["asset_id"] for a in page2["data"]}
    )


def test_assets_default_sort_is_risk_score_desc(completed_scan, client):
    body = client.get(
        f"/api/v1/scans/{completed_scan}/assets", params={"page_size": 200}
    ).json()
    scores = [a["risk_score"] for a in body["data"]]
    assert scores == sorted(scores, reverse=True)


def test_assets_filter_by_severity(completed_scan, client):
    body = client.get(
        f"/api/v1/scans/{completed_scan}/assets",
        params={"severity": "CRITICAL", "page_size": 200},
    ).json()
    assert body["pagination"]["total_items"] == 42
    assert all(a["risk_severity"] == "CRITICAL" for a in body["data"])


def test_assets_search_by_algorithm(completed_scan, client):
    body = client.get(
        f"/api/v1/scans/{completed_scan}/assets", params={"q": "rsa"}
    ).json()
    assert body["pagination"]["total_items"] > 0
    assert all("rsa" in a["algorithm"].lower() for a in body["data"])


def test_findings_filter_by_method(completed_scan, client):
    body = client.get(
        f"/api/v1/scans/{completed_scan}/findings",
        params={"method": "AST", "page_size": 200},
    ).json()
    assert body["pagination"]["total_items"] == 27
    assert all(f["discovery_method"] == "AST" for f in body["data"])


def test_finding_detail_round_trips(completed_scan, client):
    listing = client.get(
        f"/api/v1/scans/{completed_scan}/findings", params={"page_size": 1}
    ).json()
    finding_id = listing["data"][0]["finding_id"]
    detail = client.get(
        f"/api/v1/scans/{completed_scan}/findings/{finding_id}"
    ).json()
    assert detail["finding_id"] == finding_id


def test_asset_detail_includes_supporting_findings(completed_scan, client):
    listing = client.get(
        f"/api/v1/scans/{completed_scan}/assets", params={"page_size": 1}
    ).json()
    asset_id = listing["data"][0]["asset_id"]
    detail = client.get(f"/api/v1/scans/{completed_scan}/assets/{asset_id}").json()
    assert detail["asset_id"] == asset_id
    assert isinstance(detail["supporting_findings"], list)
    assert len(detail["supporting_findings"]) == len(detail["supporting_finding_ids"])

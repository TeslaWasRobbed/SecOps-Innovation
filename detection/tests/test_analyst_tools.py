from detection.analyst_tools import build_investigation_summary, build_siem_query, extract_indicators


def test_extract_indicators_detects_common_artifacts() -> None:
    text = "Suspicious traffic from 8.8.4.4 to evil.example.com and hash 9e107d9d372bb6826bd81d3542a419d6"
    indicators = extract_indicators(text)

    assert any(item["type"] == "ip" and item["value"] == "8.8.4.4" for item in indicators)
    assert any(item["type"] == "domain" and item["value"] == "evil.example.com" for item in indicators)
    assert any(item["type"] == "hash" and item["value"] == "9e107d9d372bb6826bd81d3542a419d6" for item in indicators)


def test_build_siem_query_returns_templates_for_indicators() -> None:
    indicators = [
        {"type": "domain", "value": "evil.example.com"},
        {"type": "ip", "value": "8.8.4.4"},
    ]

    query = build_siem_query(indicators)

    assert "evil.example.com" in query["splunk"]
    assert "8.8.4.4" in query["sentinel"]
    assert "dns.question.name" in query["elastic"]


def test_extract_indicators_detects_email_addresses() -> None:
    indicators = extract_indicators("Contact analyst@company.com about the suspicious login from 8.8.4.4")

    assert any(item["type"] == "email" and item["value"] == "analyst@company.com" for item in indicators)


def test_build_investigation_summary_returns_actionable_recommendations() -> None:
    indicators = [
        {"type": "domain", "value": "evil.example.com"},
        {"type": "ip", "value": "8.8.4.4"},
        {"type": "hash", "value": "9e107d9d372bb6826bd81d3542a419d6"},
    ]

    summary = build_investigation_summary(indicators)

    assert summary["total_indicators"] == 3
    assert summary["by_type"]["domain"] == 1
    assert any("domain" in action for action in summary["recommended_actions"])

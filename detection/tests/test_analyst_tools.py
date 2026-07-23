from detection.analyst_tools import build_siem_query, extract_indicators


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

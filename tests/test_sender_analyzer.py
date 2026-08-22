from src.tools.sender_analyzer import analyze_sender


def test_legitimate_sender():
    result = analyze_sender(
        "accounts@acme-example.com"
    )

    assert result["risk_score"] == 0
    assert result["lookalike_brand"] is False
    assert result["findings"] == []


def test_suspicious_lookalike_sender():
    result = analyze_sender(
        "security-update@micr0soft-support.com"
    )

    assert result["risk_score"] > 0
    assert result["lookalike_brand"] is True
    assert len(result["findings"]) > 0
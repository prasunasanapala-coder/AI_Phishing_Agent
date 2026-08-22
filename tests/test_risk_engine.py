from src.scoring.risk_engine import calculate_risk


def test_low_risk_email():
    sender = {"risk_score": 0}
    urls = []
    content = {"risk_score": 0}
    attachments = {"risk_score": 0}

    result = calculate_risk(
        sender,
        urls,
        content,
        attachments,
    )

    assert result["total_score"] == 0
    assert result["risk_level"] == "🟢 Low"


def test_phishing_email_score():
    sender = {"risk_score": 40}

    urls = [
        {"risk_score": 10}
    ]

    content = {
        "risk_score": 125
    }

    attachments = {
        "risk_score": 0
    }

    result = calculate_risk(
        sender,
        urls,
        content,
        attachments,
    )

    assert result["total_score"] == 70
    assert result["risk_level"] == "🟠 High"


def test_normal_attachment():
    sender = {"risk_score": 0}
    urls = []
    content = {"risk_score": 10}
    attachments = {"risk_score": 0}

    result = calculate_risk(
        sender,
        urls,
        content,
        attachments,
    )

    assert result["total_score"] == 10
    assert result["risk_level"] == "🟢 Low"


def test_executable_attachment():
    sender = {"risk_score": 0}
    urls = []
    content = {"risk_score": 10}
    attachments = {"risk_score": 50}

    result = calculate_risk(
        sender,
        urls,
        content,
        attachments,
    )

    assert result["total_score"] == 25
    assert result["risk_level"] == "🟢 Low"
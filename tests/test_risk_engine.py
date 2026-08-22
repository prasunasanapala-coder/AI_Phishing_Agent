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

def test_risk_score_never_exceeds_100():
    result = calculate_risk(
        {"risk_score": 999},
        [{"risk_score": 999}],
        {"risk_score": 999},
        {"risk_score": 999},
    )

    assert result["total_score"] == 100


def test_risk_contributions_respect_limits():
    result = calculate_risk(
        {"risk_score": 40},
        [{"risk_score": 50}],
        {"risk_score": 100},
        {"risk_score": 50},
    )

    assert result["contributions"] == {
        "sender": 25,
        "url": 25,
        "content": 35,
        "attachment": 15,
    }

    assert result["total_score"] == 100
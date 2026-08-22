from src.tools.content_analyzer import analyze_content


def test_empty_email_body():
    result = analyze_content("")

    assert result["risk_score"] == 0
    assert "Email body is empty." in result["findings"]


def test_normal_email_content():
    result = analyze_content(
        "Hello, this is a normal business message."
    )

    assert result["risk_score"] == 0
    assert result["findings"] == []


def test_suspicious_keywords():
    result = analyze_content(
        "Please verify your account and reset your password."
    )

    # verify = 10
    # account = 10
    # password = 15
    # reset = 15
    #"verify your account" = 25
    # Total = 75
    assert result["risk_score"] == 75

    assert "Contains suspicious keyword: 'verify'" in result["findings"]
    assert "Contains suspicious keyword: 'account'" in result["findings"]
    assert "Contains suspicious keyword: 'password'" in result["findings"]
    assert "Contains suspicious keyword: 'reset'" in result["findings"]


def test_click_link():
    result = analyze_content(
        "Please click the link to continue."
    )

    # click = 10
    # "click the link" = 20
    assert result["risk_score"] == 30

    assert "Contains suspicious keyword: 'click'" in result["findings"]
    assert "Encourages the recipient to click a link." in result["findings"]


def test_account_verification():
    result = analyze_content(
        "Please verify your account immediately."
    )

    # verify = 10
    # account = 10
    # immediately = 15
    # "verify your account" = 25
    assert result["risk_score"] == 60

    assert "Requests account verification." in result["findings"]


def test_unusual_activity():
    result = analyze_content(
        "We detected unusual activity on your account."
    )

    # unusual activity = 20
    # account = 10
    assert result["risk_score"] == 30

    assert "Claims unusual account activity." in result["findings"]
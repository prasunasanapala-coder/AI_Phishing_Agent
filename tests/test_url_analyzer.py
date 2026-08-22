from src.tools.url_analyzer import analyze_url


def test_https_normal_url():
    result = analyze_url("https://example.com")

    assert result["domain"] == "example.com"
    assert result["risk_score"] == 0
    assert result["findings"] == []


def test_http_url():
    result = analyze_url("http://example.com")

    assert result["risk_score"] == 20
    assert "Uses HTTP instead of HTTPS." in result["findings"]


def test_ip_address_url():
    result = analyze_url("https://192.168.1.10/login")

    assert result["risk_score"] == 50
    assert "URL uses an IP address." in result["findings"]
    assert "Contains keyword 'login'." in result["findings"]


def test_url_shortener():
    result = analyze_url("https://bit.ly/example")

    assert result["risk_score"] == 30
    assert "Uses a URL shortening service." in result["findings"]


def test_suspicious_keywords():
    result = analyze_url(
        "https://example.com/login/verify/account"
    )

    assert result["risk_score"] == 30

    assert "Contains keyword 'login'." in result["findings"]
    assert "Contains keyword 'verify'." in result["findings"]
    assert "Contains keyword 'account'." in result["findings"]
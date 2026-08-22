from src.tools.attachment_analyzer import analyze_attachments


def test_no_attachments():
    result = analyze_attachments([])

    assert result["risk_score"] == 0
    assert "No attachments found." in result["findings"]


def test_high_risk_attachment():
    result = analyze_attachments(
        ["invoice.exe"]
    )

    assert result["risk_score"] == 50
    assert "High-risk attachment: invoice.exe" in result["findings"]


def test_medium_risk_attachment():
    result = analyze_attachments(
        ["invoice.zip"]
    )

    assert result["risk_score"] == 25
    assert "Potentially risky attachment: invoice.zip" in result["findings"]


def test_double_extension():
    result = analyze_attachments(
        ["invoice.pdf.exe"]
    )

    # Double extension = 20
    # .exe = 50
    # Total = 70
    assert result["risk_score"] == 70

    assert "Double extension detected: invoice.pdf.exe" in result["findings"]
    assert "High-risk attachment: invoice.pdf.exe" in result["findings"]


def test_multiple_attachments():
    result = analyze_attachments(
        [
            "invoice.exe",
            "documents.zip",
        ]
    )

    # .exe = 50
    # .zip = 25
    # Total = 75
    assert result["risk_score"] == 75

    assert "High-risk attachment: invoice.exe" in result["findings"]
    assert "Potentially risky attachment: documents.zip" in result["findings"]


def test_normal_multiple_dot_filename():
    result = analyze_attachments(
        ["report.final.pdf"]
    )

    assert result["risk_score"] == 0
    assert result["findings"] == []
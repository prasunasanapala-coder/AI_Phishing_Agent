def calculate_risk(
    sender_result,
    url_results,
    content_result,
    attachment_result
):
    """
    Calculate the overall phishing risk score.

    Each analysis contributes a capped amount to the final 100-point score.
    The raw analyzer score is preserved for reporting/debugging.
    """

    # -----------------------------
    # Sender Risk
    # Maximum contribution: 25
    # -----------------------------

    sender_raw = sender_result["risk_score"]
    sender_contribution = min(sender_raw, 25)

    # -----------------------------
    # URL Risk
    # Maximum contribution: 25
    # -----------------------------

    url_raw = sum(
        url["risk_score"]
        for url in url_results
    )

    url_contribution = min(url_raw, 25)

    # -----------------------------
    # Content Risk
    # Maximum contribution: 35
    # -----------------------------

    content_raw = content_result["risk_score"]
    content_contribution = min(content_raw, 35)

    # -----------------------------
    # Attachment Risk
    # Maximum contribution: 15
    # -----------------------------

    attachment_raw = attachment_result["risk_score"]
    attachment_contribution = min(
        attachment_raw,
        15
    )

    # -----------------------------
    # Overall Risk
    # -----------------------------

    total = (
        sender_contribution
        + url_contribution
        + content_contribution
        + attachment_contribution
    )

    # -----------------------------
    # Risk Level
    # -----------------------------

    if total >= 80:
        level = "🔴 Critical"

    elif total >= 60:
        level = "🟠 High"

    elif total >= 30:
        level = "🟡 Medium"

    else:
        level = "🟢 Low"

    return {
        "total_score": total,
        "risk_level": level,

        # Raw analyzer scores
        "raw_scores": {
            "sender": sender_raw,
            "url": url_raw,
            "content": content_raw,
            "attachment": attachment_raw,
        },

        # Actual contributions to the 100-point score
        "contributions": {
            "sender": sender_contribution,
            "url": url_contribution,
            "content": content_contribution,
            "attachment": attachment_contribution,
        },

        # Maximum possible contribution
        "maximums": {
            "sender": 25,
            "url": 25,
            "content": 35,
            "attachment": 15,
        }
    }
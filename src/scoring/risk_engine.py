def calculate_risk(
    sender_result,
    url_results,
    content_result,
    attachment_result,
    header_result,
):
    sender_score = min(sender_result["risk_score"], 25)

    url_score = min(
        sum(url["risk_score"] for url in url_results),
        25
    )

    content_score = min(content_result["risk_score"], 35)

    attachment_score = min(
        attachment_result["risk_score"],
        15
    )

    total = (
        sender_score +
        url_score +
        content_score +
        attachment_score
    )

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
        "risk_level": level
    }
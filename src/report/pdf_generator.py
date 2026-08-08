from reportlab.lib import styles
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
)
from reportlab.lib.units import inch

def generate_pdf(
    filename,
    email,
    sender_result,
    header_result,
    url_results,
    content_result,
    attachment_result,
    iocs,
    risk,
    ai_report,
):
    """
    Generate a phishing investigation PDF report.
    """

    styles = getSampleStyleSheet()

    doc = SimpleDocTemplate(filename)

    story = []

    # ----------------------------------------------------
    # Title
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>AI Phishing Investigation Report</b>",
            styles["Title"],
        )
    )

    story.append(Spacer(1, 0.3 * inch))

    # ----------------------------------------------------
    # Executive Summary
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>Executive Summary</b>",
            styles["Heading1"],
        )
    )

    story.append(
        Paragraph(
            f"""
            Overall Risk Score:
            <b>{risk['total_score']}/100</b><br/>

            Risk Level:
            <b>{risk['risk_level']}</b>
            """,
            styles["BodyText"],
        )
    )

    story.append(Spacer(1, 0.2 * inch))

    # ----------------------------------------------------
    # Email Details
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>Email Details</b>",
            styles["Heading1"],
        )
    )

    story.append(
        Paragraph(
            f"""
            Sender: {email['sender']}<br/>
            Recipient: {email['recipient']}<br/>
            Subject: {email['subject']}<br/>
            Date: {email['date']}
            """,
            styles["BodyText"],
        )
    )

    story.append(Spacer(1, 0.2 * inch))

    # ----------------------------------------------------
    # Header Analysis
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>Header Analysis</b>",
            styles["Heading1"],
        )
    )

    story.append(
        Paragraph(
            f"<b>SPF:</b> {header_result['spf']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            f"<b>DKIM:</b> {header_result['dkim']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            f"<b>DMARC:</b> {header_result['dmarc']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Reply-To:</b> {header_result['reply_to']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Return-Path:</b> {header_result['return_path']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Received Headers:</b> {header_result['received_count']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Score:</b> {header_result['risk_score']}",
            styles["BodyText"],
            )
    )

    story.append(
        Paragraph(
            "<b>Findings</b>",
            styles["Heading2"],
        )
    )

    if header_result["findings"]:

        for finding in header_result["findings"]:

            story.append(
                Paragraph(
                    f"• {finding}",
                    styles["BodyText"],
                )
            )

    else:

        story.append(
            Paragraph(
                "No suspicious header findings detected.",
                styles["BodyText"],
            )
        )

    story.append(Spacer(1, 0.2 * inch))

    # ----------------------------------------------------
    # Sender Analysis
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>Sender Analysis</b>",
            styles["Heading1"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Sender Email:</b> {sender_result['email']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Domain:</b> {sender_result['domain']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Score:</b> {sender_result['risk_score']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Lookalike Domain:</b> {'Yes' if sender_result['lookalike_brand'] else 'No'}",
            styles["BodyText"],
        )
    )
    

    story.append(
        Paragraph(
            "<b>Findings</b>",
            styles["Heading2"],
        )
    )

    if sender_result["findings"]:

        for finding in sender_result["findings"]:

            story.append(
                Paragraph(
                    f"• {finding}",
                    styles["BodyText"],
                )
            )

    else:

        story.append(
            Paragraph(
                "No suspicious sender indicators found.",
                styles["BodyText"],
            )
        )

    story.append(Spacer(1, 0.2 * inch))

    # ----------------------------------------------------
    # URL Analysis
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>URL Analysis</b>",
            styles["Heading1"],
        )
    )

    if url_results:

        for result in url_results:

            story.append(
                Paragraph(
                    f"<b>URL:</b> {result['url']}",
                    styles["BodyText"],
                )
            )

            story.append(
                Paragraph(
                    f"<b>Domain:</b> {result['domain']}",
                    styles["BodyText"],
                )
            )

            story.append(
                Paragraph(
                    f"<b>Risk Score:</b> {result['risk_score']}",
                    styles["BodyText"],
                )
            )

            story.append(
                Paragraph(
                    "<b>Findings</b>",
                    styles["Heading2"],
                )
            )

            if result["findings"]:

                for finding in result["findings"]:

                    story.append(
                        Paragraph(
                            f"• {finding}",
                            styles["BodyText"],
                        )
                    )

            else:

                story.append(
                    Paragraph(
                        "No suspicious URL indicators found.",
                        styles["BodyText"],
                    )
                )

            story.append(Spacer(1, 0.15 * inch))

    else:

        story.append(
            Paragraph(
                "No URLs detected in the email.",
                styles["BodyText"],
            )
        )

    story.append(Spacer(1, 0.2 * inch))

    # ----------------------------------------------------
    # Content Analysis
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>Content Analysis</b>",
            styles["Heading1"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Score:</b> {content_result['risk_score']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            "<b>Findings</b>",
            styles["Heading2"],
        )
    )

    if content_result["findings"]:

        for finding in content_result["findings"]:

            story.append(
                Paragraph(
                    f"• {finding}",
                    styles["BodyText"],
                )
            )

    else:

        story.append(
            Paragraph(
                "No suspicious content indicators detected.",
                styles["BodyText"],
            )
        )

    story.append(Spacer(1, 0.2 * inch))

    # ----------------------------------------------------
    # Attachment Analysis
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>Attachment Analysis</b>",
            styles["Heading1"],
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Score:</b> {attachment_result['risk_score']}",
            styles["BodyText"],
        )
    )

    story.append(
        Paragraph(
            "<b>Findings</b>",
            styles["Heading2"],
        )
    )

    if attachment_result["findings"]:

        for finding in attachment_result["findings"]:

            story.append(
                Paragraph(
                    f"• {finding}",
                    styles["BodyText"],
                )
            )

    else:

        story.append(
            Paragraph(
                "No suspicious attachments detected.",
                styles["BodyText"],
            )
        )

    story.append(
        Paragraph(
            "<b>Attachments</b>",
            styles["Heading2"],
        )
    )

    if iocs["attachments"]:

        for attachment in iocs["attachments"]:

            story.append(
                Paragraph(
                    f"• {attachment}",
                    styles["BodyText"],
                )
            )

    else:

        story.append(
            Paragraph(
                "No attachments present.",
                styles["BodyText"],
            )
        )

    story.append(Spacer(1, 0.2 * inch))

    # ----------------------------------------------------
    # Indicators of Compromise
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>Indicators of Compromise</b>",
            styles["Heading1"],
        )
    )

    story.append(
        Paragraph(
            str(iocs),
            styles["BodyText"],
        )
    )

    story.append(Spacer(1, 0.2 * inch))

    # ----------------------------------------------------
    # AI Investigation
    # ----------------------------------------------------

    story.append(
        Paragraph(
            "<b>AI Investigation Report</b>",
            styles["Heading1"],
        )
    )

    story.append(
        Paragraph(
            ai_report.replace("\n", "<br/>"),
            styles["BodyText"],
        )
    )

    doc.build(story)
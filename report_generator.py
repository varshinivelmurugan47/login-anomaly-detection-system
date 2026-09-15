import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def _get_value(event, *field_names, default=""):
    """
    Read a value from either:
    - a SQLAlchemy model object
    - a dictionary
    """

    for field_name in field_names:
        if isinstance(event, dict):
            value = event.get(field_name)
        else:
            value = getattr(event, field_name, None)

        if value is not None:
            return value

    return default


def _format_value(value):
    """
    Convert values such as datetime objects into readable text.
    """

    if value is None:
        return ""

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")

    return str(value)


def _risk_level(event):
    """
    Read the risk level from different possible field names.
    """

    value = _get_value(
        event,
        "risk_level",
        "risk",
        "level",
        default="LOW",
    )

    return str(value).upper()


def _risk_color(risk):
    """
    Return a background color for the risk level.
    """

    risk = risk.upper()

    if risk == "CRITICAL":
        return colors.HexColor("#7f1d1d")

    if risk == "HIGH":
        return colors.HexColor("#dc2626")

    if risk == "MEDIUM":
        return colors.HexColor("#f59e0b")

    if risk == "SAFE":
        return colors.HexColor("#16a34a")

    return colors.HexColor("#22c55e")


def generate_report(
    events,
    start_date=None,
    end_date=None,
    output_path=None,
):
    """
    Generate a downloadable PDF report.

    This function supports the call used in app.py:

        generate_report(events, start_date, end_date)

    Parameters:
        events:
            A list of SQLAlchemy LoginEvent objects or dictionaries.

        start_date:
            Report start datetime. Optional.

        end_date:
            Report end datetime. Optional.

        output_path:
            Optional custom PDF path.

    Returns:
        The generated PDF file path.
    """

    # Use the reports directory inside the project by default.
    if output_path is None:
        project_directory = os.path.dirname(os.path.abspath(__file__))
        reports_directory = os.path.join(project_directory, "reports")

        os.makedirs(reports_directory, exist_ok=True)

        output_path = os.path.join(
            reports_directory,
            "siem_analysis_report.pdf",
        )
    else:
        output_directory = os.path.dirname(os.path.abspath(output_path))

        if output_directory:
            os.makedirs(output_directory, exist_ok=True)

    # Convert None into an empty list.
    if events is None:
        events = []

    # ReportLab styles.
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        leading=22,
        spaceAfter=10,
    )

    subtitle_style = ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#555555"),
        spaceAfter=15,
    )

    heading_style = ParagraphStyle(
        name="ReportHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
    )

    small_style = ParagraphStyle(
        name="ReportSmall",
        parent=styles["BodyText"],
        fontSize=7,
        leading=9,
    )

    story = []

    # ---------------------------------------------------------
    # Report title
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "SIEM Event Monitoring and Risk Analysis Report",
            title_style,
        )
    )

    generated_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story.append(
        Paragraph(
            f"Generated on: {generated_time}",
            subtitle_style,
        )
    )

    if start_date is not None:
        start_text = _format_value(start_date)
    else:
        start_text = "All available dates"

    if end_date is not None:
        end_text = _format_value(end_date)
    else:
        end_text = "Current time"

    story.append(
        Paragraph(
            f"<b>Report Period:</b> {start_text} to {end_text}",
            body_style,
        )
    )

    story.append(Spacer(1, 12))

    # ---------------------------------------------------------
    # Risk summary
    # ---------------------------------------------------------

    total_events = len(events)

    safe_count = 0
    low_count = 0
    medium_count = 0
    high_count = 0
    critical_count = 0

    for event in events:
        risk = _risk_level(event)

        if risk == "SAFE":
            safe_count += 1
        elif risk == "LOW":
            low_count += 1
        elif risk == "MEDIUM":
            medium_count += 1
        elif risk == "HIGH":
            high_count += 1
        elif risk == "CRITICAL":
            critical_count += 1

    story.append(
        Paragraph(
            "Risk Summary",
            heading_style,
        )
    )

    summary_data = [
        ["Metric", "Count"],
        ["Total Events", str(total_events)],
        ["Safe Logins", str(safe_count)],
        ["Low Risk", str(low_count)],
        ["Medium Risk", str(medium_count)],
        ["High Risk", str(high_count)],
        ["Critical Risk", str(critical_count)],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[3.2 * inch, 1.2 * inch],
        repeatRows=1,
    )

    summary_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f4e78"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (1, -1),
                    "CENTER",
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(summary_table)
    story.append(Spacer(1, 18))

    # ---------------------------------------------------------
    # Event details
    # ---------------------------------------------------------

    story.append(
        Paragraph(
            "Event Details",
            heading_style,
        )
    )

    table_data = [
        [
            Paragraph("<b>Timestamp</b>", small_style),
            Paragraph("<b>Username</b>", small_style),
            Paragraph("<b>IP Address</b>", small_style),
            Paragraph("<b>Location</b>", small_style),
            Paragraph("<b>Device</b>", small_style),
            Paragraph("<b>Risk</b>", small_style),
            Paragraph("<b>Explanation</b>", small_style),
        ]
    ]

    for event in events:
        timestamp = _get_value(
            event,
            "timestamp",
            "time",
            "created_at",
            default="",
        )

        username = _get_value(
            event,
            "username",
            "user",
            "user_name",
            default="",
        )

        ip_address = _get_value(
            event,
            "ip_address",
            "ip",
            "source_ip",
            default="",
        )

        location = _get_value(
            event,
            "location",
            "geo_location",
            default="",
        )

        device = _get_value(
            event,
            "device",
            "device_name",
            "user_agent",
            default="",
        )

        risk = _risk_level(event)

        explanation = _get_value(
            event,
            "explanation",
            "reason",
            "description",
            default="",
        )

        risk_paragraph = Paragraph(
            f'<font color="{_risk_color(risk).hexval()}">'
            f"<b>{risk}</b>"
            f"</font>",
            small_style,
        )

        table_data.append(
            [
                Paragraph(_format_value(timestamp), small_style),
                Paragraph(_format_value(username), small_style),
                Paragraph(_format_value(ip_address), small_style),
                Paragraph(_format_value(location), small_style),
                Paragraph(_format_value(device), small_style),
                risk_paragraph,
                Paragraph(_format_value(explanation), small_style),
            ]
        )

    if len(table_data) == 1:
        table_data.append(
            [
                Paragraph("No events found", small_style),
                "",
                "",
                "",
                "",
                "",
                "",
            ]
        )

    event_table = Table(
        table_data,
        repeatRows=1,
        colWidths=[
            1.05 * inch,
            0.75 * inch,
            0.90 * inch,
            0.90 * inch,
            0.85 * inch,
            0.65 * inch,
            2.20 * inch,
        ],
    )

    event_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f4e78"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    story.append(event_table)

    # ---------------------------------------------------------
    # Report footer
    # ---------------------------------------------------------

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "This report was generated by the Login Anomaly Detection "
            "and SIEM Monitoring System.",
            subtitle_style,
        )
    )

    # Build the PDF.
    document = SimpleDocTemplate(
        output_path,
        pagesize=landscape(A4),
        rightMargin=25,
        leftMargin=25,
        topMargin=25,
        bottomMargin=25,
        title="SIEM Event Monitoring Report",
        author="Login Anomaly Detection System",
    )

    document.build(story)

    return output_path

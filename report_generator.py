from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from datetime import datetime, timedelta


def generate_10_day_report(events, output_path):

    document = SimpleDocTemplate(

        output_path,

        pagesize=landscape(A4),

        rightMargin=10 * mm,

        leftMargin=10 * mm,

        topMargin=10 * mm,

        bottomMargin=10 * mm
    )

    styles = getSampleStyleSheet()

    story = []

    # ======================================================
    # TITLE
    # ======================================================

    story.append(

        Paragraph(
            "<b>LOGIN ANOMALY DETECTION SYSTEM</b>",
            styles["Title"]
        )

    )

    story.append(

        Paragraph(
            "<b>10-DAY LOGIN SECURITY REPORT</b>",
            styles["Heading2"]
        )

    )

    story.append(
        Spacer(1, 10)
    )

    # ======================================================
    # REPORT PERIOD
    # ======================================================

    end_date = datetime.utcnow()

    start_date = (

        end_date

        - timedelta(days=10)

    )

    story.append(

        Paragraph(

            f"<b>Reporting Period:</b> "
            f"{start_date.strftime('%d-%m-%Y')} "
            f"to "
            f"{end_date.strftime('%d-%m-%Y')}",

            styles["Normal"]

        )

    )

    story.append(

        Paragraph(

            f"<b>Generated On:</b> "
            f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",

            styles["Normal"]

        )

    )

    story.append(
        Spacer(1, 12)
    )

    # ======================================================
    # STATISTICS
    # ======================================================

    total = len(events)

    successful = sum(

        1

        for event in events

        if event.login_success

    )

    failed = total - successful

    safe = sum(

        1

        for event in events

        if event.risk_level == "Safe"

    )

    low = sum(

        1

        for event in events

        if event.risk_level == "Low"

    )

    medium = sum(

        1

        for event in events

        if event.risk_level == "Medium"

    )

    high = sum(

        1

        for event in events

        if event.risk_level == "High"

    )

    critical = sum(

        1

        for event in events

        if event.risk_level == "Critical"

    )

    statistics = [

        ["Metric", "Count"],

        ["Total Login Attempts", total],

        ["Successful Logins", successful],

        ["Failed Logins", failed],

        ["Safe Events", safe],

        ["Low Risk", low],

        ["Medium Risk", medium],

        ["High Risk", high],

        ["Critical Risk", critical]

    ]

    statistics_table = Table(

        statistics,

        colWidths=[
            70 * mm,
            30 * mm
        ]

    )

    statistics_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.black
            ),

            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            )

        ])

    )

    story.append(
        statistics_table
    )

    story.append(
        Spacer(1, 15)
    )

    # ======================================================
    # LOGIN EVENT DETAILS
    # ======================================================

    story.append(

        Paragraph(
            "<b>LOGIN EVENT DETAILS</b>",
            styles["Heading3"]
        )

    )

    data = [[

        "ID",
        "Username",
        "IP Address",
        "Location",
        "Device",
        "Time",
        "Status",
        "Risk",
        "Score"

    ]]

    for event in events:

        status = (

            "Success"

            if event.login_success

            else "Failed"

        )

        timestamp = (

            event.timestamp.strftime(
                "%d-%m-%Y %H:%M"
            )

        )

        data.append([

            str(event.id),

            event.username,

            event.ip_address,

            event.location,

            event.device,

            timestamp,

            status,

            event.risk_level,

            str(event.risk_score)

        ])

    table = Table(

        data,

        repeatRows=1,

        colWidths=[

            10 * mm,
            25 * mm,
            30 * mm,
            25 * mm,
            35 * mm,
            30 * mm,
            20 * mm,
            20 * mm,
            15 * mm

        ]

    )

    table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.3,
                colors.black
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            )

        ])

    )

    story.append(table)

    story.append(
        Spacer(1, 15)
    )

    # ======================================================
    # SECURITY SUMMARY
    # ======================================================

    story.append(

        Paragraph(

            "<b>Security Summary:</b> "
            "This report contains login activities "
            "recorded during the previous ten days. "
            "High and Critical risk events should be "
            "reviewed by the administrator.",

            styles["Normal"]

        )

    )

    # ======================================================
    # BUILD PDF
    # ======================================================

    document.build(story)

"""
Byzantium — One-Page Co-Founder Progress Summary
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.colors import HexColor, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import Flowable
import datetime

NAVY   = HexColor("#1B2A4A")
GOLD   = HexColor("#C4A35A")
GREEN  = HexColor("#2A6E47")
AMBER  = HexColor("#C47A2A")
RED    = HexColor("#8B2E2E")
GREY   = HexColor("#64748B")
GLITE  = HexColor("#F1F5F9")
GMID   = HexColor("#CBD5E1")
WHITE  = white
W, H   = A4


class Bar(Flowable):
    def __init__(self, pct, colour, width=5.8*cm, height=10):
        super().__init__()
        self.pct = pct; self.colour = colour
        self.bw = width; self.bh = height
        self.width = width; self.height = height

    def draw(self):
        c = self.canv
        c.setFillColor(GMID)
        c.roundRect(0, 0, self.bw, self.bh, 3, fill=1, stroke=0)
        fw = max(6, self.pct / 100 * self.bw)
        c.setFillColor(self.colour)
        c.roundRect(0, 0, fw, self.bh, 3, fill=1, stroke=0)
        c.setFont("Helvetica-Bold", 6.5)
        if self.pct > 10:
            c.setFillColor(WHITE)
            c.drawString(5, 2, f"{self.pct}%")
        else:
            c.setFillColor(GREY)
            c.drawString(fw + 3, 2, f"{self.pct}%")


def dot(colour, size=7):
    class Dot(Flowable):
        def __init__(self):
            super().__init__()
            self.width = size; self.height = size
        def draw(self):
            c = self.canv
            c.setFillColor(colour)
            c.circle(size/2, size/2, size/2, fill=1, stroke=0)
    return Dot()


def on_page(canvas, doc):
    canvas.saveState()
    # Top bar
    canvas.setFillColor(NAVY)
    canvas.rect(0, H - 15*mm, W, 15*mm, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, H - 16.5*mm, W, 1.5*mm, fill=1, stroke=0)
    # Title in bar
    canvas.setFont("Helvetica-Bold", 16)
    canvas.setFillColor(WHITE)
    canvas.drawString(1.8*cm, H - 10.5*mm, "BYZANTIUM")
    canvas.setFont("Helvetica", 10)
    canvas.setFillColor(GOLD)
    canvas.drawString(6.5*cm, H - 10.5*mm, "AI Agent Trust Infrastructure — Progress Summary")
    # Date right
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GMID)
    canvas.drawRightString(W - 1.8*cm, H - 10.5*mm,
                           datetime.date.today().strftime("%B %Y"))
    # Footer
    canvas.setFillColor(GLITE)
    canvas.rect(0, 0, W, 8*mm, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, 8*mm, W, 0.8*mm, fill=1, stroke=0)
    canvas.setFont("Helvetica-BoldOblique", 8)
    canvas.setFillColor(NAVY)
    canvas.drawCentredString(W/2, 3*mm,
        "The engine is built and proven. The next 30 days fits it into the car and drives it to customers.")
    canvas.restoreState()


def build(path):
    doc = SimpleDocTemplate(path, pagesize=A4,
        rightMargin=1.6*cm, leftMargin=1.6*cm,
        topMargin=2.2*cm, bottomMargin=1.6*cm)

    S = lambda name, **kw: ParagraphStyle(name, **kw)

    sec   = S("sec",  fontName="Helvetica-Bold", fontSize=9,  textColor=GOLD,
               leading=11, spaceBefore=10, spaceAfter=3)
    body  = S("body", fontName="Helvetica",      fontSize=8.5, textColor=HexColor("#2D3748"),
               leading=12, spaceAfter=2)
    small = S("sm",   fontName="Helvetica",      fontSize=7.5, textColor=GREY,
               leading=10, spaceAfter=1)
    bold  = S("bold", fontName="Helvetica-Bold", fontSize=8.5, textColor=NAVY, leading=12)
    big   = S("big",  fontName="Helvetica-Bold", fontSize=28,  textColor=NAVY,
               leading=30, alignment=TA_CENTER)
    bigsub= S("bigsub",fontName="Helvetica",     fontSize=8,   textColor=GREY,
               alignment=TA_CENTER, spaceAfter=4)
    wht   = S("wht",  fontName="Helvetica-Bold", fontSize=8,   textColor=WHITE, leading=11)
    week  = S("week", fontName="Helvetica-Bold", fontSize=8,   textColor=NAVY, leading=11)
    step  = S("step", fontName="Helvetica",      fontSize=8,   textColor=HexColor("#2D3748"),
               leading=11)

    story = []
    story.append(Spacer(1, 0.1*cm))

    # ── HERO STAT ──────────────────────────────────────────────────────────
    hero = Table([[
        Table([
            [Paragraph("35%", big)],
            [Paragraph("Complete", bigsub)],
        ], colWidths=[3*cm]),
        Table([
            [Paragraph("11", big)],
            [Paragraph("Components Built", bigsub)],
        ], colWidths=[3.5*cm]),
        Table([
            [Paragraph("30", big)],
            [Paragraph("Days to MVP Demo", bigsub)],
        ], colWidths=[3.5*cm]),
        Paragraph(
            "Byzantium is the trust layer for AI agents — a real-time system that "
            "answers <i>\"can this AI be trusted to do this right now?\"</i> in under "
            "200ms, and produces a signed, auditable receipt every time. "
            "The core product works today. What remains is wiring, rail integrations, "
            "and hardening.",
            S("desc", fontName="Helvetica", fontSize=8.5, textColor=HexColor("#2D3748"),
              leading=13, leftIndent=8)),
    ]], colWidths=[3*cm, 3.5*cm, 3.5*cm, 7.4*cm])
    hero.setStyle(TableStyle([
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("LINEAFTER",    (0,0), (0,0),   0.8, GMID),
        ("LINEAFTER",    (1,0), (1,0),   0.8, GMID),
        ("LINEAFTER",    (2,0), (2,0),   0.8, GMID),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("BACKGROUND",   (0,0), (-1,-1), GLITE),
        ("BOX",          (0,0), (-1,-1), 1,   GMID),
    ]))
    story.append(hero)
    story.append(Spacer(1, 0.3*cm))

    # ── TWO COLUMNS ────────────────────────────────────────────────────────
    # Left = what's built  |  Right = 30-day timeline

    # LEFT: status table
    components = [
        # (name, pct, colour, one-liner)
        ("Digital Identity (DID + PQ Crypto)",  85, GREEN, "Cryptographic agent passports. Unorgeable. Done."),
        ("Spend Mandate Engine",                 65, GREEN, "Per-agent policy enforcement in real time. Working."),
        ("Trust Check API  (<200ms)",            60, GREEN, "Core product. PASS/FLAG/BLOCK + signed token. Working."),
        ("Liability Receipt System",             75, GREEN, "Tamper-proof signed record per agent action. Working."),
        ("Merkle Audit Trail",                   75, GREEN, "Regulator-verifiable receipt batches. Working."),
        ("Behavioural Reputation Graph",         45, AMBER, "Transaction history + trust score. In progress."),
        ("Database Layer (PG / Redis / Neo4j)",  40, AMBER, "Interfaces complete; need live-DB wiring."),
        ("Privacy Proofs (ZK / SP1)",            20, AMBER, "Circuits written; need compile + hot-path wiring."),
        ("Secure Enclave (SGX / Gramine)",       15, RED,   "Manifests done; gateway not calling it yet."),
        ("Immutable Anchoring (immudb / BTC)",   10, RED,   "Stubs only. Needed for insurance use case."),
        ("Rail Integrations (x402, A2A)",         0, RED,   "Not started. Distribution layer / revenue gate."),
    ]

    left_rows = [[Paragraph("WHAT'S BUILT", sec), Paragraph("STATUS", sec)]]
    for name, pct, colour, note in components:
        name_cell = [
            Paragraph(f"<b>{name}</b>", bold),
            Paragraph(note, small),
        ]
        nc = Table([[r] for r in name_cell], colWidths=[7.8*cm])
        nc.setStyle(TableStyle([
            ("TOPPADDING",   (0,0), (-1,-1), 1),
            ("BOTTOMPADDING",(0,0), (-1,-1), 1),
            ("LEFTPADDING",  (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 0),
        ]))
        bar_cell = Table([
            [Bar(pct, colour, width=5.8*cm, height=10)],
        ], colWidths=[5.8*cm])
        bar_cell.setStyle(TableStyle([
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ("LEFTPADDING",  (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 0),
        ]))
        left_rows.append([nc, bar_cell])

    left_tbl = Table(left_rows, colWidths=[7.8*cm, 5.8*cm])
    left_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0),   NAVY),
        ("TEXTCOLOR",    (0,0), (-1,0),   WHITE),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),  [WHITE, GLITE]),
        ("TOPPADDING",   (0,0), (-1,-1),  5),
        ("BOTTOMPADDING",(0,0), (-1,-1),  5),
        ("LEFTPADDING",  (0,0), (-1,-1),  6),
        ("RIGHTPADDING", (0,0), (-1,-1),  6),
        ("VALIGN",       (0,0), (-1,-1),  "MIDDLE"),
        ("BOX",          (0,0), (-1,-1),  0.8, GMID),
        ("LINEBELOW",    (0,0), (-1,-2),  0.4, GMID),
    ]))

    # RIGHT: 30-day timeline
    weeks = [
        ("WEEK 1–2", GOLD, [
            ("Connect live databases (PostgreSQL, Redis, Neo4j)", "Persistence replaces in-memory stubs"),
            ("Apply API key auth to trust-check endpoint",        "Rails can now onboard securely"),
            ("Daily spend cap accumulator",                       "Closes last policy-enforcement gap"),
            ("End-to-end integration test",                       "Required for any investor demo"),
        ]),
        ("WEEK 2–3", NAVY, [
            ("Compile SP1 ZK circuits → ELF binaries",           "The privacy proof becomes real"),
            ("Background proof refresh job → Redis cache",        "Hot path reads proof, not raw score"),
            ("Wire threshold proof into trust-check route",       "Score never leaves our system"),
        ]),
        ("WEEK 3–4", GREEN, [
            ("x402 payment rail integration",                     "First revenue-generating integration"),
            ("immudb anchoring (real gRPC calls)",                "Unlocks insurance / regulator use case"),
            ("A2A protocol adapter (Google / Anthropic agents)",  "Expands addressable agent ecosystem"),
            ("Basic rate limiting + TLS config",                  "Minimum security bar for pilots"),
        ]),
    ]

    right_rows = [[Paragraph("30-DAY PLAN TO MVP DEMO", sec)]]
    for label, colour, tasks in weeks:
        # Week header
        hdr = Table([[Paragraph(label, S("wh2", fontName="Helvetica-Bold",
                                          fontSize=8, textColor=WHITE, leading=10))]],
                    colWidths=[5.8*cm])
        hdr.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), colour),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ]))
        right_rows.append([hdr])
        for task, sub in tasks:
            cell = Table([
                [Paragraph(f"→ <b>{task}</b>", step)],
                [Paragraph(sub, small)],
            ], colWidths=[5.6*cm])
            cell.setStyle(TableStyle([
                ("TOPPADDING",   (0,0), (-1,-1), 1),
                ("BOTTOMPADDING",(0,0), (-1,-1), 1),
                ("LEFTPADDING",  (0,0), (-1,-1), 0),
                ("RIGHTPADDING", (0,0), (-1,-1), 0),
            ]))
            right_rows.append([cell])

    right_tbl = Table(right_rows, colWidths=[5.8*cm])
    right_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,0),   NAVY),
        ("TEXTCOLOR",    (0,0), (0,0),   WHITE),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 2),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("BOX",          (0,0), (-1,-1), 0.8, GMID),
        ("LINEBELOW",    (0,0), (-1,-2), 0.3, GMID),
        ("ROWBACKGROUNDS",(1,0),(-1,-1), [WHITE, GLITE]),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
    ]))

    body_tbl = Table([[left_tbl, Spacer(0.3*cm, 1), right_tbl]],
                     colWidths=[13.6*cm, 0.3*cm, 5.8*cm])
    body_tbl.setStyle(TableStyle([
        ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",  (0,0), (-1,-1), 0),
        ("BOTTOMPADDING",(0,0),(-1,-1), 0),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING",(0,0), (-1,-1), 0),
    ]))
    story.append(body_tbl)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f"Written: {path}")


if __name__ == "__main__":
    import os
    build(os.path.join(os.path.dirname(__file__), "Byzantium_Progress_Report.pdf"))

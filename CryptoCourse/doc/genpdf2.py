from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Preformatted,
                                ListFlowable, ListItem)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
import xml.sax.saxutils as su
import re

MD = r"E:\windows库\桌面\ws\RSA\CryptoCourse\doc\课程设计报告.md"
OUT = r"E:\windows库\桌面\ws\RSA\CryptoCourse\doc\课程设计报告.pdf"

pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
FONT = "STSong-Light"

def esc(t):
    return su.escape(t)

styles = {
    "title": ParagraphStyle("title", fontName=FONT, fontSize=18, leading=24, spaceAfter=8),
    "h1": ParagraphStyle("h1", fontName=FONT, fontSize=14, leading=20, spaceBefore=10, spaceAfter=5),
    "h2": ParagraphStyle("h2", fontName=FONT, fontSize=12, leading=17, spaceBefore=7, spaceAfter=4),
    "h3": ParagraphStyle("h3", fontName=FONT, fontSize=11, leading=15, spaceBefore=5, spaceAfter=3),
    "body": ParagraphStyle("body", fontName=FONT, fontSize=10.5, leading=15, spaceAfter=4),
    "quote": ParagraphStyle("quote", fontName=FONT, fontSize=9.5, leading=13, leftIndent=12,
                            textColor="#333333", spaceAfter=4),
}

def clean_inline(t):
    t = re.sub(r"`([^`]+)`", r"<b>\1</b>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    return t

doc = SimpleDocTemplate(OUT, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm,
                        topMargin=18*mm, bottomMargin=18*mm)
flow = []

with open(MD, encoding="utf-8") as f:
    lines = f.read().split("\n")

i = 0
while i < len(lines):
    raw = lines[i].rstrip("\n")
    if raw.strip() == "":
        flow.append(Spacer(1, 4)); i += 1; continue
    if raw.startswith("### "):
        flow.append(Paragraph(esc(clean_inline(raw[4:])), styles["h3"]))
    elif raw.startswith("## "):
        flow.append(Paragraph(esc(clean_inline(raw[3:])), styles["h2"]))
    elif raw.startswith("# "):
        flow.append(Paragraph(esc(clean_inline(raw[2:])), styles["title"]))
    elif raw.startswith("> "):
        flow.append(Paragraph(esc(clean_inline(raw[2:])), styles["quote"]))
    elif raw.startswith("- "):
        flow.append(Paragraph("• " + esc(clean_inline(raw[2:])), styles["body"]))
    elif raw.startswith("|"):
        cells = [c.strip() for c in raw.strip("|").split("|")]
        flow.append(Preformatted("  " + "  |  ".join(cells),
                     ParagraphStyle("tbl", fontName=FONT, fontSize=9, leading=12)))
    else:
        flow.append(Paragraph(esc(clean_inline(raw)), styles["body"]))
    i += 1

doc.build(flow)
print("PDF written:", OUT)

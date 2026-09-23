"""Structural PDF checks; rendered-page visual review remains a separate gate."""
import hashlib
import json
from pathlib import Path
import re
import pdfplumber
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parent
source = ROOT / 'whitepaper_en.md'
pdf = ROOT.parent / 'whitepaper-en.pdf'
raw = source.read_text()
assert re.findall(r'^## (\d+)\.', raw, re.M) == [str(i) for i in range(1, 10)]
assert re.findall(r'^## Appendix ([A-E])\.', raw, re.M) == list('ABCDE')
assert re.findall(r'^\[FIG:([^\]]+)\]', raw, re.M) == [
    'system', 'graph', 'agenda', 'delivery', 'helpers', 'payments', 'citation', 'membership', 'agreement', 'reuse']
assert raw.index('[FIG:system]') < raw.index('## 2.')
assert all(term not in raw for term in ('Implementation status', 'state-v5 pilot'))
reader = PdfReader(pdf)
assert reader.outline
with pdfplumber.open(pdf) as document:
    text = '\n'.join(page.extract_text() or '' for page in document.pages)
    for term in ('Purpose and scope', 'Bounded profile and open rules', 'KNOWN_UNPAID', 'Test-NAO', 'READY', 'TERMINAL',
                 'ProofId', 'QuestionId', 'ResolutionId', 'source', 'seven-day'):
        assert term in text, term
    assert 'Implementation status' not in text
    for n, page in enumerate(document.pages, 1):
        text = page.extract_text() or ''
        assert len(text.split()) > 50 and '\ufffd' not in text and '\u25a0' not in text, n
        assert all(60 <= c['x0'] <= c['x1'] <= page.width - 60 for c in page.chars), n
        assert all(20 <= c['top'] < c['bottom'] <= page.height - 20 for c in page.chars), n
        assert ''.join(c['text'] for c in page.chars if c['top'] > page.height - 44) == str(n), n
for page in reader.pages:
    for font in page['/Resources'].get('/Font', {}).values():
        descriptor = font.get_object().get('/FontDescriptor')
        if descriptor:
            assert any(k in descriptor.get_object() for k in ('/FontFile', '/FontFile2', '/FontFile3'))
links = {a.get_object().get('/A', {}).get('/URI') for page in reader.pages for a in page.get('/Annots', [])}
assert links == {'https://arxiv.org/html/1807.04938v3'}
print(json.dumps({'structural_checks': 'passed', 'pages': len(reader.pages),
                  'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                  'pdf_sha256': hashlib.sha256(pdf.read_bytes()).hexdigest(),
                  'visual_review': 'separate required gate'}, indent=2))

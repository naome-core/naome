"""Structural PDF checks; rendered-page visual review remains a separate gate."""
import hashlib
import json
from pathlib import Path
import re
import sys
import pdfplumber
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parent
variant = len(sys.argv) == 2 and sys.argv[1] == 'variable-en'
assert len(sys.argv) == 1 or variant, 'use no argument or variable-en'
source = ROOT / ('whitepaper_variable_proposal_en.md' if variant else 'whitepaper_en.md')
pdf = ROOT.parent / ('whitepaper-variable-proposal-en.pdf' if variant else 'whitepaper-en.pdf')
raw = source.read_text()
assert re.findall(r'^## (\d+)\.', raw, re.M) == [str(i) for i in range(1, 10)]
assert re.findall(r'^## Appendix ([A-E])\.', raw, re.M) == list('ABCDE')
figures = ['system', 'graph', 'agenda', 'delivery', 'helpers', 'payments', 'citation', 'membership', 'agreement', 'reuse']
assert re.findall(r'^\[FIG:([^\]]+)\]', raw, re.M) == figures
assert raw.index('[FIG:system]') < raw.index('## 2.')
assert '4 ≤ N ≤ 32' in raw
assert ('256' not in raw) if variant else ('historical v6 256-seat' in raw)
assert all(term not in raw for term in ('Implementation status', 'state-v5 pilot'))
assert ('Variable-roster proposal v0.2' if variant else 'Draft v0.2') in raw
assert ('24 September 2026' if variant else '28 September 2026') in raw
if variant:
    assert all(term not in raw for term in ('K = 4', 'three-of-four', 'READY 3/4', 'TERMINAL 3/4', 'four owner accounts'))
reader = PdfReader(pdf)
assert reader.outline
with pdfplumber.open(pdf) as document:
    text = '\n'.join(page.extract_text() or '' for page in document.pages)
    for term in ('Purpose and scope', 'Bounded profile and open rules', 'KNOWN_UNPAID', 'Test-NAO', 'READY', 'TERMINAL',
                 'ProofId', 'QuestionId', 'ResolutionId', 'source', 'seven-day'):
        assert term in text, term
    for term in (('Variable-roster proposal v0.2', '32-unit ceiling', 'READY', 'TERMINAL') if variant else ('Draft v0.2', 'founder', 'state-v7',)):
        assert term in text, term
    assert 'Implementation status' not in text
    for n, page in enumerate(document.pages, 1):
        text = page.extract_text() or ''
        assert len(text.split()) > 150 and '\ufffd' not in text and '\u25a0' not in text, n
        assert all(60 <= c['x0'] <= c['x1'] <= page.width - 60 for c in page.chars), n
        assert all(20 <= c['top'] < c['bottom'] <= page.height - 20 for c in page.chars), n
        assert ''.join(c['text'] for c in page.chars if c['top'] > page.height - 44) == str(n), n
for page in reader.pages:
    for font in page['/Resources'].get('/Font', {}).values():
        descriptor = font.get_object().get('/FontDescriptor')
        if descriptor:
            assert any(k in descriptor.get_object() for k in ('/FontFile', '/FontFile2', '/FontFile3'))
links = {a.get_object().get('/A', {}).get('/URI') for page in reader.pages for a in page.get('/Annots', [])}
assert links == ({'https://arxiv.org/html/1807.04938v3'} if variant else {'https://arxiv.org/html/1807.04938v3',
                 'https://ethereum.org/guides/how-to-create-an-ethereum-account/',
                 'https://ethereum.org/developers/docs/gas/',
                 'https://ethereum.org/developers/docs/consensus-mechanisms/pos/attestations'})
print(json.dumps({'structural_checks': 'passed', 'variant': 'variable' if variant else 'base', 'pages': len(reader.pages),
                  'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                  'pdf_sha256': hashlib.sha256(pdf.read_bytes()).hexdigest(),
                  'visual_review': 'separate required gate'}, indent=2))

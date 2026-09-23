from pathlib import Path
import re, math, json, hashlib
from reportlab import rl_config
rl_config.invariant = 1
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Flowable, KeepTogether, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase.pdfmetrics import registerFont, registerFontFamily, stringWidth, getFont
from reportlab.pdfbase.ttfonts import TTFont
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parent
OUT=ROOT.parent
FONT=Path('/System/Library/Fonts/Supplemental')
for name,suffix in [('NSerif',''),('NSerifBold',' Bold'),('NSerifItalic',' Italic'),('NSerifBoldItalic',' Bold Italic')]:
    registerFont(TTFont(name,str(FONT/f'Times New Roman{suffix}.ttf')))
registerFontFamily('NSerif',normal='NSerif',bold='NSerifBold',italic='NSerifItalic',boldItalic='NSerifBoldItalic')
registerFont(TTFont('NMath',str(FONT/'Arial Unicode.ttf')))
registerFont(TTFont('NMono',str(FONT/'Andale Mono.ttf')))
W,H=A4;M=61;CW=W-2*M-12
INK=colors.HexColor('#222222');GRAY=colors.HexColor('#dddddd');PALE=colors.HexColor('#f5f5f5')

def rich(s):
    return s.replace('∀','<font name="NMath">∀</font>').replace('⅔','2/3')

def styles(lang):
    body=ParagraphStyle('body',fontName='NSerif',fontSize=11,leading=14.8,alignment=TA_LEFT,spaceAfter=6.5,textColor=INK,allowWidows=0,allowOrphans=0)
    return {
      'body':body,
      'heading':ParagraphStyle('heading',parent=body,fontName='NSerifBold',fontSize=14,leading=17.5,spaceBefore=17,spaceAfter=9,keepWithNext=True),
      'sub':ParagraphStyle('sub',parent=body,fontName='NSerifBold',fontSize=11.7,leading=15,spaceBefore=10,spaceAfter=7,keepWithNext=True),
      'title':ParagraphStyle('title',parent=body,fontName='NSerifBold',fontSize=21,leading=25,alignment=TA_CENTER,spaceAfter=3),
      'subtitle':ParagraphStyle('subtitle',parent=body,fontName='NSerifBold',fontSize=17,leading=21,alignment=TA_CENTER,spaceAfter=14),
      'meta':ParagraphStyle('meta',parent=body,fontSize=9.5,leading=12,alignment=TA_CENTER,spaceAfter=16),
      'abstract':ParagraphStyle('abstract',parent=body,fontSize=10.8,leading=14.3,leftIndent=18,rightIndent=18,spaceAfter=14),
      'caption':ParagraphStyle('caption',parent=body,fontName='NSerifItalic',fontSize=9.8,leading=12.4,spaceBefore=2,spaceAfter=12),
      'equation':ParagraphStyle('equation',parent=body,fontName='NSerifItalic',fontSize=11,leading=17.5,alignment=TA_CENTER,spaceBefore=2,spaceAfter=9),
      'ref':ParagraphStyle('ref',parent=body,fontSize=9.1,leading=11.5,spaceAfter=5),
    }

class Figure(Flowable):
    def __init__(self,kind,lang):
        super().__init__();self.kind=kind;self.lang=lang;self.width=CW
        self.height={'system':254,'question':152,'graph':157,'membership':116,'agenda':91,'agreement':224,'delivery':113,'payments':230,'citation':252,'helpers':262,'reuse':292,'security':101,'journey':86}[kind]
        self.spaceBefore=3;self.spaceAfter=7
    def label(self,x,y,t,size=10.5,bold=False,left=False,color=INK):
        self.canv.setFont('NMath' if '∀' in t else ('NSerifBold' if bold else 'NSerif'),size);self.canv.setFillColor(color)
        (self.canv.drawString if left else self.canv.drawCentredString)(x,y,t)
    def arrow(self,points):
        c=self.canv;c.setStrokeColor(INK);c.setLineWidth(.7)
        for a,b in zip(points,points[1:]):c.line(*a,*b)
        a,b=points[-2:];ang=math.atan2(b[1]-a[1],b[0]-a[0])
        for d in [-.45,.45]:c.line(*b,b[0]-4*math.cos(ang+d),b[1]-4*math.sin(ang+d))
    def box(self,x,y,w,h,text,shade=False,size=10.5):
        c=self.canv;c.setStrokeColor(colors.HexColor('#777777'));c.setLineWidth(.6);c.setFillColor(PALE if shade else colors.white);c.roundRect(x,y,w,h,4,stroke=1,fill=1)
        p=Paragraph(rich(text),ParagraphStyle('figure',fontName='NSerif',fontSize=size,leading=size+2.7,alignment=TA_CENTER,textColor=INK))
        _,ph=p.wrap(w-16,999)
        assert ph<=h-12,(self.kind,self.lang,text,ph,h)
        p.drawOn(c,x+8,y+(h-ph)/2)
    def stages(self,texts,y=24):
        n=len(texts);pitch=CW/n;xs=[pitch*(i+.5) for i in range(n)]
        for i,x in enumerate(xs):
            self.canv.setStrokeColor(INK);self.canv.setFillColor(PALE);self.canv.circle(x,y+32,12,stroke=1,fill=1)
            self.label(x,y+28,str(i+1),10.5,True)
            if i<n-1:self.arrow([(x+15,y+32),(xs[i+1]-15,y+32)])
            p=Paragraph(rich(texts[i]),ParagraphStyle('step',fontName='NSerif',fontSize=10.5,leading=13,alignment=TA_CENTER,textColor=INK))
            _,ph=p.wrap(pitch-12,999);assert ph<=26.01,(texts[i],ph)
            p.drawOn(self.canv,x-(pitch-12)/2,y+10-ph)
    def draw(self):
        c=self.canv;de=self.lang=='de';k=self.kind
        if k=='system':
            accent=colors.HexColor('#41566b')
            cx= CW/2;cy=127;rx=175;ry=85
            c.setStrokeColor(accent);c.setLineWidth(1.2)
            c.ellipse(cx-rx,cy-ry,cx+rx,cy+ry,stroke=1,fill=0)
            for degrees in (120,60,0,-60,-120,-180):
                a=math.radians(degrees)
                x=cx+rx*math.cos(a);y=cy+ry*math.sin(a)
                dx=rx*math.sin(a);dy=-ry*math.cos(a)
                length=math.hypot(dx,dy);tx=dx/length;ty=dy/length
                nx=-ty;ny=tx
                c.setFillColor(accent)
                p=c.beginPath();p.moveTo(x,y)
                p.lineTo(x-8*tx+3.5*nx,y-8*ty+3.5*ny)
                p.lineTo(x-8*tx-3.5*nx,y-8*ty-3.5*ny)
                p.close();c.drawPath(p,stroke=0,fill=1)
            labels=(['<b>Frage</b><br/>aufnehmen, öffnen','<b>Eigentümerwahl</b><br/>feste Bedingungen','<b>Einreichung</b><br/>binden, offenlegen','<b>Prüfung</b><br/>Beweis oder Widerlegung','<b>Abschluss</b><br/>nur bei Annahme zahlen','<b>Siegel und Fortsetzung</b><br/>Beitritt optional'] if de else ['<b>Question</b><br/>admit and open','<b>Owner vote</b><br/>frozen terms','<b>Submission</b><br/>commit, disclose','<b>Verification</b><br/>proof or refutation','<b>Settlement</b><br/>pay only if accepted','<b>Seal and continue</b><br/>handoff optional'])
            angles=(150,90,30,-30,-90,-150)
            label_bottoms=(187,227,187,42,4,42)
            label_width=130
            for i,(degrees,label,bottom) in enumerate(zip(angles,labels,label_bottoms),1):
                a=math.radians(degrees)
                x=cx+rx*math.cos(a);y=cy+ry*math.sin(a)
                c.setFillColor(accent);c.circle(x,y,12.5,stroke=0,fill=1)
                c.setFillColor(colors.white);c.setFont('NSerifBold',10)
                c.drawCentredString(x,y-3.4,str(i))
                p=Paragraph(rich(label),ParagraphStyle('cycle-label',fontName='NSerif',fontSize=9.8,leading=12.2,alignment=TA_CENTER,textColor=INK))
                _,ph=p.wrap(label_width,999);assert ph<=27,(label,ph)
                p.drawOn(c,x-label_width/2,bottom)
            self.label(CW/2,149,'EIN NETZWERKZYKLUS' if de else 'ONE NETWORK CYCLE',11.5,True,color=accent)
            c.setStrokeColor(colors.HexColor('#c4cbd1'));c.setLineWidth(.45)
            c.line(165,139,CW-165,139)
            self.label(CW/2,120,'Über mehrere vereinbarte und versiegelte Datensätze' if de else 'Across multiple agreed and sealed records',9.5)
        elif k=='question':
            gap=18;bw=(CW-gap)/2
            for i,title in enumerate(['question.nao','solution.nao']):
                x=i*(bw+gap);c.setStrokeColor(colors.HexColor('#aaaaaa'));c.setFillColor(PALE);c.setLineWidth(.5);c.rect(x,35,bw,111,stroke=1,fill=1)
                self.label(x+10,130,title,10.5,True,True)
            snippets=[['success = "resolve"','statement = not_(forall(x,','    equal(x, x)))'],['proof:','  p0 = equality_reflexivity(x)','  p1 = generalization(p0, x)','  return p1']]
            for i,lines in enumerate(snippets):
                x=i*(bw+gap)
                for j,line in enumerate(lines):
                    assert stringWidth(line,'NMono',8.7)<=bw-18,line
                    c.setFont('NMono',8.7);c.setFillColor(INK);c.drawString(x+9,108-j*12.5,line)
            self.label(bw/2,45,'Auszug: falsche Behauptung' if de else 'Excerpt: false claim',9.1)
            self.label(bw+gap+bw/2,45,'Auszug: zwei geprüfte Schritte' if de else 'Excerpt: two checked steps',9.1)
            self.arrow([(bw/2,32),(bw/2,19),(CW/2-47,19)])
            self.arrow([(CW-bw/2,32),(CW-bw/2,19),(CW/2+47,19)])
            self.label(CW/2,15,'REFUTED',11,True)
            self.label(CW/2,0,'Geprüft: ∀x. x = x; keine zusätzliche Annahme' if de else 'Checked: ∀x. x = x; no additional assumption',10)
        elif k=='graph':
            gap=20;bw=(CW-2*gap)/3
            self.box(0,102,bw,47,'<b>Formale Frage</b><br/>genehmigte Ziele R, ¬R' if de else '<b>Formal question</b><br/>approved targets R, ¬R',size=10)
            self.box(bw+gap,102,bw,47,'<b>Geprüftes Zertifikat</b><br/>belegt genau ein Ziel' if de else '<b>Checked certificate</b><br/>establishes one target',size=10)
            self.box(2*(bw+gap),102,bw,47,'<b>Tatsächliches Ergebnis</b><br/>bewiesene Schlussformel' if de else '<b>Actual result</b><br/>the proved conclusion',size=10)
            self.arrow([(bw+2,125),(bw+gap-2,125)])
            self.arrow([(2*bw+gap+2,125),(2*(bw+gap)-2,125)])
            self.label(CW/2,79,'Erfolgreiche Auswahl und Abrechnung erforderlich' if de else 'Successful selection and settlement required',10.3,True)
            self.box(0,14,(CW-20)/2,48,'<b>Bibliothek</b><br/>speichert den tatsächlich geführten Beweis' if de else '<b>Library</b><br/>records the proof actually established',size=10.1)
            self.box((CW+20)/2,14,(CW-20)/2,48,'<b>ResolutionId</b><br/>markiert die Fragenfamilie als abgeschlossen' if de else '<b>ResolutionId</b><br/>marks the question family completed',size=10.1)
            self.arrow([(CW/2,99),(CW/2,91)])
            self.arrow([(CW/2,73),(CW/2,67),((CW-20)/4,67),((CW-20)/4,64)])
            self.arrow([(CW/2,73),(CW/2,67),((3*CW+20)/4,67),((3*CW+20)/4,64)])
        elif k=='membership':
            self.label(CW/2,102,'Vier stabile Sitze; Schlüssel wechseln in jeder Periode' if de else 'Four stable slots; keys rotate every period',10.7,True)
            start=74;gap=11;bw=(CW-start-3*gap)/4
            before=['10','13','17','21'];after=['19','13','17','21']
            for y,values in [(61,before),(5,after)]:
                self.label(4,y+9,('Vorher' if y==61 else 'Nachher') if de else ('Before' if y==61 else 'After'),10.2,True,True)
                for i,value in enumerate(values):
                    self.box(start+i*(bw+gap),y,bw,28,f'<b>S{i+1}</b>  {value}',shade=(y==5 and i==0),size=10.3)
            self.label(CW/2,43,'Anspruch 19 ersetzt die älteste Einheit 10 in Sitz S1' if de else 'Claim 19 replaces oldest unit 10 in slot S1',10.0)
        elif k=='agenda':
            self.box(0,42,123,39,'<b>Forschungsprofil</b><br/>Eigentümerinteressen' if de else '<b>Research Profile</b><br/>Owner’s interests',size=10)
            self.box((CW-146)/2,42,146,39,'<b>KI-Entscheidung</b><br/>YES / NO' if de else '<b>AI decision</b><br/>YES / NO',size=10)
            self.box(CW-123,42,123,39,'<b>Signierte Stimme</b><br/>exakte Frage' if de else '<b>Signed ballot</b><br/>exact question',True,size=10)
            self.arrow([(126,61),((CW-146)/2-3,61)]);self.arrow([((CW+146)/2+3,61),(CW-126,61)])
            self.label(CW/2,19,'Bei Fristende: 67 YES von 100 → genehmigt' if de else 'At the deadline: 67 YES out of 100 → approved',10.5,True)
            self.label(CW/2,3,'T: Eröffnung | volle sieben Tage | D: Abschluss' if de else 'T: opening | full seven days | D: closure',10)
        elif k=='agreement':
            self.label(CW/2,210,'Datensatz h enthält den exakten Plan für S(h+1)' if de else 'Agreed record h contains the exact plan for S(h+1)',10.8,True)
            self.label(0,166,'Eingehend' if de else 'Incoming',9.8,True,True)
            self.box(76,139,154,51,'<b>Historie prüfen</b><br/>Nachfolger dauerhaft vorbereiten' if de else '<b>Verify history</b><br/>prepare successor durably',size=10.1)
            self.box(273,139,CW-273,51,'<b>READY 3/4</b><br/>exakter Datensatz und Zustand' if de else '<b>READY 3/4</b><br/>exact record and state',size=10.1)
            self.arrow([(233,164),(270,164)])
            self.label(0,85,'Ausgehend' if de else 'Outgoing',9.8,True,True)
            self.box(76,57,102,62,'<b>TERMINAL</b><br/>Signatur speichern' if de else '<b>TERMINAL</b><br/>save signature',size=9.9)
            self.box(194,57,115,62,'<b>Fähigkeit stilllegen</b><br/>alte Periode' if de else '<b>Retire capability</b><br/>old period',size=9.9)
            self.box(325,57,CW-325,62,'<b>TERMINAL 3/4</b><br/>freigeben und versiegeln' if de else '<b>TERMINAL 3/4</b><br/>release and seal',size=9.9)
            self.arrow([(181,88),(191,88)]);self.arrow([(312,88),(322,88)])
            self.arrow([(354,136),(354,128),(127,128),(127,121)])
            self.arrow([(389,54),(389,43)])
            self.label(CW/2,29,'Erst der vollständige Siegelbeleg installiert S(h+1).' if de else 'Only complete seal evidence installs S(h+1).',10.1,True)
            self.label(CW/2,9,'Leere Sitze zählen weiter; externe Schlüsselkopien erfordern Betreiberkontrolle.' if de else 'Vacant slots still count; external key copies require operator control.',9.4)
        elif k=='delivery':
            self.label(CW/2,98,'Lösungsphase nach versiegelter Genehmigung' if de else 'Solution phase after sealed approval',10.7,True)
            gap=12;bw=(CW-4*gap)/5
            labels=(['<b>Commitment</b><br/>Original binden','<b>Bindungsphase</b><br/>Abschluss versiegelt','<b>Offenlegung</b><br/>Original bereitstellen','<b>Offenlegungen</b><br/>geschlossen','<b>Auswahl</b><br/>berechtigte gültige Quittung'] if de else ['<b>Commitment</b><br/>bind the original','<b>Commitment</b><br/>closure sealed','<b>Disclosure</b><br/>supply the original','<b>Disclosures</b><br/>closed','<b>Selection</b><br/>eligible valid receipt'])
            for i,label in enumerate(labels):
                self.box(i*(bw+gap),25,bw,62,label,size=9.5)
                if i<4:self.arrow([(i*(bw+gap)+bw+2,56),((i+1)*(bw+gap)-2,56)])
            self.label(CW/2,7,'Abrechnung verlangt zusätzlich gültige Prüfung gegen ihren tatsächlichen Elternzustand.' if de else 'Settlement also requires valid checking against its actual parent state.',9.5)
        elif k=='helpers':
            self.label(CW/2,248,'Erst vollständig prüfen, dann gemeinsam veröffentlichen' if de else 'Validate completely, then publish together',11,True)
            gap=14;bw=(CW-2*gap)/3
            titles=(['<b>1. Original prüfen</b><br/>Commitment, Lösung und alle Hilfsbeweise','<b>2. Wiederverwenden</b><br/>Duplikate ersetzen; ungenutzte Teile entfernen','<b>3. Ergebnis prüfen</b><br/>Ganze bereinigte Gruppe und tatsächliche Nutzung'] if de else ['<b>1. Check original</b><br/>Commitment, solution and every helper proof','<b>2. Reuse old proofs</b><br/>Replace duplicates; remove unused branches','<b>3. Check final group</b><br/>Complete normalized proof and actual use'])
            for i,title in enumerate(titles):
                self.box(i*(bw+gap),151,bw,81,title,size=10.2)
                if i<2:self.arrow([(i*(bw+gap)+bw+2,192),((i+1)*(bw+gap)-2,192)])
            last_x=2*(bw+gap)+bw/2
            self.arrow([(last_x,148),(last_x,139),(CW/2,139),(CW/2,131)])
            c.setStrokeColor(colors.HexColor('#999999'));c.setFillColor(PALE)
            c.roundRect(0,26,CW,99,5,stroke=1,fill=1)
            self.label(CW/2,109,'Ein versiegelter Datensatz bestätigt die ganze Gruppe' if de else 'One sealed record accepts the whole group',10.5,True)
            self.box(14,41,132,50,'<b>Beweisblock A</b><br/>eigene Adresse' if de else '<b>Proof block A</b><br/>own address',size=10.2)
            self.box(164,41,132,50,'<b>Beweisblock F</b><br/>eigene Adresse' if de else '<b>Proof block F</b><br/>own address',size=10.2)
            self.box(314,41,CW-328,50,'<b>Abschluss F</b><br/>einmal abrechnen' if de else '<b>Completion F</b><br/>settle once',size=10.2)
            self.label(CW/2,7,'Bei ungültiger Lösung: kein neuer Beweisblock aus dieser Gruppe' if de else 'Invalid solution: no new proof block from this group',10.2,True)
        elif k=='reuse':
            gap=25;bw=(CW-gap)/2;xx=bw+gap
            self.label(bw/2,278,'Eingereicht' if de else 'Submitted',11,True)
            self.label(xx+bw/2,278,'Nach Ersetzung und Bereinigung' if de else 'After replacement and pruning',10.2,True)
            for x in (0,xx):
                c.setStrokeColor(colors.HexColor('#bbbbbb'));c.setFillColor(PALE);c.roundRect(x,56,bw,207,5,stroke=1,fill=1)
                self.box(x+77,211,64,35,'<b>F</b>',size=11)
                self.box(x+10,140,70,43,'<b>A</b><br/>neu' if de else '<b>A</b><br/>new',size=10.2)
                self.arrow([(x+95,208),(x+45,186)])
                self.arrow([(x+123,208),(x+166,186)])
            self.box(125,140,81,43,'<b>H</b><br/>wie C' if de else '<b>H</b><br/>same as C',size=10.2)
            self.box(125,68,81,43,'<b>B</b><br/>nur für H' if de else '<b>B</b><br/>only for H',size=10.2)
            self.arrow([(165.5,137),(165.5,114)])
            self.box(xx+125,140,81,43,'<b>C</b><br/>gespeichert' if de else '<b>C</b><br/>stored',True,size=10.2)
            self.label(xx+bw/2,108,'H ersetzt; B nicht mehr benötigt' if de else 'H replaced; B no longer needed',9.5)
            self.label(xx+bw/2,87,'H und B werden nicht aufgenommen' if de else 'H and B are not newly admitted',9.3)
            self.arrow([(bw+3,228),(bw+gap-3,228)])
            self.label(CW/2,38,'C: gleiche kanonische Aussage, gleiche Foundation und Annahmen' if de else 'C: same canonical conclusion, same Foundation and assumptions',10)
            self.label(CW/2,21,'C ist zitierberechtigt; A erst bei späterer berechtigter Verwendung' if de else 'C is citation-eligible; A only through later eligible use',10,True)
            self.label(CW/2,4,'Pfeile im Graphen bedeuten: verwendet. Zitate aus entfernten Zweigen entfallen.' if de else 'Graph arrows mean uses. Citations from removed branches no longer count.',9.5)
        elif k=='citation':
            self.label(CW/2,237,'Zitierberechtigung folgt dem endgültigen Beweis' if de else 'Citation eligibility follows the final proof',11,True)
            c.setStrokeColor(colors.HexColor('#bbbbbb'));c.setFillColor(PALE)
            c.roundRect(0,57,225,165,5,stroke=1,fill=1)
            self.label(112,205,'Neu im aktuellen Datensatz' if de else 'New in the current record',10.1,True)
            self.label(350,205,'Schon im versiegelten Elternzustand' if de else 'Already in the sealed parent',9.7,True)
            self.box(11,116,64,43,'<b>F</b><br/>Lösung' if de else '<b>F</b><br/>solution',size=10)
            self.box(132,161,70,36,'<b>A</b>',size=10.7)
            self.box(132,78,70,36,'<b>B</b>',size=10.7)
            self.box(268,116,72,43,'<b>C</b><br/>älter' if de else '<b>C</b><br/>older',True,size=10)
            self.box(384,116,CW-384,43,'<b>D</b><br/>Vorfahr' if de else '<b>D</b><br/>ancestor',size=9.8)
            self.arrow([(78,145),(108,179),(129,179)])
            self.arrow([(78,129),(108,96),(129,96)])
            self.arrow([(205,179),(235,179),(265,145)])
            self.arrow([(205,96),(235,96),(265,129)])
            self.arrow([(343,137),(381,137)])
            self.label(304,100,'einmal berechtigt' if de else 'eligible once',9.7,True)
            self.label(422,94,'keine automatische' if de else 'no automatic',9.2)
            self.label(422,80,'Zahlung auf diesem Pfad' if de else 'payment on this path',8.8)
            self.label(112,39,'Kein Anteil aus diesem Datensatz' if de else 'No share from this record',10,True)
            self.label(344,39,'Der erste ältere Beweis beendet den Zahlungspfad.' if de else 'The first older proof ends the payment path.',9)
            self.label(CW/2,18,'Pfeile bedeuten: verwendet. Zwei Pfade zu C ergeben einen Pool-Eintrag.' if de else 'Arrows mean uses. Two paths to C produce one pool entry.',9.8)
            self.label(CW/2,2,'Auch D kann für die Gültigkeitsprüfung weiterhin benötigt werden.' if de else 'D may still be required for validity checking.',10)
        elif k=='payments':
            self.label(CW/2,213,'Ein Forschungsabschluss gibt insgesamt 1 NAO aus' if de else 'One research completion issues 1 NAO in total',11,True)
            self.box(0,151,258,49,'<b>0,70 NAO: gemeinsames Forschungsbudget</b><br/>Lösung: 0,70 − P | Zitierpool: P' if de else '<b>0.70 NAO: combined research budget</b><br/>Solution: 0.70 − P | Citation pool: P',True,size=10.3)
            self.box(269,151,94,49,'<b>0,20 NAO</b><br/>Validatorbetrieb' if de else '<b>0.20 NAO</b><br/>Validator service',size=9.7)
            self.box(374,151,CW-374,49,'<b>0,10 NAO</b><br/>Reserve' if de else '<b>0.10 NAO</b><br/>Reserve',size=10)
            self.label(0,130,'DATENSATZ n' if de else 'RECORD n',9.5,True,True)
            self.box(72,78,170,47,'<b>Empfänger zu F</b><br/>erhält 0,70 NAO minus P' if de else '<b>Recipient for F</b><br/>receives 0.70 NAO minus P',size=10.1)
            self.box(260,78,CW-260,47,'<b>Empfänger von C</b><br/>Anteil gemäß Pool-Richtlinie' if de else '<b>Beneficiary of C</b><br/>share under the pool policy',size=10.1)
            self.label(CW/2,62,'Neuer Hilfsbeweis A: keine Zahlung aus Datensatz n' if de else 'New helper A: no payment from record n',10.2,True)
            self.label(0,39,'SPÄTER' if de else 'LATER',9.5,True,True)
            self.box(72,0,170,49,'<b>Neue Lösung G</b><br/>verwendet das gespeicherte A' if de else '<b>New solution G</b><br/>uses the stored proof A',size=10.1)
            self.box(292,0,CW-292,49,'<b>Empfänger von A</b><br/>bei späterem berechtigtem Zitat' if de else '<b>Beneficiary of A</b><br/>on later eligible citation',size=10)
            self.arrow([(245,24),(289,24)])
        elif k=='security':
            self.label(CW/2,84,'100 gleiche Einheiten; ein Quorum braucht 67' if de else '100 equal units; a quorum needs 67',11,True)
            x=0
            for f,a,b,fill in [(.34,'34 nicht verfügbar' if de else '34 unavailable','Gewicht bleibt erhalten' if de else 'weight still counts',GRAY),(.66,'66 verfügbar' if de else '66 available','Kein Quorum für den nächsten Schritt' if de else 'No quorum for the next transition',colors.white)]:
                ww=CW*f;c.setFillColor(fill);c.setStrokeColor(INK);c.setLineWidth(.6);c.rect(x,28,ww,39,stroke=1,fill=1)
                self.label(x+ww/2,52,a,10.5,True);self.label(x+ww/2,36,b,9.8);x+=ww
            self.label(CW/2,6,'Auch eine Ersetzung braucht ein Quorum; die Uhr entfernt keine Stimmen' if de else 'Replacement also needs a quorum; the clock removes no votes',10)
        elif k=='journey':
            self.stages(['Alice beginnt<br/>mit 0 NAO','Erster gültiger<br/>Beweis gewinnt','Alice: 0,70 NAO<br/>und Stimmanspruch','Später beitreten,<br/>solange berechtigt'] if de else ['Alice starts<br/>with 0 NAO','First eligible<br/>valid answer wins','Alice: 0.70 NAO<br/>and voting claim','Join later while<br/>the claim is eligible'],30)
            self.label(CW/2,0,'Nicht beitreten: Ergebnis und Bezahlung bleiben erhalten' if de else 'Choosing not to join preserves the result and payment',10)
        else:raise ValueError(k)

def footer(canvas,doc):
    canvas.saveState();canvas.setFillColor(colors.HexColor('#666666'));canvas.setFont('NSerif',8.7)
    if doc.page>1:
        canvas.drawString(M+6,H-34,'NAOME')
        canvas.drawRightString(W-M-6,H-34,'Formale Forschung' if doc.paper_lang=='de' else 'Formal Research')
        canvas.setStrokeColor(colors.HexColor('#aaaaaa'));canvas.setLineWidth(.35);canvas.line(M+6,H-44,W-M-6,H-44)
    canvas.setFillColor(INK);canvas.setFont('NSerif',9);canvas.drawCentredString(W/2,31,str(doc.page));canvas.restoreState()

class PaperDoc(SimpleDocTemplate):
    def afterFlowable(self,flowable):
        if isinstance(flowable,Paragraph) and flowable.style.name in ('heading','sub'):
            title=flowable.getPlainText();key=f'heading-{len(self.headings)}'
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title,key,level=0 if flowable.style.name=='heading' else 1,closed=False)
            self.headings.append({'title':title,'page':self.page})

def identity_table(lang,sty):
    de=lang=='de'
    rows=([['Identität','Bezeichnet'],['ResolutionId','Die Foundation und den kanonischen Kern einer Fragenfamilie.'],['QuestionId','Die exakte formale Aufgabe einschließlich ihrer Prüfbedingungen.'],['StatementId','Die expandierte geschlossene Aussage.'],['DerivationId','Den Herleitungsgraphen unabhängig von Einbettung oder Zitierung.'],['ProofId','Das kanonische Beweiszertifikat.'],['ArtifactId','Ein typisiertes kanonisches Bibliotheksobjekt.']] if de else [['Identity','Names'],['ResolutionId','The Foundation and canonical core of a question family.'],['QuestionId','The exact formal task, including its checking conditions.'],['StatementId','The expanded closed conclusion.'],['DerivationId','The inference graph, whether inlined or cited.'],['ProofId','The canonical proof certificate.'],['ArtifactId','A typed canonical library object.']])
    cell=ParagraphStyle('cell',parent=sty['body'],fontSize=10,leading=13,spaceAfter=0)
    head=ParagraphStyle('cellhead',parent=cell,fontName='NSerifBold')
    data=[[Paragraph(v,head if i==0 else cell) for v in row] for i,row in enumerate(rows)]
    table=Table(data,colWidths=[103,CW-103],repeatRows=1,hAlign='LEFT')
    table.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('BACKGROUND',(0,0),(-1,0),PALE),('LINEABOVE',(0,0),(-1,0),.5,INK),('LINEBELOW',(0,0),(-1,0),.4,INK),('LINEBELOW',(0,-1),(-1,-1),.5,INK),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4)]))
    table.spaceBefore=4;table.spaceAfter=12
    return table

def build(lang):
    sty=styles(lang);raw=(ROOT/f'whitepaper_{lang}.md').read_text()
    blocks=re.split(r'\n\s*\n',raw.strip());story=[];title_count=0;figure_count=0;i=0
    while i<len(blocks):
        block=blocks[i];i+=1
        if block=='<!-- APPENDICES -->':story.append(Spacer(1,12));continue
        if block=='[IDENTITIES]':story.append(KeepTogether([identity_table(lang,sty)]));continue
        if block.startswith('[FIG:'):
            figure=Figure(block[5:-1],lang)
            assert blocks[i].startswith('[CAPTION] '),(lang,block,'missing caption')
            figure_count+=1
            prefix='Abbildung' if lang=='de' else 'Figure'
            caption=Paragraph(f'<b>{prefix} {figure_count}.</b> '+rich(blocks[i][10:]),sty['caption']);i+=1
            story.append(KeepTogether([figure,caption]));continue
        if block.startswith('# '):
            for line in block.splitlines():
                story.append(Paragraph(rich(line[2:]),sty['title' if title_count==0 else 'subtitle']));title_count+=1
            continue
        style='body'
        if block in ('## Reference', '## Quelle'):
            assert blocks[i].startswith('[REF1] ')
            reference=blocks[i][7:];i+=1
            label='Quelle' if lang=='de' else 'Reference'
            story.append(Paragraph(f'<b>{label}.</b> [1] '+rich(reference),sty['ref']))
            continue
        if block.startswith('### '):style='sub';block=block[4:]
        elif block.startswith('## '):style='heading';block=block[3:]
        else:
            match=re.match(r'^\[(META|ABSTRACT|CAPTION|EQ|REF\d+)\]\s*(.*)$',block,re.S)
            if match:
                tag,block=match.groups();style={'META':'meta','ABSTRACT':'abstract','CAPTION':'caption','EQ':'equation'}.get(tag,'ref')
                if tag.startswith('REF'):block=f'[{tag[3:]}] '+block
                if tag=='ABSTRACT':block=('<b>Zusammenfassung.</b> ' if lang=='de' else '<b>Abstract.</b> ')+block
        p=Paragraph(rich(block),sty[style])
        for frag in p.frags:
            face=getFont(frag.fontName).face
            for char in getattr(frag,'text',''):assert char.isspace() or ord(char) in face.charWidths,(lang,frag.fontName,char)
        if style=='equation' and story and isinstance(story[-1],Paragraph) and story[-1].style.name=='body':
            lead=story.pop();story.append(KeepTogether([lead,p]))
        else:story.append(p)
    pdf=OUT/f'whitepaper-{lang}.pdf'
    doc=PaperDoc(str(pdf),pagesize=A4,leftMargin=M,rightMargin=M,topMargin=58,bottomMargin=53,title='NAOME: A Public Network for Formal Research' if lang=='en' else 'NAOME: Ein öffentliches Netzwerk für formale Forschung',author='NAOME',subject='A public network for formal research: questions, proof publication, incentives, participation and shared history',pageCompression=1)
    doc.paper_lang=lang;doc.headings=[];doc.build(story,onFirstPage=footer,onLaterPages=footer)
    report={'language':lang,'pages':len(PdfReader(pdf).pages),'headings':doc.headings,'bytes':pdf.stat().st_size,'source_sha256':hashlib.sha256((ROOT/f'whitepaper_{lang}.md').read_bytes()).hexdigest(),'sha256':hashlib.sha256(pdf.read_bytes()).hexdigest()}
    print(json.dumps(report,indent=2));return report
if __name__=='__main__':
    import sys
    reports=[build(l) for l in (sys.argv[1:] or ['en'])]

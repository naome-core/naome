# NAOME: MVP-Start — Anforderungen, Regeln und Abnahme

Stand: 15. September 2026. Forschungsgrundlage ist das beigefügte [deutsche Whitepaper](whitepaper-de.pdf), Ausgabe `concise-v10` vom 14. September 2026.

Herkunft: Zusammengeführt aus dem lokal gesicherten Branch `task/whitepaper-rule-inventory`, Commit `0d6259badd6575d681ebdf2c3b42bff24e396ebc`. Der neue Startbranch `task/mvp-start` wurde auf `origin/main`-Commit `d29f0776aecd1b1d9eca8bb5056f25912a91c17c` angelegt.

**Ziel:** Bekannte, vertrauenswürdige Teilnehmer betreiben gemeinsam ein kleines Forschungsnetz. Sie reichen formale Fragen ein, wählen Aufgaben aus, prüfen Beweise oder Widerlegungen, veröffentlichen wiederverwendbare Ergebnisse und verbuchen die Belohnung auf allen Rechnern übereinstimmend. Die Bedienung erfolgt über die Kommandozeile.

Diese Datei enthält den vollständigen ausgearbeiteten MVP-Vorschlag: 35 offene Anforderungen, sieben Abnahmeszenarien, fünf Umsetzungsschritte und die Regeln R1–R11 mit ihren Parametern. Leere Kästchen bedeuten „muss vor MVP-Abnahme nachgewiesen werden“, nicht „es existiert keinerlei nutzbarer Code“. Es wurde noch kein MVP implementiert. Die vorbereitenden Forschungsmodelle prüfen ausgewählte Regeln; sie erfüllen keine dieser Integrationsanforderungen. Diese Startdatei ändert weder das Whitepaper noch die bestehende Konsensspezifikation des Repositorys.

Die Aussagen zum vorhandenen Code stammen aus dem vorbereitenden Abgleich mit Repository-Commit `02855decfcbd7ec4e152e4debd4ebb7f2de54d93`. Sie sind ein dokumentierter Ausgangspunkt und kein Nachweis späterer Branchstände. Die folgende Planung benötigt keine zusätzlich mitgeführten Modellskripte, Prüfberichte oder Manuskriptquellen.

Navigation: [Checkliste](#checkliste) · [Abnahmeszenarien](#abnahme) · [Umsetzungsschritte](#umsetzung) · [Regeln und Parameter](#regeln) · [Forschungsstand und verbleibende Arbeit](#r11).

## 1. Festgelegter Rahmen und empfohlene Begrenzungen

Vom Nutzer vorgegeben sind der vertrauenswürdige Teilnehmerkreis, „Survival of the first“, die zunächst ausreichende Kommandozeile sowie diese Forschungs- und Planungsphase. Die folgenden konkreten Vereinfachungen sind begründete **R&D-Empfehlungen für das MVP-Profil**, keine bereits beschlossenen Änderungen des öffentlichen Protokolls. Ihre genaue Bedeutung steht in den [Regeln R1–R11](#regeln); die Abnahmefälle machen ihre Auswirkungen überprüfbar.

| Bereich | Vorgeschlagener Umfang |
|---|---|
| Validatoren | Vier feste, gleich gewichtete Validatoren; drei Stimmen bilden ein striktes Zweidrittelquorum. |
| Nutzer | In Genesis registrierte Forschungskonten; Einreichen ist ohne Startguthaben möglich. |
| Forschungsbetrieb | Eine aktive Frage über den gesamten Versuch bis zur Abrechnung; weitere Fragen warten. Mehrere Autoren können gleichzeitig an der aktiven Frage arbeiten. Zur MVP-Abnahme gilt das klar bezeichnete Labprofil mit 5 Minuten Abstimmung und je 2 Minuten Commitment/Reveal. |
| Ergebnisse | Ein echter Beweis **oder** eine echte Widerlegung des genehmigten Ziels. Ein erfolgloser Versuch bleibt ungelöst. |
| Beweisgruppen | Eine Wurzel und begrenzte, tatsächlich verwendete Hilfsbeweise; Wiederverwendung älterer Beweise samt ursprünglicher Zuordnung. |
| Autorschaft | Ein Autor für alle neuen Beweise eines Pakets; dieser ist auch ihr Geldempfänger. |
| Vergütung | Ein Test-NAO je erstmaligem Forschungsabschluss, positiver Zitierpool bei berechtigten Zitaten, exakte ganze Atome. |
| Mitgliedschaft | Einmaligen Teilnahmeanspruch aufzeichnen, aber noch keine neuen Stimmrechte aktivieren. |
| Betrieb | Eigenständige Prozesse und Datenspeicher auf macOS/Linux; feste Peer-Adressen, gemeinsame Genesis, Neustart und Nachholen fehlender Historie. |
| Bedienung | CLI mit lesbaren Meldungen und maschinenlesbarer Ausgabe; keine grafische Oberfläche erforderlich. |

Nicht zur ersten Abnahme gehören öffentliche Registrierung, automatische Mitgliederrotation, periodische Schlüsselvernichtung, Börsenwert oder Einlösung der Testwährung, Überweisungen, Reserveausgaben, gemeinsame Autorschaft, Empfängerdelegation, eigenständige Definitionsveröffentlichung, laufende Protokoll-Upgrades, allgemeine mathematische Äquivalenzerkennung oder ein autonomer Problemlöser für beliebige Forschungsfragen. Die agentengestützte **Auswahl** von Fragen gehört dagegen zum MVP. Bestehende Fähigkeiten zur Notationsexpansion und mathematischen Prüfung werden genutzt.

<a id="checkliste"></a>

## 2. Start und gemeinsamer Zustand

- [ ] **MVP-01 – Reproduzierbarer Start.** Eine gemeinsame Genesis beschreibt die vier Validatoren, Konten, Peer-Zuordnungen, Foundation, Protokollversion, Parameter und zunächst leere Forschungsbibliothek. Unterschiedliche Genesis oder Parameter werden beim Verbindungs-/Protokollstart erkannt. Private Schlüssel stehen nicht in der gemeinsamen Genesis.
- [ ] **MVP-02 – Echte Verteilung.** Vier unabhängige Validatorprozesse laufen mit getrennten Schlüsseln und Datenverzeichnissen auf mindestens zwei Rechnern. Eine Ein-Prozess-Simulation oder vier Ansichten derselben Datenbank reichen zur Abnahme nicht.
- [ ] **MVP-03 – Vollständiger Konsenszustand.** Finalität bindet Fragen, Stimmen, Phasen, Commitments, Offenlegungen, Beweise, Autoren, Abschlüsse, Teilnahmeansprüche, Guthaben und Reserve. Ein zusätzlicher lokaler Status neben einer unveränderten Artefaktkette genügt nicht.
- [ ] **MVP-04 – Datensätze ohne Beweis.** Abstimmungen, Phasenwechsel und andere Steuerungsoperationen können finalisiert werden, auch wenn noch kein neues Forschungsergebnis vorliegt.
- [ ] **MVP-05 – Determinismus.** Dieselbe Genesis und dieselbe finalisierte Historie ergeben auf allen Zielsystemen identische Kennungen und denselben vollständigen Zustandswert. Lokale Uhr, KI-Ausgabe und Empfangsreihenfolge ändern beim Wiederabspielen keine Entscheidung.

## 3. Fragen, Forschungsprofil und Abstimmung

- [ ] **MVP-06 – Frage einreichen.** Ein registrierter Nutzer kann Zweck und `.nao`-Beweispflicht einreichen. Der Compiler zeigt vor der Abstimmung die beiden exakten Ziele sowie Frage- und Familienkennung. Freie Variablen, unbekannte Annahmen, unzulässige Referenzen und überschrittene Grenzen werden verständlich zurückgewiesen.
- [ ] **MVP-07 – Begrenzte Warteschlange.** Finalisierte Quittungen bestimmen ihre Reihenfolge. Pro Familie gibt es höchstens einen wartenden oder aktiven Versuch. Aufnahme, Ablehnung wegen Überlastung und spätere Eröffnung sind unterschiedliche sichtbare Zustände.
- [ ] **MVP-08 – Bekannte Antworten.** Bei tatsächlicher Eröffnung wird gegen beide exakten Ziele geprüft. Ein bereits veröffentlichter unbezahlter Hilfsbeweis führt zu `KNOWN_UNPAID`; ein bezahlter Abschluss bleibt `COMPLETED`. Beide Fälle erzeugen keine neue Belohnung oder Teilnahmeberechtigung.
- [ ] **MVP-09 – Ein aktiver Versuch.** Während Abstimmung, Lösung und ausstehender Abrechnung bleibt die Beweisbibliothek unverändert. Keine Nebenroute darf Beweise, Definitionen oder importierte Zustände auswählen. Der nächste Versuch beginnt erst nach einem finalisierten Abschluss in einem späteren Datensatz.
- [ ] **MVP-10 – Forschungsprofil und echte Agentenprüfung.** Jeder Betreiber kann sein lokales Forschungsprofil bearbeiten. Ein begrenzter Agentenaufruf beurteilt mindestens eine reale Frage anhand dieses Profils und liefert YES/NO mit Begründung. Ein vom Betreiber autorisierter Adapter signiert die Entscheidung; Geheimnisse bleiben lokal. Simulierte Antworten sind nur Testmittel.
- [ ] **MVP-11 – Ausfall der Agentenprüfung.** Fehlende, ungültige oder verspätete Ausgabe erzeugt keine Stimme. Der Betreiber kann rechtzeitig manuell abstimmen; eine bereits finalisierte Stimme wird nicht überschrieben. KI-Text beeinflusst weder Beweisgültigkeit noch das deterministische Wiederabspielen.
- [ ] **MVP-12 – Vollständiges Stimmfenster.** Vier feste Stimmen bilden den Nenner; drei YES genehmigen, zwei YES nicht. Pro Eigentümer zählt die erste gültige Stimme. Das Fenster schließt erst nach seiner Frist, auch bei frühem Quorum.
- [ ] **MVP-13 – Gemeinsame Zeit.** Signierte Zeitberichte, monotone Datensatzzeit und getrennte Phasen bestimmen Fristen. Operationen genau auf einer Frist sind zu spät. Ohne Finalität verändert kein lokaler Timer den kanonischen Status.

## 4. Lösung, Vorrang und Beweisaufnahme

- [ ] **MVP-14 – Dauerhaftes Commitment.** Die CLI speichert signiertes Original, Geheimnis und Commitment vor dem Versand. Die finalisierte Quittung reserviert die spätere Offenlegung. Neustart und wiederholter Versand erzeugen keinen zweiten Anspruch.
- [ ] **MVP-15 – Geschützte Offenlegung.** Offenlegung ist erst nach finalisiertem Commitment-Abschluss zulässig. Kette, Versuch, Autor, Originalhash und Frist müssen passen. Die vollständigen notwendigen Bytes sind auf den bestätigenden Validatoren verfügbar und dauerhaft wiederherstellbar.
- [ ] **MVP-16 – „Survival of the first“.** Unter gültigen rechtzeitigen Offenlegungen gewinnt die früheste berechtigte Commitment-Quittung. Frühere Netzwerkankunft oder schnellere Prüfung begründen keinen Vorrang. Eine fehlende oder ungültige frühere Offenlegung blockiert einen gültigen späteren Kandidaten nicht.
- [ ] **MVP-17 – Wirkliche Mathematikprüfung.** Der vorhandene Checker prüft Original und normalisierte Endfassung samt erforderlichen Abhängigkeiten. Der Schluss entspricht exakt einem genehmigten Ziel. Ein Gegenbeispiel ohne Zertifikat, ein KI-Urteil oder ein Beweis nur von „Q oder nicht Q“ reicht nicht.
- [ ] **MVP-18 – Eindeutige Hilfsbeweise.** Unterschiedliche neue Zertifikate derselben exakten Aussage im selben Paket werden zurückgewiesen; eine Wurzel/Hilfsbeweis-Kollision ebenfalls. Nur byteidentische Knoten mit identischer Zuordnung dürfen zusammengeführt werden.
- [ ] **MVP-19 – Wiederverwendung.** Ein passender älterer Beweis ersetzt einen doppelten Hilfsbeweis nach der festgelegten frühesten zulässigen Aufnahme. Seine Autoren- und Empfängerzuordnung bleibt erhalten. Ein kürzerer Nachbau verdrängt ihn nicht.
- [ ] **MVP-20 – Bereinigung und Quittung.** Nicht mehr verwendete Hilfsbeweise und Zitate entfallen. Der endgültige Graph bleibt azyklisch und vollständig gültig. Eine reproduzierbare Normalisierungsquittung verbindet das signierte Original mit den endgültigen Kennungen und dem konkreten Elternzustand.
- [ ] **MVP-21 – Einmaliger atomarer Abschluss.** Alle neuen Beweise, der Ausgang PROVED/REFUTED, der Familienabschluss, genau ein passiver Teilnahmeanspruch und sämtliche Geldbuchungen werden gemeinsam finalisiert. Ein Fehler veröffentlicht oder bezahlt keinen Teil davon.
- [ ] **MVP-22 – Ablauf und Wiederholung.** Ohne rechtzeitige gültige Offenlegung entsteht `UNRESOLVED`, ohne Geld oder Hilfsveröffentlichung. Ein neuer Versuch braucht neue Genehmigung und neue Kennungen. Rechtzeitig gültige Offenlegungen bleiben bis zur ausstehenden Abrechnung geschützt.

## 5. Zitieren, Testguthaben und Nachlesen

- [ ] **MVP-23 – Echtes späteres Zitieren.** Ein weiterer, anderer Forschungsabschluss lädt einen zuvor veröffentlichten Beweis vom Netzwerk und verwendet ihn nachweisbar. Der ursprüngliche Empfänger erhält einen positiven Zitierbetrag.
- [ ] **MVP-24 – Richtige Zitiergrenze.** Gezählt werden die verschiedenen ersten älteren Beweise entlang der tatsächlich verwendeten Pfade aus der normalisierten Wurzel. Wiederholte Pfade zählen einmal; neue Beweise desselben Datensatzes, entfernte Zitate und Vorfahren hinter dieser Grenze erhalten keinen Anteil.
- [ ] **MVP-25 – Exakte Verteilung.** Bei vorhandenen Zitaten werden 0,60 Test-NAO an den Lösungsautor und insgesamt 0,10 an die berechtigten Beweise gebucht; ohne Zitate erhält der Autor 0,70. Weitere 0,20 gehen zu gleichen Teilen an die vier Validatorenkonten, 0,10 in die Reserve. Restatome folgen [R7](#r7).
- [ ] **MVP-26 – Geldmengenerhaltung.** Bei Startguthaben null gilt nach N bezahlten Abschlüssen: Summe aller Guthaben einschließlich Reserve = N × 1.000.000.000 Atome. Keine Fließkommaarithmetik, Überläufe, doppelte Buchungen oder vom Signaturteilnehmerkreis abhängigen Ausschüttungen.
- [ ] **MVP-27 – Nutzbare Bibliothek.** Nutzer können Frage, Ausgang, Original, normalisierte Beweisgruppe, tatsächliche Schlussformel, Autor, Zitate, Belohnung und Teilnahmeanspruch nachschlagen und exportieren. Ein lokales Prüfkommando prüft heruntergeladene Zertifikate unabhängig; angezeigte Hashes allein gelten nicht als Beweisprüfung.

## 6. Betrieb, Wiederanlauf und Fehlerverhalten

- [ ] **MVP-28 – Belastbare CLI.** Einrichten, Starten, Stoppen, Profilbearbeitung, Einreichen, Abstimmen, Committen, Offenlegen, Statusabfragen, Nachholen, Export und Prüfung funktionieren ohne Datenbank-Handarbeit. Meldungen unterscheiden transportiert, finalisiert, mathematisch gültig und abgerechnet. Kommandoformen werden bei der Implementierung festgelegt.
- [ ] **MVP-29 – Authentifizierung und Wiederholungsschutz.** Aktionen sind an Genesis, Version, Rolle, Autor und Nonce beziehungsweise Versuch gebunden. Fremde Autoren, andere Ketten, veränderte Pakete und alte Versuche werden abgewiesen. Erneutes Senden exakt derselben Aktion liefert dieselbe Quittung, ohne erneute Wirkung.
- [ ] **MVP-30 – Neustart und Nachholen.** Nach Prozessabsturz werden gespeicherte signierte Nachrichten wiederholt, ohne erneut widersprüchlich zu signieren. Ein zurückkehrender Validator lädt und prüft die vollständige Forschungshistorie und erreicht denselben Zustand.
- [ ] **MVP-31 – Fehler bei Speicherung.** Unterbrechungen vor und nach Journal-/Ankerschritten ergeben alten Zustand, vollständigen neuen Zustand oder einen ausdrücklich gestoppten Wiederherstellungsfall. Halbe Beweisgruppen, verlorene bestätigte Offenlegungen und doppelte Belohnungen sind nicht zulässig.
- [ ] **MVP-32 – Ausfälle und Trennung.** Mit drei erreichbaren Validatoren wird Fortschritt demonstriert. Bei einer 2:2-Trennung finalisiert keine Hälfte neue Abschlüsse. Nach Wiederverbindung konvergieren alle vier. Ein Rechnerausfall, der zwei Prozesse betrifft, wird folgerichtig als Quorumverlust behandelt.
- [ ] **MVP-33 – Harte Arbeitsgrenzen.** Warteschlange, Commitments, Paketgrößen, Formelarbeit, Hilfsbeweise, Referenzpfade und Transportpuffer haben deterministische Grenzen. Überlastung führt zu erklärbarer Ablehnung. Bereits reservierte Offenlegungen behalten ihre Kapazität. Die endliche Laufgrenze sperrt neue Versuche rechtzeitig; ihre Datensatzreserve schützt bereits aktive Versuche bis zur Abrechnung.
- [ ] **MVP-34 – Grenzen qualifizieren.** Die vorgeschlagenen Startwerte werden an den tatsächlichen Beispielbeweisen, Zielrechnern und Verzögerungen gemessen. Mindest-/Maximalfälle und erschöpfte Kapazität sind Teil der Abnahme. Diese Planung behauptet keine bereits gemessene Durchsatz- oder Speicherleistung.
- [ ] **MVP-35 – Vollständige Prüfung.** Ein Beobachter ohne Signierschlüssel spielt die finalisierte Historie ab und vergleicht nicht nur Artefakte, sondern auch alle Forschungs- und Geldzustände. Korrupte vollständige Daten oder widersprüchliche geprüfte Finalität führen zu einem sichtbaren Halt.

<a id="abnahme"></a>

## 7. Verbindliches Abnahmeszenario für den vorgeschlagenen Umfang

- [ ] **AB-01 – Start und echte Auswahl.** Vier getrennte Validatoren starten; ein anfangs mittelloser Forschungsteilnehmer reicht Frage A ein. Mindestens ein tatsächlicher Profil-/Agentenaufruf wird nachvollziehbar ausgeführt. Drei gültige YES führen erst am Fensterende zur Genehmigung.
- [ ] **AB-02 – Konkurrenz.** Zwei Autoren committen verschiedene gültige Lösungen. Der spätere Autor legt zuerst offen; der frühere gewinnt bei ebenfalls rechtzeitiger gültiger Offenlegung. In einem separaten Lauf gewinnt der spätere, wenn das frühere Reveal fehlt oder ungültig ist.
- [ ] **AB-03 – Beweisgruppe.** A wird als PROVED abgeschlossen; mindestens ein verwendeter neuer Hilfsbeweis H wird gemeinsam mit der Wurzel veröffentlicht. H erhält keine eigene Anfangsbelohnung und keinen eigenen Teilnahmeanspruch.
- [ ] **AB-04 – Wiederverwendung und Widerlegung.** Ein anderes Forschungskonto als der H-Autor löst eine andere Frage B als REFUTED. Ihr tatsächlich geprüftes Widerlegungszertifikat verwendet H. Ein eingereichtes Duplikat von H wird durch die gespeicherte Fassung ersetzt. H wird von einem anderen Knoten abgerufen, während sein ursprünglicher Anbieter nicht erreichbar ist und das Dreierquorum verfügbar bleibt. Der ursprüngliche H-Autor erhält den positiven Zitierbetrag.
- [ ] **AB-05 – Keine nachträgliche Belohnung.** Eine wartende Frage C, deren exaktes Ziel H bereits beantwortet, endet beim Öffnen als `KNOWN_UNPAID`. Kein neuer NAO und kein neuer Teilnahmeanspruch entstehen.
- [ ] **AB-06 – Negative Pfade.** Nicht genehmigte Frage, falsches Ziel, ungültiges Original, ungültige Endfassung, verspätetes Reveal, doppeltes Paket, fremde Kette, alter Versuch, unzulässige neue Duplikate, ungültige Signatur und Überlastung werden entsprechend den Regeln behandelt. Ein erfolgloser Versuch wird niemals als Widerlegung ausgegeben.
- [ ] **AB-07 – Unterbrechung und unabhängige Kontrolle.** Absturz um Abrechnung, eine ausgefallene Instanz, 2:2-Trennung, Heilung und vollständiger Kaltstart werden geprüft. Alle vier Zustandswerte und die unabhängige Nachprüfung stimmen überein; N bezahlte Familien haben genau N Ausgaben und N passive Ansprüche.

Die mathematischen Beispielzertifikate müssen vor dem Integrationstest mit dem echten Checker nachgewiesen sein. Dass H tatsächlich für das Widerlegungsziel von B verwendet werden kann, ist eine Anforderung an die Fixtures; das reine Regelmodell belegt dies nicht. Die erste Abnahme verwendet das Labprofil und zusätzliche automatisierte Grenzfälle. Ein späterer vollständiger Durchlauf des siebentägigen Forschungsprofils ist eine gesonderte Langzeitqualifikation und kein notwendiges Hindernis für diesen MVP.

<a id="umsetzung"></a>

## 8. Reihenfolge der späteren Umsetzung

| Schritt | Zusammenhängender Arbeitsblock | Fertig, wenn … |
|---|---|---|
| 1 | Profil, Formate und reale Beispielbeweise | Der [Regelentwurf](#regeln) hat ausführbare Kodierungsvektoren und reale Zertifikate für AB-03/04; alle Grenzwerte sind maschinenlesbar festgelegt. |
| 2 | Forschungszustand und atomare lokale Übergänge | Fragen, Phasen, Priorität, Normalisierung und Geldbuchungen erfüllen die lokalen positiven und negativen Abnahmefälle. |
| 3 | Konsens, dauerhafte Speicherung und Nachholen | Der vollständige Zustand wird von realen Validatoren gemeinsam finalisiert und unabhängig wiederabgespielt; Steuerungsdatensätze funktionieren. |
| 4 | CLI, signierter Eingang und Agentenanbindung | Bekannte Nutzer können den gesamten Ablauf ohne manuelle Datenänderungen durchführen. |
| 5 | Mehrrechner-Abnahme und Betriebsanleitung | AB-01 bis AB-07 sowie die angemessenen Repository-Prüfungen bestehen mit nachvollziehbarer Evidenz. |

Die vorhandenen mathematischen Kernbibliotheken, Transport- und Betriebsbausteine werden wiederverwendet. Proposal-/Finalitätsformate, Forschungszustand und deren Wiederabspielen brauchen substanzielle Erweiterungen. Vorhandene Gebührenarithmetik und niedrigste-ID-Kandidatenauswahl dürfen nicht ungeprüft als neue Vergütungs- oder Vorrangregel übernommen werden. Dieser Codeabgleich gehört zum unten beschriebenen vorbereitenden Forschungsstand.

Eine spätere Implementierung nutzt Rust `1.97.1` und die Repository-Prüfungen mit getrennter Build-/Testphase in `test` und `release`. CI, lokale Tests und tatsächliche Mehrrechnerläufe werden getrennt berichtet. Für laufende Validatorprozesse richtet sich der MVP nach den vorhandenen Unix-Betriebspfaden; ein erfolgreicher Windows-Build ist kein Windows-Laufzeitnachweis. Diese Liste erteilt keine Erlaubnis für eine automatische PR-Kette.

<a id="regeln"></a>

## 9. Regelentwurf und konkrete Parameter

Die folgenden Regeln konkretisieren die vorangehenden Anforderungen für das vorgeschlagene MVP-Profil. Die Unterscheidung zwischen Nutzerentscheidungen und R&D-Empfehlungen aus Abschnitt 1 gilt für alle Regeln. Die Vereinfachungen beanspruchen keine faire öffentliche Aufnahme, sichere Machtverteilung oder wirtschaftlich optimale Vergütung.

<a id="r1"></a>

### R1. Ein eigener, unveränderlicher Versuchsrahmen

Das Profil heißt vorläufig `research-mvp-v1` und startet eine eigene Genesis. Es interpretiert weder alte V0-Nachrichten neu noch migriert es bestehende Produktionsguthaben. Vier verschiedene bekannte Eigentümer besitzen jeweils eine feste Stimme. Forschungs- und Konsensquorum sind jeweils strikt größer als zwei Drittel, also drei von vier; fehlende Teilnehmer bleiben im Nenner. Keine Registrierung oder Belohnung ändert diese Gewichte.

Genesis bindet Foundation und Prüferprofil, die vier Validatoren mit Kontenzuordnung, höchstens 16 registrierte Forschungskonten, Transportzuordnungen, Zeitprofil, Grenzen und Belohnungsregeln. Startguthaben und Reserve sind null. Forschungskonten benötigen kein Guthaben für Frage, Stimme, Commitment oder Offenlegung. Kontenschlüssel und Konsens-/Transportschlüssel werden nach Rolle getrennt behandelt; ein mehrfach verwendeter Betreiber erhält keine zusätzliche Stimme. Schlüsselrotation und Änderungen an Genesis oder Parametern während eines Laufs sind nicht Teil des MVP.

Eine neue Test-Genesis ist ein neuer Versuchslauf mit eigener Kennung. Sie wird ausdrücklich als solcher angezeigt; sie repariert oder überschreibt keine alte Historie. Bestehende Historien und Schlüsselstände bleiben nachvollziehbar. Normale Neustarts verwenden dieselbe Genesis und denselben dauerhaften Zustand.

<a id="r2"></a>

### R2. Eine aktive Frage schützt genehmigte Verpflichtungen

Eine begrenzte FIFO-Warteschlange ordnet Fragen nach ihrer finalisierten Quittung `(Höhe, Operationsindex)`. Jede Familie hat höchstens einen wartenden oder aktiven Versuch. Eine Ablehnung vor finalisierter Aufnahme gibt keinen Warteschlangenplatz. Die Wartefrist ist die zertifizierte Zeit des Aufnahmedatensatzes plus die im Profil fixierte Warteschlangendauer. Bei Datensatzzeit größer oder gleich dieser Frist verfällt der Eintrag vor einer möglichen Eröffnung. Erneute Zustellung verlängert nichts; nach Verfall erfordert erneutes Einreichen eine neue Aktion und erhält eine neue Position.

Global ist genau ein Versuch aktiv, vom Öffnen des Stimmfensters bis zum finalisierten Abschluss oder endgültig ungelösten Ablauf. Dies umfasst ausstehende Abrechnung nach einer rechtzeitigen Offenlegung. Nur die Abrechnung dieses Versuchs veröffentlicht neue Beweise. Eigenständige Beweis-/Definitionsaufnahme, Bibliotheksimporte und andere Ausgabepfade sind ausgeschlossen. Steuerungsdatensätze dürfen währenddessen weiterlaufen.

Die nächste Frage wird nur geöffnet, wenn bereits der **Elternzustand** keinen aktiven Versuch enthält und die vollständige Versuchsreservierung verfügbar ist. Der Supervisor veranlasst diese Systemoperation automatisch; der Proposer kann keine beliebige spätere Frage wählen. Die höchstens 32 Einträge werden in Quittungsreihenfolge geprüft: verfallene und bekannte Fragen erhalten ihren Status, höchstens die erste verbleibende zulässige Frage wird geöffnet. Ihre formalen Ziele werden erneut gegen die ausgewählte Bibliothek geprüft. Existiert ein gültiger ausgewählter Beweis eines der beiden exakten Ziele, ist keine bezahlte Eröffnung zulässig:

- Bereits bezahlte Familien bleiben `COMPLETED`.
- Ein bekannter, bislang nicht gesondert bezahlter Zielbeweis erzeugt `KNOWN_UNPAID`, ohne nachträgliches Geld und ohne Teilnahmeanspruch. Die tatsächlich gespeicherte Beweisherkunft wird angezeigt.

Beide Zustände verhindern eine spätere bezahlte Wiedereröffnung dieser Familie. Die Prüfung betrifft die exakten normalisierten Ziele; sie behauptet keine Erkennung jeder logisch gleichwertigen Aussage. Ein Hilfsbeweis kann weiterhin durch Verwendung in einem **anderen** neuen Abschluss Zitiervergütung verdienen.

Beim Öffnen wird die gesamte zu diesem Zeitpunkt ausgewählte Bibliothek als erlaubter Referenzkontext fixiert. Während des Versuchs bleibt ihre Beweismenge unverändert. So kann keine andere Veröffentlichung eine schon genehmigte Aufgabe nachträglich „bereits bekannt“ machen. Diese Serialisierung kostet Durchsatz, beseitigt aber im MVP den sonst offenen Konflikt zwischen unbezahltem Hilfsbeweis, späterer Frage und bereits geschützter Belohnungschance.

<a id="r3"></a>

### R3. Ziele und Identitäten bleiben getrennt

Der vorhandene Foundation-Compiler expandiert die erlaubte Notation und normalisiert Variablen. Eine Frage enthält eine geschlossene Formel Q; nach Expansion werden ausschließlich führende Negationen entfernt. Der verbleibende Kern R und die Negationsparität bestimmen die exakten Ziele R und ¬R sowie deren Darstellung als PROVED oder REFUTED. Ein Zeitablauf bedeutet niemals REFUTED.

`StatementId`, `ProofId`, `DerivationId` und typisierte `ArtifactId` behalten ihre vorhandene mathematische Bedeutung. `ResolutionId` bindet Foundation und kanonischen Kern R. Entgegengesetzte Formulierungen und führende Doppelnegationen öffnen keinen zweiten bezahlten Familienabschluss. Titel, Empfänger oder Softwarelabels setzen die Familienhistorie nicht zurück.

Ein eingereichter Vorschlag bindet Zweck, formale Quelle und Autorenkennung. Beim tatsächlichen Öffnen bindet `QuestionId` zusätzlich beide exakten Ziele, Orientierung, Foundation/Prüfer, Bibliothekswurzel und sämtliche geltenden Grenzen/Richtlinien. Die Versuchsnummer einer Familie steigt bei jeder tatsächlichen neuen Eröffnung. Keine vom Nutzer frei gewählte Nummer erzeugt einen neuen Versuch.

Das bislang unbestimmte Commitment-„round“ wird für diesen MVP durch `SolutionRoundId` ersetzt:

`H(rollenspezifische Domäne, GenesisId, QuestionId, Versuchsnummer, ApprovalRecordId)`.

Damit bezeichnet es die Lösungsrunde einer konkreten Genehmigung. Die Kennung wird erst beim späteren COMMIT-Start aus der dann bereits finalisierten Genehmigungsdatensatzkennung erzeugt und installiert. Der Genehmigungsdatensatz muss somit nicht seine eigene Kennung als Teil seines Zustands hashen. Konsensrunde, Höhe und Neustart sind andere Begriffe. Protokolländerungszyklen und Kompromittierungszyklen entfallen im festen MVP-Profil, weil es keine laufenden Upgrades oder dynamische Signierperioden gibt.

<a id="r4"></a>

### R4. Vollständige Phasen mit eindeutigen Fristgrenzen

Jeder Datensatz enthält Zeitberichte von mindestens drei verschiedenen festen Validatoren. Berichte signieren Genesis, Elternkennung, Höhe, TIME-Rolle und ganzzahlige UTC-Sekunden. Datensatzzeit ist das Maximum aus Elternzeit und unterem Median der enthaltenen Berichte. Bei vier Berichten ist dies der zweite aufsteigend sortierte Wert, bei drei der zweite. Zertifikate werden nach Validatorenkennung kanonisch geordnet; falscher Kontext oder doppelte Signierer machen sie ungültig. Betreiber halten ihre Uhren synchron; die unten genannte Fehlergrenze ist eine Betriebsannahme, kein kryptografischer Beweis der Uhrzeit.

Fällige Schließungen werden vor Nutzeroperationen ausgewertet. Stimmen, Commitments und Reveals dürfen nur zur noch offenen Phase des Elternzustands gehören. Das Einreihen weiterer Fragen ist phasenneutral und bleibt innerhalb der freien Kapazität möglich. Daher kann keine phasengebundene Operation in derselben Höhe ihre eigene Genehmigung oder den Beginn ihrer Offenlegungsphase verwenden. Jede Start-/Schließungsentscheidung muss finalisiert sein, bevor der nächste Datensatz darauf aufbaut.

| Elternphase | Deterministische Folge |
|---|---|
| Kein aktiver Versuch | Bei ausreichender Abschlusskapazität wird im nächsten Datensatz die FIFO-Warteschlange gemäß R2 verarbeitet und die erste verbleibende zulässige Frage geöffnet; `VOTING`, Frist = Datensatzzeit + Stimmfenster. Bei ausgeschöpfter Eröffnungskapazität gilt stattdessen der verpflichtende Laufabschluss aus R10. |
| `VOTING`, Zeit < Frist | Erste gültige YES/NO-Stimme je Eigentümer aufnehmen. Ein frühes Quorum schließt nicht. |
| `VOTING`, Zeit ≥ Frist | Drei oder vier YES → `APPROVED_WAIT`; sonst `NOT_APPROVED` und Freigabe des aktiven Platzes. Keine Stimme dieser Höhe zählt nachträglich. |
| `APPROVED_WAIT` | Nächster Datensatz startet `COMMIT`; dessen Zeit + Commitmentdauer bildet die neue Frist. Commitments erst in späteren Datensätzen. |
| `COMMIT`, Zeit < Frist | Höchstens ein Commitment je Forschungskonto; Reihenfolge nach finalisierter Quittung. |
| `COMMIT`, Zeit ≥ Frist | `COMMIT_CLOSED_WAIT`; die Liste der Commitments ist geschlossen. |
| `COMMIT_CLOSED_WAIT` | Nächster Datensatz startet `REVEAL`; dessen Zeit + Revealdauer bildet die neue Frist. Reveals erst in späteren Datensätzen. |
| `REVEAL`, Zeit < Frist | Vollständige passende und gültige Offenlegungen aufnehmen. |
| `REVEAL`, Zeit ≥ Frist | `SETTLEMENT_PENDING`; keine weiteren Offenlegungen, keine Freigabe des aktiven Platzes. |
| `SETTLEMENT_PENDING` | Nächster gültiger Datensatz rechnet den ersten berechtigten Gewinner ab oder erzeugt bei keiner gültigen Offenlegung `UNRESOLVED`. Erst danach ist der Platz frei. |

Eine Offenlegung zählt zeitlich nur, wenn die **zertifizierte Zeit ihres finalisierten Aufnahmedatensatzes strikt vor** der Revealfrist liegt. Der reale Zeitpunkt, an dem dieser Datensatz abschließend finalisiert wird, ist kein zusätzliches Replay-Kriterium. Netzwerkannahme oder lokale Prüfung kurz vor der Frist genügen ebenfalls nicht. Fehlende Bytes werden nicht als erfolgreiche Offenlegung eingetragen. Ein bereits finalisiertes gültiges Reveal darf nicht verfallen, nur weil seine spätere Abrechnung auf Quorum oder Wiederanlauf wartet.

Ein Halt finalisiert keine lokalen Zeitereignisse. Bei Wiederaufnahme kann ein bereits laufendes Fenster abgelaufen sein. Das folgende Fenster beginnt dagegen erst mit seinem eigenen finalisierten Startdatensatz und erhält seine volle nominelle Dauer. Beibehaltene Konsensvorschläge behalten ihr ursprüngliches Zeitzertifikat; Replay verwendet keine aktuelle lokale Uhr.

<a id="r5"></a>

### R5. Authentifizierung, Commitment und Vorrang

Ein MVP-Konto besitzt einen in Genesis registrierten öffentlichen Schlüssel. Alle neuen Beweise einer Einreichung gehören dem signierenden Autor; ihr Geldempfänger ist dasselbe Konto. Gemeinsame Autorschaft, fremde neue Autorenangaben und abweichende Empfänger werden zurückgewiesen. Bereits vorhandene referenzierte Beweise behalten ihre gespeicherten Kontenzuordnungen.

Das kanonische Originalpaket enthält Wurzel, Hilfszertifikate, Abhängigkeitskanten und die eindeutige neue Autorschaft. Sein Hash bindet unveränderte Bytes. Ein Commitment bindet Genesis, Version, `SolutionRoundId`, Autor, Richtlinie, Originalhash und 32 kryptografisch zufällige geheime Bytes. Das Konto signiert die Commitmentoperation. Das Reveal liefert Geheimnis und vollständiges signiertes Original mit passendem Kontext. Je Commitment darf höchstens eine gültige Offenlegung finalisiert werden; ein zweites Reveal mit neuer Nonce wird zurückgewiesen. Identische Wiederzustellung liefert nur die vorhandene Quittung. Vor Veröffentlichung speichert die CLI das Geheimnis und die Originalbytes dauerhaft und lokal; sie kann dieselbe Aktion nach einem Neustart erneut senden.

Jede Nutzeraktion hat eine vom Kontoinhaber monoton verwendete Nonce und eine Inhaltskennung. Ein noch nie angewandter Noncewert muss genau dem nächsten erwarteten Wert entsprechen. Ungültige Aktionen verbrauchen keine Nonce. Identische bereits finalisierte Aktionen liefern die bestehende Quittung; anderer Inhalt unter verbrauchter Nonce wird zurückgewiesen. Offline vorbereitete Folgeaktionen warten auf ihre Vorgänger. Pro Eigentümer/Votingversuch und pro Autor/Lösungsrunde verhindern zusätzliche Fachregeln zweite Stimmen oder Commitments.

Nach finalisiertem Revealabschluss gewinnt unter gültigen rechtzeitigen Offenlegungen das kleinste Commitment-Koordinatenpaar `(Aufnahmehöhe, Operationsindex)`. Dessen Inhalt wird durch die Quittung gebunden. Der erste Entdecker außerhalb des Netzwerks ist damit nicht bewiesen; der Rang ist ein protokollierter Einreichungsvorrang. Fehlendes oder ungültiges Reveal überspringt diesen Kandidaten, nicht die Prüfung anderer Autoren. PROVED und REFUTED konkurrieren um denselben einmaligen Abschluss.

<a id="r6"></a>

### R6. „Survival of the first“ in der Bibliothek

Ein bereits ausgewählter Beweis derselben exakten kanonischen Aussage wird wiederverwendet, sofern Foundation, Annahmen, genehmigter Kontext und Ressourcenregeln passen. Der Abgleich verwendet `StatementId` **und** exakte Schlussformelbytes; `ResolutionId` oder beliebige mathematische Äquivalenz reichen nicht. Unter mehreren zulässigen Elternbeweisen gilt das Minimum `(Aufnahmehöhe, Operationsindex, ProofId in Byte-Reihenfolge)`. Die Bibliothek speichert diese Erstzuordnung dauerhaft. Ein späterer kürzerer Beweis verdrängt sie nicht.

Das frische MVP verhindert neue Mehrfachauswahlen derselben exakten Aussage bereits bei der Aufnahme. Alte V0-Historien mit anderen Regeln werden nicht stillschweigend importiert. Für mehrere Beweise verschiedener Aussagen derselben atomaren Veröffentlichung stellt die ProofId das reproduzierbare letzte Sortierkriterium dar; daraus entsteht kein Vorrang verschiedener Autoren derselben Aussage.

Innerhalb eines Originalpakets gilt nach Zusammenführen exakt byteidentischer Zertifikatknoten mit identischer Zuordnung: **Zwei verschiedene neue Zertifikate derselben exakten Aussage machen das Paket ungültig.** Das gilt auch für eine Kollision zwischen Wurzel und Hilfsbeweis. Damit muss kein künstlicher zeitlicher Erstautor unter gleichzeitig eingereichten neuen Duplikaten erfunden werden.

Jedes Originalzertifikat muss gültig sein, einschließlich später entfernter Teile. Nach zulässiger Ersetzung neuer doppelter Hilfsbeweise durch Elternbeweise werden von der Wurzel nicht mehr erreichte Teile entfernt, der Graph topologisch kanonisiert und betroffene Kennungen neu berechnet. Die Endfassung samt vollständiger benötigter Abhängigkeiten wird erneut geprüft. Ältere Beweise werden nicht rekursiv umgeschrieben; ein neuer Helfer kann keinen anderen neuen Helfer als „älteren Ersatz“ bestimmen. Beide Grenzen und die abschließende Azyklizitätsprüfung verhindern zirkuläre Ersetzung.

Die Normalisierungsquittung enthält in festgelegter Reihenfolge: Version, Genesis, Lösungsrunde, Commitment-Koordinate/-Kennung, Originalhash, aktuellen Elternzustandswert, Richtlinienkennung, sortierte Ersetzungsabbildung, finales Paket samt Kennungen und gespeicherte Zuordnungen. Sie wird durch den finalisierten Datensatz gebunden. Originalsignaturen bleiben auf den Originalbytes; es wird keine Autorensignatur auf umgeschriebene Bytes behauptet.

Auch bei unveränderter Beweismenge können Steuerungsdatensätze den Abrechnungselternzustand ändern. Eine alte Normalisierungsquittung darf deshalb nicht einfach wiederverwendet werden: Sie wird gegen den exakten neuen Elternzustand reproduziert. Commitmentrang und genehmigte Bedingungen bleiben erhalten.

<a id="r7"></a>

### R7. Zitierpool und exakte Geldbuchungen

Ein bezahlter Abschluss erzeugt genau `1.000.000.000` Atome = 1 **Test-NAO**. 200.000.000 Betriebsatome gehen zu je 50.000.000 an jedes der vier festen Validatorenkonten, unabhängig davon, welche drei oder vier tatsächlich zertifizieren. 100.000.000 gehen in die Reserve. Die übrigen 700.000.000 bilden die Forschungszuteilung.

Die berechtigte Zitiermenge wird aus dem **endgültigen** Graphen ermittelt: Von der Wurzel durch neue Hilfsbeweise gehen; auf jedem Pfad am ersten im versiegelten Elternzustand ausgewählten Beweis anhalten. Jeder verschiedene ProofId zählt einmal. Benötigte ältere Vorfahren werden weiterhin zur Gültigkeitsprüfung geladen, erhalten hinter dieser Zahlungsgrenze aber keinen automatischen Anteil. In diesem Datensatz neu veröffentlichte Beweise verdienen in diesem Datensatz keine Zitiervergütung. Entfernte Verweise zählen nicht. Selbstzitate sind zulässig.

Für n berechtigte Beweise gilt:

- n = 0: kein Zitierpool; 700.000.000 Atome an den Lösungsautor.
- n > 0: 600.000.000 an den Lösungsautor und P = 100.000.000 an die berechtigten älteren Beweise.
- Berechtigte ProofIds aufsteigend nach Rohbytes sortieren. `q = P div n`, `r = P mod n`. Die ersten r IDs erhalten q + 1, die übrigen q. Erst danach Beträge gleicher gespeicherter Empfänger addieren.

Bei drei IDs ergibt dies 33.333.334 / 33.333.333 / 33.333.333 Zitieratome. Doppelte Verweise vervielfachen nichts. Es gibt keinen verbrannten Rest und keinen zusätzlichen Pool je Hilfsbeweis. Mehrere verschiedene berechtigte Beweise desselben Autors dürfen mehrere Anteile erzeugen; der MVP behauptet keine Abwehr künstlicher Zitierketten. 0,10 NAO ist ein einfacher positiver **Testparameter**, keine empirisch ermittelte faire Forschungsbewertung.

Kontoguthaben, Reserve und Summe werden als ganze nichtnegative Atome geführt. Für das MVP werden explizit begrenzte, geprüft gerechnete u128-Werte empfohlen; Überlauf verwirft den ganzen Kandidaten. Dies begrenzt die im Gesamtentwurf vorgesehenen wachsenden natürlichen Geldwerte, ohne Fließkommarundung oder Wraparound einzuführen. Jede Abrechnung bewahrt `Guthaben + Reserve = 1.000.000.000 × Anzahl bezahlter Familien`. Der Testtoken ist nicht einlösbar; Transfers und Reserveausgaben fehlen bewusst.

Der Gewinnerautor erhält genau einen passiven, nicht übertragbaren Teilnahmeanspruch mit ursprünglicher Abschlussnummer. Helpers, Zitate, Guthaben und erneute Zustellung erzeugen keine zusätzlichen Ansprüche oder aktiven Stimmen.

<a id="r8"></a>

### R8. Neue Datensätze und eindeutige Kodierung

Das heutige `ConsensusValueV0`/`ArtifactBlock`-Modell bestätigt ein einzelnes Artefakt. Der MVP benötigt ein eigenes versioniertes Forschungsdatensatzformat, das auch null oder mehrere neue Artefakte sowie Forschungsoperationen binden kann. Kein Forschungsergebnis darf nur in einer unbestätigten Neben-Datenbank stehen. Die bestehenden Konsens-, Transport- und Speicherpfade müssen dieses Format tatsächlich prüfen, signieren, übertragen, auswählen und wiederabspielen.

Der verbindliche Datensatzinhalt umfasst Genesis/Profil, Höhe, Elternkennung, vorherigen vollständigen Zustandswert, Zeitzertifikat, geordnete Nutzeroperationen, deterministisch abgeleitete Phasen-/Abrechnungsergebnisse und den vollständigen Folgezustandswert. Signaturbeweise werden vom bezeichneten Inhalt getrennt; die Wahl einer ausreichenden Signaturteilmenge darf dessen Identität und Auszahlung nicht verändern.

Für die technische Umsetzung wird der vorhandene strikte Binärkodierungsstil verwendet: rollenspezifische Hash-/Signaturdomänen, eindeutige Längen, feste Feldreihenfolge, kanonische Ganzzahlen, explizite Tags und Zurückweisung unbekannter Varianten, doppelter Einträge und restlicher Bytes. Mengen werden nach ihren definierten Rohbyte-Kennungen sortiert, wirkliche Operationsfolgen behalten ihre gebundene Reihenfolge. JSON dient der CLI-Ausgabe, nicht ungeprüft der Konsensidentität. Vollständige Tags, Decoder und Golden Vectors gehören zu Umsetzungsschritt 1; die hier festgelegten Bedeutungen dürfen dabei nicht neu interpretiert werden.

Die mathematischen Artefaktkennungen bleiben wiederverwendbar. Ein vollständiger Forschungszustandswert deckt zusätzlich Fragen, Versuche, Phasen, Quittungen, Nonces, Erstzuordnungen, bekannte/unbezahlte und bezahlte Familien, Teilnahmeansprüche, Konten, Geldreserve und Warteschlangen ab. Restliche Datensatz-/Bytebudgets und die noch gebundene aktive Abschlusskapazität sind gesonderte, ebenfalls kanonisch gespeicherte und wiederabgespielte Zustandsfelder; sie sind nicht die Geldreserve. Ein Artefakt-Merklebaum allein ist dafür unzureichend.

<a id="r9"></a>

### R9. Dauerhaftigkeit und Grenzen der vereinfachten Sicherheit

Kandidaten werden vollständig auf temporärem Zustand ausgewertet. Erst ein gültiger finalisierter Datensatz darf sämtliche Folgen gemeinsam sichtbar machen. Das autoritative Journal enthält alle zur Wiederherstellung erforderlichen finalisierten Eingaben und Beweisbytes. Separate Suchindizes und Ansichten sind daraus reproduzierbare Ableitungen, keine weitere Wahrheitsquelle. Die bestehenden Anker-/Journalprinzipien werden auf den neuen vollständigen Zustand erweitert.

Ein bestätigtes Reveal benötigt dauerhafte verfügbare Bytes, nicht nur einen Hash oder eine Transportquittung. Ein Absturz nach dauerhafter Speicherung und vor Antwort wird durch Identität und Replay aufgelöst. Eine unklare Schreibsituation stoppt den betroffenen Pfad bis zur überprüften Wiederherstellung. Falsch dekodierte vollständige Journalrahmen, Ankerabweichung oder verifizierte widersprüchliche Finalität werden nicht automatisch „repariert“.

Die vier festen Schlüssel erfordern in diesem MVP keine periodische Vernichtung. Gespeicherte Signierabsichten müssen dennoch widersprüchliches Neusignieren nach Neustart verhindern. Historische Schlüsselkompromittierung, gleichzeitiges bösartiges Zurückrollen aller Anker und ein öffentliches Angreifermodell bleiben außerhalb des zugesagten MVP-Schutzes. Ein verlorenes Quorum wird nicht durch einen kleineren Nenner oder ungeprüfte neue Validatoren ersetzt.

<a id="r10"></a>

### R10. Konkrete Startwerte und ihre Qualifikation

Die folgenden Werte sind vollständig festgelegte **Startvorschläge**, noch keine gemessenen Leistungsgrenzen. Sie werden in Genesis gebunden. Eine andere Wahl vor dem ersten Start erzeugt ein anderes Profil; ein laufender Versuch ändert sie nicht. Eine spätere Änderung im MVP erfolgt nur über einen ausdrücklich getrennten neuen Testlauf.

| Parameter | Vorschlag |
|---|---|
| Aktive Versuche | 1, einschließlich ausstehender Abrechnung |
| Wartende Fragen | 32 insgesamt; höchstens 1 je ResolutionId |
| Registrierte Forschungskonten / Commitments | Höchstens 16 Konten, höchstens 1 Commitment je Konto und Versuch |
| Formale Frage | 16 KiB Quelle; beide expandierten Ziele jeweils höchstens 1.024 Knoten und Tiefe 32 |
| Beweisgruppe | Höchstens 16 neue Hilfsbeweise plus Wurzel; Original und Endfassung jeweils höchstens 256 KiB |
| Einzelzertifikat | Höchstens 64 KiB, 4.096 Schritte; zusätzlich alle strengeren bestehenden Checkergrenzen |
| Ältere Abhängigkeiten | Höchstens 64 verschiedene benötigte Beweise in der vollständigen Prüfclosure, insgesamt höchstens 2 MiB; Tiefe höchstens 32 |
| Zitierempfängerbasis | Höchstens 64 verschiedene berechtigte ProofIds, durch Closuregrenze begrenzt |
| Nutzeroperationen / Datensatz | Höchstens 16; höchstens eine Abrechnungsgruppe; Originalbeweise werden nicht mehrfach als Kopien in dieselbe Nachricht eingebettet |
| Vollständiger Forschungsdatensatz | Höchstens 1 MiB einschließlich benötigter neuer Pakete, Operationen und Nachweise; Transporteinheiten erhalten dazu passende, vor Allokation geprüfte Grenzen |
| Prüfarbeit | Vorhandene Formelarbeitsgrenze je Checkeraufruf bleibt erhalten; Anzahl und Eingangsbytes sämtlicher Aufrufe, DAG-Traversierung und Normalisierung müssen zusätzlich vorab begrenzt sein |
| Laufendes Archiv | MVP-Lauf höchstens 8.192 Datensätze; konservative vollständige Archiv-/Offenlegungsreservierung aus diesen Obergrenzen vor Start prüfen, kein automatisches Löschen bestätigter Historie |
| Abschlussreserve | Vor Eröffnung 64 Datensatzplätze einschließlich Eröffnung samt maximalen Rahmenbytes reservieren; zusätzlich ist ab Genesis 1 Platz innerhalb der Laufgrenze ausschließlich für den endgültigen Laufabschluss reserviert |
| Uhrenfehler | Betreiberziel höchstens 2 Sekunden; bei erkennbarer Überschreitung keine neuen Zeitberichte, Statusfehler anzeigen |
| Forschungsprofil | Abstimmung 604.800 s, Commitment 86.400 s, Reveal 86.400 s, Warteschlangenfrist 2.592.000 s |
| Labprofil | Abstimmung 300 s, Commitment 120 s, Reveal 120 s, Warteschlangenfrist 1.800 s |
| Agentenprüfung | Je Frage/Versuch höchstens 2 Inferenzversuche, 60 s je Aufruf und 4 begrenzte Werkzeugabrufe; Fehler → keine automatische Stimme |

Die Reservierung berücksichtigt alle bis zu 16 möglichen Offenlegungen, Original- und Endprüfung sowie deren vollständige ältere Prüfclosure. Bei Aufnahme eines Commitments wird der zugesagte Platz tatsächlich gebunden. Ein kleines Endergebnis entschuldigt kein zu großes Original. Ein Datensatz, der zu viele ansonsten gültige Operationen bündelt, ist ungültig; die Operationen können vor Fristablauf in passende spätere Datensätze aufgenommen werden.

Der Supervisor arbeitet ereignis- und fristgesteuert: neue gültige Aktionen, fällige Phasen und ausstehende Abrechnung lösen Vorschläge aus. Er erzeugt keine periodischen leeren Datensätze nur zur Erhöhung der Höhe. Konsenswiederholungen einer unentschiedenen Höhe verbrauchen keinen neuen finalisierten Datensatzplatz. Bereits fällige Systemoperationen haben Vorrang; ein Vorschlag darf eine erforderliche Schließung oder Abrechnung nicht mit beliebigen Leeroperationen umgehen.

Selbst bei nur einer dieser Fachaktionen pro Datensatz reichen 43 Plätze für Eröffnung, vier Stimmen, Stimmabschluss, COMMIT-Start, 16 Commitments, Commitmentabschluss, REVEAL-Start, 16 Reveals, Revealabschluss und Abrechnung. Die Reserve von 64 Plätzen bietet darüber hinaus Raum für begrenzte Systemarbeit; ihre tatsächliche Verwendung wird mit dem Profil geprüft. Für einen finalisierten Datensatz wird höchstens ein reservierter Platz verbraucht, wenn er solche noch ausstehenden aktiven Fachaktionen oder einen erforderlichen Phasenübergang ausführt. Unproduktive Leeroperationen, reine Wiederholungen, zusätzliche Zeit-Ticks sowie fremde Warteschlangen- und Ablaufarbeit dürfen die verbleibende Reserve nicht verbrauchen. Warteschlangenabläufe werden vor dem nächsten zulässigen Datensatz mitgeführt; gesonderte Ablaufdatensätze benötigen unreservierte Kapazität.

Ist im inaktiven Elternzustand weniger als die Eröffnungsreserve frei, führt der nächste Datensatz zwingend den endgültigen Laufabschluss aus. Nach fälligen Warteschlangenabläufen werden die übrigen wartenden Fragen mit `CAPACITY_END` geschlossen; dieser Datensatz enthält keine neuen Nutzeraktionen. Der seit Genesis gesondert reservierte Endplatz darf niemals für gewöhnliche Arbeit oder einen Versuch verwendet werden. Der Endzustand weist weitere Einreichungen und Datensätze zurück und bleibt lesbar. Ein aktiver Versuch behält hingegen seine Abschlussplätze bis zum gültigen Ergebnis oder endgültig ungelösten Ablauf, auch nach einem vorübergehenden Quorumverlust. Kapazitätsende beendet somit keinen bereits geschützten aktiven Versuch.

Für die spätere Qualifikation müssen Datenhaltung, endgültige Wire-Overheads, aktive Puffer und Testrechner zusammenpassen. Vor Start wird aus Profil und Archivgrenze die erforderliche Speichermenge konservativ berechnet; sinkender freier Speicher führt zu einer sichtbaren lokalen Betriebsstörung statt verlorenen bestätigten Daten. Er verändert nicht die deterministische Gültigkeit eines Datensatzes. Ob ein Datensatz reservierte Kapazität verbraucht, folgt ausschließlich aus seinen gültigen Fachoperationen und Pflichtübergängen sowie dem kanonischen Restbudget, nicht aus einer Behauptung des Proposers. Die Archivrahmen allein sind mit 8.192 × 1 MiB auf 8 GiB begrenzt; Indizes, Signierjournale, Protokollnachweise und Sicherheitsreserve kommen hinzu. Das ist ein endlicher MVP-Lauf, kein unbegrenzt laufendes Produktionsnetz. Die Laufbegrenzung darf keine bereits geschützte Abrechnung abschneiden.

Die erste MVP-Abnahme verwendet das Labprofil; seine verkürzte Abstimmung ist eine ausdrückliche Abweichung vom siebentägigen Whitepaper-Fenster. Automatisierte Modelltests dürfen eine weitere klar bezeichnete Kurzzeitkonfiguration verwenden. Ein erfolgreicher Kurzlauf belegt die Phasenlogik, aber nicht, dass das siebentägige Forschungsprofil vollständig durchgelaufen ist. Ein solcher Langzeittest bleibt eine spätere gesonderte Qualifikation, keine Voraussetzung für die erste MVP-Abnahme.

<a id="r11"></a>

### R11. Quellen und verbleibende Umsetzungsarbeit

Im vorbereitenden Forschungsstand wurden die Regeln mit dem Whitepaper, tatsächlichen Codepfaden und drei getrennten Fachprüfungen abgeglichen. Die statische Codeprüfung benannte wiederverwendbare Grundlagen und fehlende Integration. Isolierte Regelmodelle untersuchten Verteilung, Duplikat-/Elternauswahl und Commitmentpriorität; ein Lebenszyklusmodell untersuchte Fristgrenzen, serielle Eröffnung, unbezahlte bekannte Hilfsbeweise und atomare Modellzustände. Diese Einzelberichte und Skripte sind nicht Bestandteil dieses Startpakets.

Die Modelle verwenden abstrakte Identitäts- und Gültigkeitswerte. Sie sind keine echten mathematischen Prüfungen, keine Signaturtests, keine Absturztests auf Datenträgern und kein laufendes Netzwerk. Insbesondere wurden im Rahmen dieser Planung keine neue mathematische Beweisnormalisierung im Rust-Checker, kein neuer Netzwerkzustand und keine Crash-Persistenz implementiert oder getestet. Die entsprechenden Abnahmekästchen bleiben offen. Die Datensatzreservierung aus R10 muss später real implementiert und qualifiziert werden; ihre vollständige Funktionsfähigkeit wird durch die isolierten Modelle nicht belegt.

Die Trennung einer deterministischen Zustandsmaschine von Konsens sowie das Verbot externer Seiteneffekte bei Replay wird auch in den offiziellen [CometBFT-Anwendungsanforderungen](https://raw.githubusercontent.com/cometbft/cometbft/main/spec/abci/abci%2B%2B_app_requirements.md) beschrieben. Dies ist ein Architekturvergleich, keine Empfehlung zum Austausch des vorhandenen Konsenssystems. [RFC 8949, Abschnitt 4.2](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2) zeigt, weshalb deterministische Serialisierung explizite Regeln benötigt; CBOR wird hier nicht als zusätzliche Abhängigkeit gewählt. Die [SQLite-Dokumentation zur atomaren Speicherung](https://www.sqlite.org/atomiccommit.html) erläutert Alles-oder-nichts und die nötigen Datenträgerannahmen; ein bloßes Vertrauen in Nutzer ersetzt diese Eigenschaften nicht. Eine SQLite-Migration wird damit ebenfalls nicht festgelegt.

Offen bleiben hier **Implementierungs- und Qualifikationsarbeiten**: genaue Binär-Tags und Golden Vectors, Anpassung der Konsens-/Nachweisformate, tatsächliche real geprüfte Beispielfixtures, Messung der Arbeitsgrenzen, konkrete Agentenanbindung sowie die vollständigen Persistenz- und Mehrrechnerprüfungen. Die zentralen Produktentscheidungen für Priorität, bekannte Hilfsbeweise, Vergütung, Phasen und MVP-Grenzen haben dagegen jeweils einen konkreten Vorschlag. Werden dessen bewusste Einschränkungen aufgehoben, müssen die dadurch wieder auftretenden Protokollfragen neu bearbeitet werden.

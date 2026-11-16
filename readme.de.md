# IntuneComplianceMaintainer

Hält die Minimum-OS-Version-Anforderungen in Microsoft Intune Compliance- und App-Protection-Richtlinien für Apple-Plattformen (iOS, iPadOS, macOS) aktuell und berichtet über bzw. informiert bei nicht-konformen Geräten.

Gepflegt von FP-IT-Solutions GmbH. Ursprünglich basierend auf [SkipToTheEndpoint/IntuneComplianceMaintainer](https://github.com/SkipToTheEndpoint/IntuneComplianceMaintainer); grundlegend überarbeitet (siehe [Änderungsprotokoll](#änderungsprotokoll-gegenüber-dem-original) unten) — Android- und Windows-Support entfernt, Unterstützung für das Warn-Feld ergänzt, geräteweise Compliance-Berichterstattung und individuelle E-Mail-Benachrichtigung hinzugefügt, getrennte Cadence-Zeiten für Warn vs. Block, sowie mehrere Stabilitäts-Fixes.

## Überblick

Das Skript ist in drei unabhängig voneinander schaltbare Blöcke gegliedert:

1. **Policy Maintenance** (`$RunPolicyMaintenance`) — liest die aktuell konfigurierte Minimum-OS-Version aus euren Compliance- und App-Protection-Richtlinien, prüft die neueste öffentlich verfügbare OS-Version über [endoflife.date](https://endoflife.date/docs/api/v1/), und aktualisiert die Richtlinie, sobald die konfigurierte Cadence-Zeit abgelaufen ist. Der einzige Block, der in Intune schreibt — und das nur, wenn `$DryRun` auf `$false` steht.
2. **Device Compliance Report** (`$CheckDeviceCompliance`) — rein lesend. Listet jedes Gerät auf, das gegen die konfigurierten Richtlinien ausgewertet wird, vergleicht installierte mit geforderter Version, und speichert einen CSV- **und** einen eigenständigen, sortier-/filterbaren HTML-Bericht unter `$DeviceComplianceReportPath`.
3. **User Notification Email** (`$SendUserNotificationEmail`) — verschickt eine individuelle E-Mail pro nicht-konformem Gerät an dessen Besitzer. Setzt die Daten aus Block 2 voraus. Verschickt bei `$DryRun = $true` **keine** echte E-Mail — es wird nur geloggt, was verschickt würde.

`$DryRun = $true` deaktiviert **alle** Seiteneffekte gleichzeitig: keine Richtlinien-Schreibvorgänge (Block 1) und kein Mailversand (Block 3). Block 2 ist unabhängig von `$DryRun` immer rein lesend.

## Unterstützte Plattformen

- **iOS** — Compliance und App Protection
- **iPadOS** — Compliance und App Protection
- **macOS** — nur Compliance (Intune bietet für macOS keine App-Protection-Unterstützung)

Android und Windows werden in diesem Fork bewusst nicht unterstützt.

## Voraussetzungen

- PowerShell 5.1 oder neuer (Windows PowerShell oder PowerShell 7)
- Eine Entra-ID-App-Registrierung (oder eine Azure-Automation-Managed-Identity) mit folgenden **Anwendungsberechtigungen** (mit Admin-Zustimmung) für Microsoft Graph:

| Berechtigung | Wofür benötigt |
|---|---|
| `DeviceManagementConfiguration.ReadWrite.All` | Lesen/Schreiben von Compliance-Richtlinien |
| `DeviceManagementApps.ReadWrite.All` | Lesen/Schreiben von App-Protection-Richtlinien |
| `DeviceManagementManagedDevices.Read.All` | Lesen der installierten OS-Version pro Gerät (Block 2) |
| `Mail.Send` | Versand der Benachrichtigungs-E-Mails (nur Block 3) |
| `User.Read.All` | Ermitteln der echten primären SMTP-Adresse des Geräte-Besitzers (nur Block 3) |

Bei Verwendung von `Mail.Send` die App-Registrierung unbedingt per Exchange-Online-**Application-Access-Policy** auf ein einziges Sende-Postfach beschränken — sonst kann die App als **jedes beliebige** Postfach im Tenant senden:

```powershell
New-ApplicationAccessPolicy -AppId "<client-id>" `
    -PolicyScopeGroupId "intune-automation@eurefirma.de" `
    -AccessRight RestrictAccess `
    -Description "Nur Automatisierungs-Postfach erlauben"
```

Für die Zertifikats-Authentifizierung muss das Zertifikat samt privatem Schlüssel in `Cert:\CurrentUser\My` des Kontos liegen, unter dem das Skript läuft, oder in `Cert:\LocalMachine\My` (das Skript sucht in dieser Reihenfolge in beiden). Der Computerspeicher ist die einfachste Lösung, wenn das Skript als SYSTEM läuft; das ausführende Konto braucht Lesezugriff auf den privaten Schlüssel.

Für eine Managed Identity in Azure Automation vergibt `Grant-ManagedIdentityGraphPermissions.ps1` diese Rechte. `Mail.Send` und `User.Read.All` vergibt es nur mit `-IncludeMailPermissions`.

## Konfiguration

### Authentifizierung

```powershell
# ManagedIdentity | AppRegCert | AppRegSecret
$AuthMode              = "AppRegCert"
$TenantId              = "<tenant-id>"
$ClientId              = "<client-id>"
$CertThumbprint        = "<thumbprint>"          # nur AppRegCert
$ClientSecret          = "<secret>"              # nur AppRegSecret
$UserAssignedClientId  = ""                      # ManagedIdentity, optional
$KeyVaultName          = ""                      # AppRegSecret, optional
$KeyVaultSecretName    = ""                       # AppRegSecret, optional
```

### Richtlinien und Cadence

```powershell
# Cadence für Compliance + App-Protection "Zugriff blockieren"
$CadenceDays        = 30
# Cadence für App-Protection "Warnung" — üblicherweise kürzer, damit Benutzer rechtzeitig
# vor der strengeren Block-Frist gewarnt werden. Gilt nicht für Compliance-Richtlinien
# (dort gibt es kein separates Warn-Feld).
$CadenceDaysWarning = 14

$CompliancePolicies = @{ iOS = @(); iPadOS = @(); macOS = @() }
$AppProtectionPolicies = @{ iOS = @(); iPadOS = @() }

$AllowDowngrade = $false
$DryRun         = $true
$ForceApply     = $false   # umgeht die Cadence, gilt für Warn- und Block-Frist gleichermaßen

# Merkt sich je Plattform, welche OS-Version gerade auf die Block-Frist hin verfolgt wird
# (siehe "Funktionsweise"). Wird bei jedem Lauf geschrieben, auch mit $DryRun = $true.
$VersionStateFilePath = "C:\Skripte\IntuneComplianceMaintainer-VersionState.json"
```

### Block-Schalter

```powershell
$RunPolicyMaintenance = $true

$CheckDeviceCompliance             = $true
$CompareAgainstLatestPublicVersion = $false   # Fallback auf aktuelle öffentliche Version, falls Policy keine Mindestversion hat
$ShowDeviceComplianceList          = $true    # Geräte-Tabelle zusätzlich auf der Konsole ausgeben
$DeviceComplianceReportPath        = "C:\Reports"

$SendUserNotificationEmail = $false           # setzt $CheckDeviceCompliance = $true voraus
$EmailSenderAddress        = "<sender-postfach@euretenant.onmicrosoft.com>"
$MaxNotificationsPerRun    = 50               # Sicherheitsgrenze: darüber verschickt Block 3 nichts und meldet einen Fehler
```

### Logging und Exit-Code

`$VerboseLogging = $true` zeigt alle `INFO`-Zeilen. `WARN`- und `ERROR`-Zeilen erscheinen immer, auch mit `$VerboseLogging = $false`.

Am Ende gibt das Skript eine `[SUMMARY]`-Zeile aus (Richtlinien, Gerätezeilen, E-Mails, Fehler). Ist etwas fehlgeschlagen — eine Richtlinienzeile mit `Action = Error`, eine Gerätezeile mit `Compliant = Error: ...`, eine fehlgeschlagene E-Mail oder ein geloggter `ERROR` —, endet es mit **Exit-Code 1**, damit eine geplante Aufgabe oder ein Runbook-Job den Lauf als fehlgeschlagen anzeigt.

## Funktionsweise

### Block 1 — Policy Maintenance

Für jede konfigurierte Plattform ruft das Skript die neueste OS-Version samt Release-Datum von endoflife.date ab und merkt sie sich in einer kleinen Statusdatei (`$VersionStateFilePath`). Die so verfolgte Version ist die **Zielversion**; aus ihrem Release-Datum entstehen zwei unabhängige Fristen:

- `WarningEffectiveDate = ReleaseDate + $CadenceDaysWarning`
- `RequiredEffectiveDate = ReleaseDate + $CadenceDays`

Ist eine Frist abgelaufen, wird die Zielversion für dieses Feld (Warn oder Block) fällig. Erscheint eine **neuere** Version, bevor die Fristen der Zielversion abgelaufen sind, wird die bisherige Zielversion sofort zur Warn-Zielversion (statt übersprungen zu werden), und die Verfolgung wechselt für den Block-Countdown auf die neue Version. Ohne diesen Mechanismus würden häufige Punkt-Releases die Fristen immer wieder zurücksetzen, und Warn käme womöglich nie voran. Sobald die Warn-Frist der neuen Zielversion abgelaufen ist, übernimmt sie auch das Warn-Feld.

Die Statusdatei ist reine Buchführung und wird bei jedem Lauf geschrieben, auch mit `$DryRun = $true`; nur die eigentlichen Schreibzugriffe auf Richtlinien beachten `$DryRun`. Wird die Datei gelöscht, beginnt die Verfolgung einfach neu bei der aktuell neuesten Version. Beim Testen einer Kopie des Skripts `$VersionStateFilePath` auf eine eigene Datei setzen, damit Testläufe den Stand der echten Datei nicht verändern.

Die Felder `minimumWarningOsVersion` (Warn) und `minimumRequiredOsVersion` (Block) jeder App-Protection-Richtlinie werden dann **unabhängig voneinander** gegen ihre jeweilige Frist geprüft. Es kann also vorkommen, dass in einem Lauf nur das Warn-Feld aktualisiert wird, während Block noch nicht fällig ist — das ist so gewollt und erscheint als `Updated (nur Warn - Block noch nicht faellig)` (oder umgekehrt) statt eines einfachen `Updated`. Es werden nur Felder angefasst, die in der Richtlinie bereits konfiguriert sind — das Skript schaltet nie Block zu, wo bisher nur Warn existierte, oder umgekehrt.

Compliance-Richtlinien haben nur das eine Feld `osMinimumVersion` und nutzen ausschließlich `$CadenceDays`.

**Schutzmechanismen in Block 1:**

- Die Daten von endoflife.date werden vor der Verwendung geprüft: Die Version muss wie eine Versionsnummer aussehen (z. B. `26.1` oder `26.1.2`), das Release-Datum darf nicht in der Zukunft liegen. Ein Sprung um mehr als eine Hauptversion gegenüber der verfolgten Version wird abgelehnt, und die Zielversion geht nie rückwärts. Schlägt die Prüfung fehl, wird keine Richtlinie dieser Plattform geändert, und die Richtlinien erhalten eine `Error`-Zeile. Ist eine neue Hauptversion tatsächlich korrekt, den Eintrag der Plattform in der Statusdatei löschen.
- Vor dem Schreiben einer Compliance-Richtlinie wird ihr Typ geprüft (`iosCompliancePolicy` für iOS/iPadOS, `macOSCompliancePolicy` für macOS). In eine Richtlinie einer anderen Plattform, z. B. eine versehentlich eingetragene Windows-Richtlinie, wird nie geschrieben.
- Jede Richtlinie wird für sich verarbeitet: Eine gelöschte Richtlinie, eine falsche ID oder ein fehlendes Recht ergibt eine `Error`-Zeile für diese Richtlinie, und der Lauf geht mit der nächsten Richtlinie, Plattform und Block 2/3 weiter.
- Versionsnummern werden nach einer Normalisierung verglichen (siehe Block 2), sodass Werte wie `17` oder `26.1.0` den Vergleich nicht stören. Ein gleicher Wert ist immer `Skipped`, auch mit `$AllowDowngrade = $true`.
- Graph-Aufrufe werden nur bei vorübergehenden Fehlern wiederholt (Netzwerk, 408, 429, 5xx), mit Beachtung von `Retry-After`. Andere Fehler wie 404 schlagen sofort fehl. Das Graph-Token wird nach 45 Minuten automatisch erneuert.

### Block 2 — Device Compliance Report

- **Compliance-Richtlinien**: nutzt den dokumentierten Graph-Endpunkt `/deviceManagement/deviceCompliancePolicies/{id}/deviceStatuses` für die Geräteliste (alle Seiten, über `@odata.nextLink`) und korreliert jeden Eintrag über die ID mit `/deviceManagement/managedDevices/{id}` für installierte OS-Version, Gerätemodell und letzten Sync-Zeitpunkt. Diese ID-Korrelation ist ein in der Community verbreitetes, von Microsoft aber nicht explizit dokumentiertes Muster — bei Auffälligkeiten in Graph Explorer verifizieren. Schlägt die Abfrage für ein Gerät fehl, erscheint es als `Unknown (device lookup failed)`, und eine `WARN`-Zeile nennt die Anzahl.
- **App-Protection-Richtlinien**: der einfache Endpunkt für den Gerätestatus pro Richtlinie ist nicht zuverlässig über alle Tenants hinweg verfügbar. Stattdessen nutzt das Skript die asynchrone **Intune-Reports-Export-API** (`/deviceManagement/reports/exportJobs`, Report `MAMAppProtectionStatus`): Export-Job anlegen, auf Fertigstellung warten, ZIP herunterladen, entpacken, auswerten. Obwohl Microsofts eigene Doku für diesen Report "keine Filter" angibt, enthält er tatsächlich eine `Policy`-Spalte mit dem Anzeigenamen der Richtlinie — darüber ordnet das Skript die Zeilen der richtigen Richtlinie zu. Hat eine Richtlinie Block und Warn konfiguriert, werden **beide** pro Gerät geprüft: Ein Gerät unter Block wird gegen Block gemeldet, ein Gerät, das Block erfüllt, aber unter Warn liegt, gegen Warn (`RuleType = AppProtection-Warn`).
- **Versionsvergleich**: Verwendet wird die erste Folge von Zahlen mit Punkten in einer Versionsangabe, aufgefüllt auf vier Stellen. So wird `14.1 (23B74)` (macOS mit Build) als 14.1 gelesen, `26.5.2.a` (Rapid Security Response) als 26.5.2, und `18.5` gilt als gleich `18.5.0`.
- Ausgabe: `IntuneDeviceComplianceReport_<Zeitstempel>.csv` und eine passende `.html`-Datei mit klickbaren, sortierbaren Spalten (Versionsnummern und Datumswerte werden richtig sortiert), einer Filterzeile pro Spalte, und rot markierten nicht-konformen Zeilen — komplett eigenständig (kein externes JS/CSS, funktioniert offline). In der CSV erhalten Werte, die mit `=`, `+`, `-` oder `@` beginnen, ein vorangestelltes `'`, damit Excel sie nicht als Formel ausführt.

### Block 3 — User Notification Email

Nutzt die Geräteliste aus Block 2, filtert auf `Compliant = "No"`-Zeilen mit auflösbarem Benutzer, ermittelt für jeden Benutzer die echte primäre SMTP-Adresse über `/users/{upn}` (Fallback auf die UPN, falls die Abfrage fehlschlägt — UPN und primäre E-Mail-Adresse sind nicht immer identisch, z. B. bei einem lokalen `.local`-UPN-Suffix), und verschickt eine individuelle E-Mail pro Gerät über `/users/{sender}/sendMail`.

- **Eine E-Mail pro Gerät:** Die Zeilen werden zuerst nach Benutzer und Gerät gruppiert (der App-Protection-Report hat eine Zeile pro App, und ein Gerät kann zusätzlich unter einer Compliance-Richtlinie auftauchen). Verschickt wird der schwerwiegendste Befund: Block/Compliance vor Warn, dann die höchste geforderte Version.
- **Inhalt:** Betreff und Update-Pfad passen zur Plattform (iPhone/iPad oder Mac). Weil Geräte mit der *aktuell* eingestellten Version verglichen werden, beschreibt die E-Mail den aktuellen Zustand (Zugriff blockiert / Warnung wird angezeigt / Gerät nicht konform) und verspricht keine Frist.
- **Sicherheitsgrenze:** Würden mehr als `$MaxNotificationsPerRun` Geräte angeschrieben, wird gar keine E-Mail verschickt und ein `ERROR` geloggt — Schutz vor einem Massenversand durch eine falsche Zielversion.
- `sendMail` wird nur bei 429/503 wiederholt, damit ein Timeout nicht dazu führt, dass dieselbe E-Mail zweimal verschickt wird. Die E-Mail wird als UTF-8 gesendet, damit Umlaute auch unter Windows PowerShell 5.1 richtig ankommen.

## Unbeaufsichtigter Betrieb (geplante Aufgabe)

Für den täglichen Lauf auf einem Windows-Server liegen zwei Hilfsskripte bei:

- **`Setup-IntuneComplianceMaintainerTask.ps1`** — legt eine tägliche geplante Aufgabe an (oder ersetzt sie). Standardmäßig läuft die Aufgabe unter einem bestimmten Konto (die Anmeldedaten werden abgefragt); mit `-RunAsSystem` läuft sie als `SYSTEM`. In einer PowerShell mit Administratorrechten ausführen:
  ```powershell
  .\Setup-IntuneComplianceMaintainerTask.ps1 -ScriptPath "C:\Skripte\IntuneComplianceMaintainer.ps1" -RunAsSystem -TriggerTime "05:00"
  ```
- **`Invoke-IntuneComplianceMaintainerWithLogging.ps1`** — der Wrapper, den die Aufgabe tatsächlich aufruft. Er startet das Hauptskript, schreibt dessen gesamte Ausgabe nach `IntuneComplianceMaintainer_<Zeitstempel>.log` in `-LogDirectory`, löscht Logs, die älter als `-RetentionDays` sind (Standard 30), und endet mit Exit-Code 1, wenn das Hauptskript einen Fehler geworfen hat.

Der Wrapper schreibt das Log als UTF-8 und meldet einen Lauf als `Failed` (Exit-Code 1), sowohl wenn das Hauptskript einen Fehler wirft als auch wenn es mit Exit-Code 1 endet (siehe „Logging und Exit-Code“).

**Betrieb als SYSTEM:** `SYSTEM` hat einen eigenen Zertifikatsspeicher. Ein Zertifikat, das unter dem eigenen Konto importiert wurde, sieht es nicht. Entweder `AppRegCert` mit dem Zertifikat in `Cert:\LocalMachine\My` verwenden oder `AppRegSecret` (am besten aus Key Vault). Steht das Secret direkt im Skript, die Dateirechte auf Administratoren und SYSTEM beschränken — Dateien unter `C:\` sind standardmäßig für alle lokalen Benutzer lesbar.

## Bekannte Einschränkungen

- Das Schema des `MAMAppProtectionStatus`-Reports wurde empirisch ermittelt (Microsofts öffentliche Doku listet keine exakten Spaltennamen) — falls euer Tenant andere Spaltennamen liefert, findet die stichwortbasierte Suche des Skripts (`Get-PropertyValueLike`) das erwartete Feld eventuell nicht. Bei leeren Gerätedaten die `[INFO]`-Diagnosezeilen prüfen (Zeilenanzahl des Reports, Spaltennamen, "kein Treffer"-Warnungen).
- Apple-Gerätemodell-Werte (z. B. `iPhone12,1`) sind Apples interne Kennungen, keine lesbaren Namen — es gibt keine offizielle API, die das auf Marketingnamen (z. B. "iPhone 11") abbildet.
- Windows PowerShell 5.1 dekodiert bei `Invoke-RestMethod`/`Invoke-WebRequest` UTF-8-JSON-Antworten ohne expliziten Charset fälschlich als ISO-8859-1 (verfälscht deutsche Umlaute/ß). Umgangen über einen auf rohem `HttpWebRequest` basierenden `Invoke-GraphGet`-Wrapper für GET-Aufrufe. Sieht ein Anzeigename auch unter PowerShell 7 (das diesen Bug nicht hat) noch falsch aus, ist der Wert höchstwahrscheinlich tatsächlich im gespeicherten Intune-Objekt selbst beschädigt (z. B. durch ein früheres Tool mit demselben Bug) — direkt im Intune-Portal prüfen.

## Fehlerbehebung

**"Unable to find type [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]"** — betrifft nur das *ursprüngliche* Upstream-Skript; dieser Fork baut die JWT-Client-Assertion manuell mit eingebauter .NET-Kryptografie (`System.Security.Cryptography`), keine externe Assembly nötig.

**"AADSTS7000215: Invalid client secret provided"** — ihr habt die Secret-**ID** (eine reine GUID) statt des Secret-**Werts** aus Entra ID → Zertifikate & Geheimnisse eingetragen. Der Wert wird nur einmal direkt nach dem Erstellen angezeigt.

**Zertifikat nicht gefunden** — muss samt privatem Schlüssel in `Cert:\CurrentUser\My` des Kontos liegen, unter dem das Skript tatsächlich läuft, oder in `Cert:\LocalMachine\My`, und das ausführende Konto muss den privaten Schlüssel lesen dürfen.

**Lauf zeigt `Failed` / Exit-Code 1** — die `[SUMMARY]`-Zeile und die `ERROR`-/`WARN`-Zeilen im Log prüfen; dort steht jede fehlgeschlagene Richtlinie, Geräteabfrage oder E-Mail.

## Änderungsprotokoll gegenüber dem Original

- Android- und Windows-Support komplett entfernt (nur noch iOS/iPadOS/macOS)
- Unterstützung für das App-Protection-Feld "Warnung" (`minimumWarningOsVersion`) ergänzt, unabhängig von "Zugriff blockieren" (`minimumRequiredOsVersion`) — vorher wurde nur Block gelesen/geschrieben
- Getrennte Cadence-Zeiten: eigene, kürzere Frist für Warn vs. Block
- `Current` → `CurrentRequired` umbenannt zur Klarstellung, jetzt wo auch `CurrentWarning` existiert
- `AppRegCert`-Authentifizierung repariert: ohne Abhängigkeit von `System.IdentityModel.Tokens.Jwt` neu aufgebaut
- Redundanten doppelten API-Aufruf an endoflife.date für die App-Protection-Cadence-Prüfung behoben (nutzt jetzt das Ergebnis der Compliance-Prüfung wieder)
- UTF-8-Verfälschung unter Windows PowerShell 5.1 über einen eigenen `Invoke-GraphGet`-Wrapper behoben
- Geräteweise Compliance-Berichterstattung ergänzt (Block 2), inkl. CSV- und filterbarer/sortierbarer HTML-Ausgabe, Gerätemodell und letztem Sync-Zeitpunkt
- Individuelle E-Mail-Benachrichtigung pro Benutzer für nicht-konforme Geräte ergänzt (Block 3), vollständig `$DryRun`-sicher
- Prioritäts-Bug bei der Eigenschaftssuche behoben, der beim Aufbau der Benachrichtigungsempfänger einen Anzeigenamen statt einer E-Mail-Adresse hätte auswählen können
- Dauerhafte Versionsverfolgung ergänzt (`$VersionStateFilePath`): Eine überholte Zielversion wird zur Warn-Zielversion befördert statt übersprungen, sodass Warn auch bei häufigen Releases weiter vorankommt
- `Setup-IntuneComplianceMaintainerTask.ps1` und den Logging-Wrapper `Invoke-IntuneComplianceMaintainerWithLogging.ps1` für unbeaufsichtigte tägliche Läufe ergänzt
- Härtung nach Code-Review (2026-11): Daten von endoflife.date werden geprüft; Typ der Compliance-Richtlinie wird vor dem Schreiben geprüft; Fehler pro Richtlinie statt Abbruch des Laufs; robuster Versionsvergleich (macOS-Build-Zusatz, `18.5` = `18.5.0`, einstellige Versionen); Paging für Gerätestatus; Block und Warn werden pro Gerät ausgewertet; eine E-Mail pro Gerät mit Sicherheitsgrenze und einem Text, der zum aktuellen Zustand passt; E-Mail-Text als UTF-8; Wiederholung nur bei vorübergehenden Fehlern; Token-Erneuerung; Exit-Code 1 bei Fehlern; Zertifikat auch aus `LocalMachine\My`; temporäre Dateien des Report-Exports werden immer entfernt; Formelschutz in der CSV; minimale Rechte als Standard im Grant-Skript

## Haftungsausschluss

Dieses Skript verändert produktive Intune-Richtlinien und kann im Namen eurer Organisation E-Mails versenden. Immer zuerst mit `$DryRun = $true` testen, nach Möglichkeit in einer Nicht-Produktivumgebung. Weder der ursprüngliche Upstream-Autor noch FP-IT-Solutions GmbH übernimmt Haftung für unbeabsichtigte Änderungen oder Auswirkungen auf eure Umgebung.

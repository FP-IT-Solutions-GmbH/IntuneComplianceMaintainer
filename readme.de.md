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

Für die Zertifikats-Authentifizierung muss das Zertifikat samt privatem Schlüssel in `Cert:\CurrentUser\My` liegen — und zwar im Profil des Windows-Kontos, unter dem das Skript tatsächlich läuft (Vorsicht bei geplanten Aufgaben unter einem Dienstkonto).

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
```

### Block-Schalter

```powershell
$RunPolicyMaintenance = $true

$CheckDeviceCompliance             = $false
$CompareAgainstLatestPublicVersion = $false   # Fallback auf aktuelle öffentliche Version, falls Policy keine Mindestversion hat
$ShowDeviceComplianceList          = $false   # Geräte-Tabelle zusätzlich auf der Konsole ausgeben
$DeviceComplianceReportPath        = "C:\Reports"

$SendUserNotificationEmail = $false           # setzt $CheckDeviceCompliance = $true voraus
$EmailSenderAddress        = "<sender-postfach@euretenant.onmicrosoft.com>"
```

## Funktionsweise

### Block 1 — Policy Maintenance

Für jede konfigurierte Plattform ruft das Skript die neueste OS-Version samt Release-Datum von endoflife.date ab und berechnet daraus zwei unabhängige Fristen:

- `WarningEffectiveDate = ReleaseDate + $CadenceDaysWarning`
- `RequiredEffectiveDate = ReleaseDate + $CadenceDays`

Die Felder `minimumWarningOsVersion` (Warn) und `minimumRequiredOsVersion` (Block) jeder App-Protection-Richtlinie werden dann **unabhängig voneinander** gegen ihre jeweilige Frist geprüft. Es kann also vorkommen, dass in einem Lauf nur das Warn-Feld aktualisiert wird, während Block noch nicht fällig ist — das ist so gewollt und erscheint als `Updated (nur Warn - Block noch nicht faellig)` (oder umgekehrt) statt eines einfachen `Updated`. Es werden nur Felder angefasst, die in der Richtlinie bereits konfiguriert sind — das Skript schaltet nie Block zu, wo bisher nur Warn existierte, oder umgekehrt.

Compliance-Richtlinien haben nur das eine Feld `osMinimumVersion` und nutzen ausschließlich `$CadenceDays`.

### Block 2 — Device Compliance Report

- **Compliance-Richtlinien**: nutzt den dokumentierten Graph-Endpunkt `/deviceManagement/deviceCompliancePolicies/{id}/deviceStatuses` für die Geräteliste und korreliert jeden Eintrag über die ID mit `/deviceManagement/managedDevices/{id}` für installierte OS-Version, Gerätemodell und letzten Sync-Zeitpunkt. Diese ID-Korrelation ist ein in der Community verbreitetes, von Microsoft aber nicht explizit dokumentiertes Muster — bei Auffälligkeiten in Graph Explorer verifizieren.
- **App-Protection-Richtlinien**: der einfache Endpunkt für den Gerätestatus pro Richtlinie ist nicht zuverlässig über alle Tenants hinweg verfügbar. Stattdessen nutzt das Skript die asynchrone **Intune-Reports-Export-API** (`/deviceManagement/reports/exportJobs`, Report `MAMAppProtectionStatus`): Export-Job anlegen, auf Fertigstellung warten, ZIP herunterladen, entpacken, auswerten. Obwohl Microsofts eigene Doku für diesen Report "keine Filter" angibt, enthält er tatsächlich eine `Policy`-Spalte mit dem Anzeigenamen der Richtlinie — darüber ordnet das Skript die Zeilen der richtigen Richtlinie zu.
- Ausgabe: `IntuneDeviceComplianceReport_<Zeitstempel>.csv` und eine passende `.html`-Datei mit klickbaren, sortierbaren Spalten, einer Filterzeile pro Spalte, und rot markierten nicht-konformen Zeilen — komplett eigenständig (kein externes JS/CSS, funktioniert offline).

### Block 3 — User Notification Email

Nutzt die Geräteliste aus Block 2, filtert auf `Compliant = "No"`-Zeilen mit auflösbarem Benutzer, ermittelt für jeden Benutzer die echte primäre SMTP-Adresse über `/users/{upn}` (Fallback auf die UPN, falls die Abfrage fehlschlägt — UPN und primäre E-Mail-Adresse sind nicht immer identisch, z. B. bei einem lokalen `.local`-UPN-Suffix), und verschickt eine individuelle E-Mail pro Gerät über `/users/{sender}/sendMail`. Die im Text genannte Frist (`$CadenceDays` vs. `$CadenceDaysWarning`) passt sich automatisch der auslösenden Regel (Warn oder Block) an.

## Bekannte Einschränkungen

- Das Schema des `MAMAppProtectionStatus`-Reports wurde empirisch ermittelt (Microsofts öffentliche Doku listet keine exakten Spaltennamen) — falls euer Tenant andere Spaltennamen liefert, findet die stichwortbasierte Suche des Skripts (`Get-PropertyValueLike`) das erwartete Feld eventuell nicht. Bei leeren Gerätedaten die `[INFO]`-Diagnosezeilen prüfen (Zeilenanzahl des Reports, Spaltennamen, "kein Treffer"-Warnungen).
- Apple-Gerätemodell-Werte (z. B. `iPhone12,1`) sind Apples interne Kennungen, keine lesbaren Namen — es gibt keine offizielle API, die das auf Marketingnamen (z. B. "iPhone 11") abbildet.
- Windows PowerShell 5.1 dekodiert bei `Invoke-RestMethod`/`Invoke-WebRequest` UTF-8-JSON-Antworten ohne expliziten Charset fälschlich als ISO-8859-1 (verfälscht deutsche Umlaute/ß). Umgangen über einen auf rohem `HttpWebRequest` basierenden `Invoke-GraphGet`-Wrapper für GET-Aufrufe. Sieht ein Anzeigename auch unter PowerShell 7 (das diesen Bug nicht hat) noch falsch aus, ist der Wert höchstwahrscheinlich tatsächlich im gespeicherten Intune-Objekt selbst beschädigt (z. B. durch ein früheres Tool mit demselben Bug) — direkt im Intune-Portal prüfen.

## Fehlerbehebung

**"Unable to find type [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]"** — betrifft nur das *ursprüngliche* Upstream-Skript; dieser Fork baut die JWT-Client-Assertion manuell mit eingebauter .NET-Kryptografie (`System.Security.Cryptography`), keine externe Assembly nötig.

**"AADSTS7000215: Invalid client secret provided"** — ihr habt die Secret-**ID** (eine reine GUID) statt des Secret-**Werts** aus Entra ID → Zertifikate & Geheimnisse eingetragen. Der Wert wird nur einmal direkt nach dem Erstellen angezeigt.

**Zertifikat nicht gefunden** — muss in `Cert:\CurrentUser\My` des Kontos liegen, unter dem das Skript tatsächlich läuft (nicht `Cert:\LocalMachine\My`), samt privatem Schlüssel.

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

## Haftungsausschluss

Dieses Skript verändert produktive Intune-Richtlinien und kann im Namen eurer Organisation E-Mails versenden. Immer zuerst mit `$DryRun = $true` testen, nach Möglichkeit in einer Nicht-Produktivumgebung. Weder der ursprüngliche Upstream-Autor noch FP-IT-Solutions GmbH übernimmt Haftung für unbeabsichtigte Änderungen oder Auswirkungen auf eure Umgebung.

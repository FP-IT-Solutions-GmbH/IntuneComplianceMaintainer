# IntuneComplianceMaintainer

Pflegt automatisch die Minimum-OS-Version in Microsoft Intune Compliance- und App-Protection-Richtlinien, sodass der Gerätezugriff stets auf Basis eines aktuellen Sicherheitsstands eingeschränkt wird.

> **Dies ist eine lokal angepasste Version.** Siehe [Änderungen in dieser Version](#änderungen-in-dieser-version-lokale-fixes) für die genauen Unterschiede zum Originalskript von [SkipToTheEndpoint/IntuneComplianceMaintainer](https://github.com/SkipToTheEndpoint/IntuneComplianceMaintainer), sowie [Gefundene Probleme im Original](#gefundene-probleme-im-original-skriptdokumentation) für Auffälligkeiten in der Upstream-Version.

## Änderungen in dieser Version (lokale Fixes)

Beim Testen des Originalskripts (v2.0, 01.07.2026) gegen einen echten Tenant mit einer `AppRegCert`-basierten App-Registrierung auf einer Kunden-VM wurden drei Probleme gefunden und behoben:

### 1. Behoben: `AppRegCert`-Authentifizierung schlug mit "Unable to find type" fehl

**Problem:** Die ursprüngliche `Get-GraphToken`-Funktion baute die JWT-Client-Assertion mit `[System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]` und `[System.IdentityModel.Tokens.X509SigningCredentials]`. Keiner dieser Typen ist in Windows PowerShell 5.1 standardmäßig geladen, und neuere Versionen des zugrunde liegenden NuGet-Pakets stellen `X509SigningCredentials` in diesem Namespace gar nicht mehr bereit — selbst eine manuelle Paketinstallation behob den Fehler daher nicht.

**Fix:** Der `AppRegCert`-Zweig von `Get-GraphToken` baut den JWT jetzt manuell ausschließlich mit eingebauter .NET-Kryptografie (`System.Security.Cryptography`), ganz ohne externe Assembly-Abhängigkeit:
- Header/Payload werden von Hand JSON- und Base64URL-kodiert
- Die Signatur erfolgt über `RSACertificateExtensions.GetRSAPrivateKey($cert).SignData(...)` (RS256 / PKCS1)
- Die resultierende `client_assertion` wird wie zuvor an den Token-Endpunkt gesendet

Es sind keine Konfigurationsänderungen nötig — `$AuthMode = "AppRegCert"`, `$TenantId`, `$ClientId` und `$CertThumbprint` funktionieren genau wie dokumentiert. Das Zertifikat muss weiterhin in `Cert:\CurrentUser\My` liegen (das war im Original-Prerequisites-Abschnitt bereits korrekt dokumentiert).

### 2. Behoben: App-Protection-Richtlinien mit Aktion "Warnung" statt "Zugriff blockieren" wurden vom Skript nicht erkannt

**Problem:** Bedingte-Start-Regeln (Conditional Launch) für die Minimum-OS-Version bei iOS/Android App-Protection-Richtlinien können mit einer von zwei Aktionen konfiguriert werden:
- **Zugriff blockieren** → Graph-Feld `minimumRequiredOsVersion`
- **Warnung** → Graph-Feld `minimumWarningOsVersion`

Das Originalskript hat ausschließlich `minimumRequiredOsVersion` gelesen und geschrieben. Eine Richtlinie, die nur mit der Aktion "Warnung" konfiguriert war (eine übliche, weniger einschneidende Rollout-Wahl), zeigte einen leeren `Current`-Wert und wurde nie tatsächlich aktualisiert — obwohl das Skript für sie eine Ergebniszeile ausgab.

**Fix:**
- `Get-AppProtectionPolicyInfo` liest jetzt zusätzlich `minimumWarningOsVersion` in eine neue `CurrentWarning`-Eigenschaft ein
- `Update-AppProtectionPolicy` erkennt jetzt automatisch, welche(s) Feld(er) auf der jeweiligen Richtlinie tatsächlich konfiguriert ist/sind, und aktualisiert nur diese — eine Richtlinie mit nur "Warnung" bekommt `minimumWarningOsVersion` aktualisiert, eine mit nur "Zugriff blockieren" bekommt `minimumRequiredOsVersion` aktualisiert, eine mit beidem bekommt beides aktualisiert. **Keines der beiden Felder wird bei einer Richtlinie neu gesetzt, die es vorher nicht hatte** — der Fix schaltet also nicht heimlich Blockieren zu, wo bisher nur eine Warnung existierte, oder umgekehrt.
- Ein neuer Status `NoData` wird zurückgegeben, falls eine Richtlinie überhaupt keines der beiden Felder konfiguriert hat.

### 3. Umbenannt: `Current` → `CurrentRequired` zur Klarstellung

**Problem:** Mit der Einführung von `CurrentWarning` wurde die ursprüngliche Eigenschaft `Current` mehrdeutig — sie meint konkret den *Block*-Wert, nicht "irgendeinen der beiden Werte, je nachdem was gesetzt ist".

**Fix:** Im gesamten Skript umbenannt (Ergebnisobjekte, Konsolen-`[RESULT]`-Logzeile und die abschließende Zusammenfassungstabelle) in `CurrentRequired`, passend zum Graph-Feldnamen `minimumRequiredOsVersion`. Die Spaltenliste der Zusammenfassungstabelle wird jetzt explizit angegeben (`Format-Table -Property ...`) statt sich auf die automatische Schema-Erkennung zu verlassen — der ursprüngliche Ansatz ließ die `CurrentWarning`-Spalte stillschweigend verschwinden, sobald die *erste* Zeile im Ergebnis-Array zufällig eine Compliance-Richtlinie war (die dieses Feld grundsätzlich nie hat), unabhängig davon, ob spätere App-Protection-Zeilen einen Wert hatten.

## Gefundene Probleme im Original-Skript/-Dokumentation

Diese wurden **nicht** behoben (keine Codeänderung), sind aber erwähnenswert:

- **Versionsnummer-Diskrepanz:** Der Skript-Header-Kommentar nennt `Version: v2.0, Release Date: 2026-07-01`, während die README-Versionshistorie nur bis `v1.2 (2026-07-01)` reicht. Der dort beschriebene Funktionsumfang (Android-Multi-Version-Support, Patch-Level-Enforcement etc.) entspricht v1.2 — unklar bleibt, was sich in v2.0 geändert hat, da dies nirgends dokumentiert ist.
- **Abweichender Default bei `$WindowsAllowNewerBuilds`:** Das Beispiel-Konfigurationsschnipsel in der README zeigt `$WindowsAllowNewerBuilds = $true` mit dem Kommentar "Allow devices on newer builds (e.g. Preview Updates)", der tatsächliche Skript-Default ist jedoch `$false`. Vor dem 1:1-Übernehmen des README-Beispiels lohnt sich ein bewusster Check, welcher Wert tatsächlich gewünscht ist.
- **Keine Erwähnung der `AppRegCert`-Assembly-Abhängigkeit:** Der ursprüngliche Prerequisites-Abschnitt listet Graph-Berechtigungen und Module für Managed Identity/Key Vault auf, erwähnt aber nirgends, dass der ursprüngliche (ungepatchte) Zertifikats-Auth-Codepfad voraussetzte, dass `System.IdentityModel.Tokens.Jwt` bereits in der Session geladen ist — was außerhalb von Azure Automation auf einer normalen Windows Server/VM nicht garantiert ist. Mit dem obigen Fix ist das nun hinfällig, hätte aber bei exaktem Befolgen der dokumentierten Setup-Schritte denselben Fehler verursacht.
- **`minimumWarningOsVersion` wird in der Original-Doku nirgends erwähnt:** Die Abschnitte "How It Works" und "Output" beschreiben App-Protection-Updates ausschließlich über `minimumRequiredOsVersion`. Da "Warnung" eine völlig gängige, häufig genutzte Conditional-Launch-Aktion in Intune ist, wirkt das eher wie ein Versehen als eine bewusste Scope-Einschränkung — sollte dem Original-Autor gemeldet werden.

---

## Übersicht

IntuneComplianceMaintainer ist ein PowerShell-Automatisierungsskript, das Intune Compliance- und App-Protection-Richtlinien plattformübergreifend mit den aktuellen OS-Versionsanforderungen auf dem Laufenden hält. Über die [endoflife.date-API](https://endoflife.date/docs/api/v1/) und den [Microsoft Graph Windows Update Catalog](https://learn.microsoft.com/en-us/graph/api/windowsupdates-catalog-list-entries?view=graph-rest-beta&tabs=http) wird sichergestellt, dass der Sicherheitsstand der Organisation aktuell bleibt, während konfigurierbare Cadence-Zeiträume ein schrittweises Rollout ermöglichen.

## Funktionen

- **Multi-Plattform-Support**: iOS, iPadOS, macOS, Android und Windows
- **Zwei Richtlinientypen**: Aktualisiert sowohl Compliance- als auch App-Protection-Richtlinien
- **Warn- und Block-Unterstützung** *(lokaler Fix)*: Die Minimum-OS-Version wird für App-Protection-Richtlinien unabhängig sowohl für "Warnung" (`minimumWarningOsVersion`) als auch für "Zugriff blockieren" (`minimumRequiredOsVersion`) nachverfolgt und aktualisiert
- **Flexible Authentifizierung**: Managed Identity (Azure Automation), App-Registrierung mit Zertifikat (jetzt ohne externe Abhängigkeit, siehe Fixes oben) oder App-Registrierung mit Secret (inkl. Azure-Key-Vault-Integration)
- **Cadence-Steuerung**: Konfigurierbare Verzögerung zwischen Release und Enforcement, mit optionalem Force-Apply
- **Android-Patch-Level**: Setzt zusätzlich zur OS-Version das minimale Android-Sicherheitspatch-Level durch; zielt standardmäßig auf die älteste noch unterstützte Android-Version für `osMinimumVersion` ab und leitet das monatliche Patch-Datum aus Androids Patch-Zeitplan ab (1. jedes Monats)
- **Windows-Erweiterungen**: Unterstützung für spezifische Build-Nummern, Update-Klassifizierungen, Versionsbereiche und wählbares App-Protection-Zielbuild (standardmäßig das niedrigste)
- **Sicherheitsfunktionen**: Optionaler Downgrade-Schutz und Dry-Run-Modus (Downgrade-Prüfung berücksichtigt OS-Version, Warn-Version und Patch-Level unabhängig voneinander)
- **Retry-Logik**: Eingebauter Wiederholungsmechanismus für API-Robustheit
- **Umfassendes Logging**: Ausführliches Logging mit detaillierter Ergebnisausgabe

## Voraussetzungen

- PowerShell 5.1 oder neuer
- Microsoft-Graph-API-Berechtigungen:
  - `DeviceManagementConfiguration.ReadWrite.All` (für Compliance-Richtlinien)
  - `DeviceManagementApps.ReadWrite.All` (für App-Protection-Richtlinien)
  - `WindowsUpdates.ReadWrite.All` (für Windows-Update-Catalog-Abfragen — nur nötig bei Windows-Automatisierung)
- Für Managed-Identity-Authentifizierung: Modul `Az.Accounts` (in Azure Automation i. d. R. vorinstalliert)
- Für Key-Vault-Integration: Modul `Az.KeyVault` und entsprechender Key-Vault-Zugriff
- Für Zertifikats-Authentifizierung: Zertifikat im Speicher `Cert:\CurrentUser\My` (privater Schlüssel erforderlich); **keine externe Assembly nötig** — der JWT wird mit eingebauter .NET-Kryptografie erstellt (lokaler Fix)

## Konfiguration

### Authentifizierungseinstellungen

#### Managed Identity
```powershell
$AuthMode = "ManagedIdentity"
$TenantId = "deine-tenant-id"
$UserAssignedClientId = "" # optional
```

#### App-Registrierung mit Zertifikat
```powershell
$AuthMode = "AppRegCert"
$TenantId = "deine-tenant-id"
$ClientId = "deine-client-id"
$CertThumbprint = "zertifikat-thumbprint"
```

#### App-Registrierung mit Secret
```powershell
$AuthMode = "AppRegSecret"
$TenantId = "deine-tenant-id"
$ClientId = "deine-client-id"
$ClientSecret = "dein-secret"

# Optional: Key Vault nutzen
$KeyVaultName = "dein-keyvault-name"
$KeyVaultSecretName = "dein-secret-name"
```

### Umgebungskonfiguration

```powershell
$CadenceDays = 14

$CompliancePolicies = @{
  iOS     = @("policy-guid-1", "policy-guid-2")
  iPadOS  = @("policy-guid-3")
  macOS   = @()
  Android = @("policy-guid-4")
  Windows = @("policy-guid-5")
}

$AppProtectionPolicies = @{
  iOS     = @("policy-guid-6")
  iPadOS  = @()
  Android = @("policy-guid-7")
  Windows = @("policy-guid-8")
}
```

### Sicherheitseinstellungen

```powershell
$AllowDowngrade = $false
$DryRun         = $true
$ForceApply     = $false
```

## Verwendung

1. Authentifizierung und Policy-IDs im Skript konfigurieren
2. Zuerst mit `$DryRun = $true` ausführen und die Ausgabe prüfen
3. Für den produktiven Lauf `$DryRun = $false` setzen

Auch mit `$DryRun = $false` wird nichts geändert, solange das `EffectiveDate` (Release-Datum + `$CadenceDays`) noch nicht erreicht ist — für einen Test vor diesem Datum kann `$ForceApply = $true` vorübergehend gesetzt werden; danach für den produktiven Betrieb wieder auf `$false` zurückstellen.

## Ausgabe

```
[RESULT][iOS/Compliance]    test:     action=NotEffectiveYet; currentRequired=23.5; target=26.5.2; ...
[RESULT][iOS/AppProtection] test_123: action=NotEffectiveYet; currentRequired=23.4; currentWarning=22.4; target=26.5.2; ...

Platform Type          Setting        Name     CurrentRequired CurrentWarning Target ... Action          ...
-------- ----          -------        ----     --------------- -------------- ------ --- ------          ---
iOS      Compliance    MinimumVersion test     23.5                           26.5.2 ... NotEffectiveYet ...
iOS      AppProtection MinimumVersion test_123 23.4            22.4           26.5.2 ... NotEffectiveYet ...
```

## Aktionstypen

- **Updated**: Richtlinie wurde erfolgreich aktualisiert
- **WouldUpdate**: Richtlinie würde aktualisiert (Dry-Run-Modus)
- **Skipped**: Aktueller Wert/aktuelle Werte erfüllen bereits das Ziel (Downgrade-Schutz)
- **NotEffectiveYet**: Cadence-Zeitraum ist noch nicht abgelaufen
- **NoData**: Keine Versionsdaten verfügbar (bzw. bei App Protection: weder `minimumRequiredOsVersion` noch `minimumWarningOsVersion` auf der Richtlinie konfiguriert)
- **Error**: Update fehlgeschlagen (Details in der Ausgabe)

## Sicherheitshinweise

- Secrets bei Verwendung von `AppRegSecret` in Azure Key Vault speichern
- Für Szenarien außerhalb von Azure Automation Zertifikats-Authentifizierung gegenüber Secrets bevorzugen (längere Gültigkeit, privater Schlüssel verlässt die Maschine nie)
- Für Azure-Automation-Szenarien Managed Identity verwenden
- Least-Privilege-Prinzip bei den Graph-API-Berechtigungen anwenden
- Audit-Logs auf Richtlinienänderungen prüfen
- Zuerst in einer Nicht-Produktivumgebung testen

## Lizenz

Nutzung auf eigenes Risiko. Vor dem produktiven Einsatz gründlich prüfen und testen.

## Haftungsausschluss

Dieses Skript verändert produktive Intune-Richtlinien. Immer zuerst in einer Nicht-Produktivumgebung testen und vor dem Live-Einsatz den Dry-Run-Modus nutzen. Weder der Original-Autor noch der Autor dieser lokalen Fixes übernimmt Haftung für unbeabsichtigte Änderungen oder Auswirkungen auf deine Umgebung.

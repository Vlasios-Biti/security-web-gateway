SECURITY_WEB_GATEWAY SWG ENDPOINT GUI v1.3.1
================================

QELLIMI
-------
v1.3.1 e kthen endpoint control-in ne nje program Windows te vetem.

Pas instalimit Start Menu ka vetem:
  Proxy Control
    -> Proxy Control

Kur programi hapet, GUI tregon:
- Status: ENABLED / DISABLED
- PAC URL
- Traffic Mode: PROXY/PAC ose DIRECT
- User Settings Lock
- PAC Server Reachability
- Last Change

Butonat:
- Start SWG
- Stop SWG
- Refresh
- Uninstall

SIGURIA
-------
Standard user:
- mund ta hape programin;
- mund te shohe status;
- nuk mund te ndryshoje proxy/PAC nga Windows Settings;
- Start/Stop/Uninstall kerkojne UAC dhe Administrator credentials.

Administrator:
- Start SWG = aktivizon PAC machine-wide;
- Stop SWG = heq PAC dhe kalon DIRECT, por locks mbeten;
- Uninstall = rikthen konfigurimin qe PC kishte para instalimit te pare.

BUILD
-----
1. Nxirr ZIP-in.
2. Double-click BUILD-EXE.cmd
3. Prit BUILD SUCCESS.
4. Merr:
     dist\Proxy-Control-Setup-v1.3.1.exe

UPGRADE NGA VERSIONI AKTUAL
---------------------------
Nuk eshte e nevojshme te besh uninstall paraprak.
Ekzekuto Setup v1.3.1 mbi instalimin ekzistues.
Backup-i fillestar i proxy settings ruhet dhe nuk mbishkruhet.

PAC:
  http://proxy.example.internal:8081/proxy.pac

Fail-open vazhdon te menaxhohet nga PAC ne server:
  PROXY proxy.example.internal:3128; DIRECT

DIRECT bypass IP/domain-et vazhdojne te jene pjese e PAC-it ne server.

BUILD FOR A SPECIFIC SERVER
---------------------------
PowerShell example:

  .\Build-Proxy-Control-Setup.ps1 -PacUrl "http://proxy.example.internal:8081/proxy.pac"

Use the PAC URL for the target Security Web Gateway environment.

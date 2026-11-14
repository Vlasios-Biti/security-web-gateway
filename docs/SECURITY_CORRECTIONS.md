# Kontrolli dhe korrigjimet — 3.12.7

Rishikim i kodit dhe teste lokale mbi ndryshimet pas commit-it `8f171a6`, më 14 nëntor 2026. Përdoruesi çaktivizoi shprehimisht skill-in Cloudflare gjatë punës; kërkesa u hoq nga `AGENTS.md` dhe workflow-i i atij skill-i u ndal. Korrigjimet vazhduan me rishikim normal dhe teste regresioni. Ky dokument nuk është certifikim i mungesës së vulnerabiliteteve ose përfundim i workflow-it të ndërprerë.

## Çfarë u gjet dhe u korrigjua

| Problemi | Prova / kufiri i gjetjes | Korrigjimi |
|---|---|---|
| Login konkurrues me reset-in e fjalëkalimit | Me llogari fiktive, një login i pezulluar pas verifikimit riktheu hash-in e vjetër dhe krijoi sesion pasi admini kishte bërë reset. | Përditësimi i autentikimit kushtëzohet nga hash-i aktual dhe llogaria e aktivizuar. Krijimi i sesionit kontrollon përsëri hash-in e verifikuar brenda një transaksioni shkrimi. Reset-i fiton në të dy intervalet konkurruese. Numëruesit e dështimeve përditësohen atomikisht. |
| Rrugë alternative për aplikacione të mbrojtura | Në DB fiktive, Operator merrte 403 në editorin normal, por discovery sipas emrit ndryshonte rrjetet dhe worker-i shtonte dependency sistem. Nuk pati publikim në production. | Kontrollet e objektit zbatohen në catalog/custom/HAR, në helper-at e ruajtjes, në dependency review dhe në approval. Worker-i kontrollon rolin aktual dhe statusin e llogarisë; approval i kontrollon bashkë me mutacionin në një transaksion. |
| Ndryshim anëtarësie i profilit të mbrojtur nga editorë të tjerë | Ndryshimi i marrëdhënieve nga një aplikacion/rregull mund të anashkalonte editorin e profilit. | Një kontroll i përbashkët kërkon Admin për shtim/heqje anëtarësie të profileve të mbrojtura. Anëtarësitë e pandryshuara ruhen. |
| Dependency review jashtë bllokimit të politikave | Router-i nuk përdorte të njëjtin policy guard si editorët e tjerë. Nuk u pretendua publikim real i paautorizuar. | Mutacionet e këtij router-i serializohen me editorët dhe publikimin. Testi mban një writer aktiv dhe verifikon që kërkesa tjetër pret. |
| Domain-e HAR pa normalizim të plotë | Hostname pasiv mund të ruhej si kandidat dhe të hynte në rules pa validimin që priste generatori. | Hostname normalizohet gjatë leximit; kandidatët normalizohen gjatë ruajtjes dhe përsëri gjatë approval. Kandidat i vjetër i pavlefshëm refuzohet pa ndryshuar rules. Nuk u gjet/provua ekzekutim komande ose injektim në Squid. |
| Punë e jashtme discovery brenda kërkesës/bllokimit | Fetch/parsing i burimeve gjenerike ndodhte gjatë ruajtjes. Shkallëzimi i dyshuar i regex-it dhe një DoS production nuk u demonstrua. | Discovery i GUI-së futet në radhë të veçantë dhe përpunohet jashtë policy lock. Tokenizimi i hostname-ve është linear dhe token-et mbi gjatësinë e lejuar refuzohen. HTTP ka deadline të përbashkët për redirect-et dhe mbyllje të lidhjes kur skadon. DNS mbetet përgjegjësi e resolver-it/timeout-it të worker-it. |
| Lejet e përkohshme të arkivit të eksportit | Në fixture të vogël me umask 022, faza e vjetër krijonte 0644 dhe më pas vendoste 0600. Ekspozimi kërkonte destinacion të përbashkët; `/root` e mbronte rastin default. | Arkivi krijohet në inode të ri privat 0600 përpara shkrimit dhe publikohet me replace atomik. Një symlink ekzistues i output-it zëvendësohet pa shkruar mbi skedarin ku ai tregonte. |
| Rollback upgrade me snapshot të hershëm | Burimi merrte backup përpara instalimit të dependencies/shadow validation dhe e përdorte pas dështimit. Ndryshime të kredencialeve gjatë këtij intervali mund të humbnin. | Pas ndalimit dhe kontrollit të writer-ave merret snapshot i ri `cutover.db`. Vetëm ai përdoret në rollback pas mutacionit të DB-së; sesionet pastrohen. Testi ruan një reset të bërë pas backup-it të hershëm. Upgrade real i host-it nuk u ekzekutua. |
| Besimi te backup-i lokal Windows | Restore përdorte Path/Name nga JSON; ACL-të e vjetra nuk zëvendësonin çdo ACE eksplicit. Kushtet reale të precreation/ACL nuk u provuan në një PC pilot. | Restore pranon vetëm dhjetë çiftet e njohura registry dhe identitetin e këtij kompjuteri. Mutacionet kontrollojnë owner/permissions/reparse paths përpara përdorimit të state-it; ACL-të e direktorive rindërtohen shprehimisht. Kjo është masë mbrojtëse; nuk paraqitet si provë e një ngritjeje privilegjesh të realizuar. |
| “Add access” dhe default-et FastAPI | Thirrja direkte e një route-i linte objekte Form në `client_ip`/`window_minutes`; SQLite nuk i pranonte pas një ruajtjeje të pjesshme. | Kalohen vlera konkrete. Regresioni përdor krijimin real të run-it në SQLite dhe nuk mock-on `create_run`. |
| PAC i gabuar pas restore mes VM-ve | Importohej `pac_endpoint` i VM-së burimore, megjithëse lidhja e target-it duhej të mbetej lokale. | Restore ruan `pac_endpoint` dhe `connection_policy` të target-it. Kur target-i nuk ka endpoint të ruajtur, hiqet ai i importuar dhe përdoret default-i lokal. Testohen edhe URL-të në paketën Windows dhe Edge JSON. |

## Migrimi dhe sjellja e ruajtur

Migrimi `018` shton vetëm shënimin `queued` te discovery runs dhe indeksin përkatës. Run-et e vjetra browser që janë ende në punë kalojnë në radhë; worker-i nuk merr punët sinkrone të source-sync. Politikat, VLAN-et, profilet, përdoruesit dhe endpoint-i PAC ekzistues ruhen gjatë upgrade-it normal. Asnjë menu e re, kredencial ose kanal njoftimi nuk aktivizohet automatikisht.

## Verifikimi

Paketa përfundimtare lokale kaloi **92 teste**, pa anashkalime, përfshirë kontratat Node. Matrica e endpoint-eve kreu **571 kontrolle** rolesh/CSRF/aksesi anonim. Rezultati është provë e sjelljeve të testuara, jo deklaratë se çdo skenar i mundshëm është kontrolluar.

Paketa `tests/smoke_v3127.py` përfshin testet ekzistuese dhe regresionet e reja për kredencialet, lejet, serializimin, queue/migration, importin, eksportin dhe restore/rollback. Testet përdorin DB dhe llogari fiktive, transporte të jashtme të mock-uara dhe loopback lokal për kontratat ekzistuese SNMP/proxy. Nuk u përdor VM-ja ose marrës real email/Slack/NMS.

`tests/windows_backup_contract.ps1` ekzekuton vetëm validatorin e pastër të të dhënave të backup-it; nuk ngarkon dispatch-in dhe nuk ndryshon registry, ACL ose elevation. Testi kaloi në Windows PowerShell 5.1. CI kontrollon paketën në Python 3.12/3.14, kontratat Node, migrimet, browser regression, syntax, dependencies dhe checksums.

## Çfarë duhet provuar në pilot

- Upgrade në VM: shërbimet aktive nginx/Squid/systemd, schema 018 dhe rifillimi i worker-it; krahasim i profileve/VLAN-eve/PAC përpara/pas.
- Windows: instalimi/update dhe uninstall në një PC pilot me Windows PowerShell 5.1, ACL-të reale dhe GPO/MDM. State i vjetër me owner ose leje të pasigurta refuzohet; admini duhet ta inspektojë përpara riparimit të owner/lejeve. Testet nuk instaluan controller-in në PC-në e përdoruesit.
- PAC/DIRECT gjatë ndërprerjes së VM-së, DNS/rrugët drejt AD dhe egress direkt në router; këto varen nga rrjeti dhe politikat e klientëve.
- Marrja reale e email/Slack/traps dhe polling SNMP në destinacionet e konfiguruara.

Kontrollet automatike nuk provojnë sigurinë e konfigurimit aktiv të një host-i që nuk është aksesuar. Workflow-i Cloudflare mbetet i çaktivizuar sipas kërkesës së përdoruesit.

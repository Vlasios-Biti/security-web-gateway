# Kontrolli i detajuar funksional — 3.12.6

Kontroll lokal më 2026-11-14 mbi versionin e ndryshuar pas `0c53eba`. Ky dokument përshkruan sjelljen e kodit dhe testet me të dhëna fiktive. VM-ja, kompjuterët realë, router-i, AD dhe marrësit realë të njoftimeve nuk u testuan.

## Provat dhe shtrirja

- 77 teste të mbledhura: 75 kaluan, 2 u anashkaluan sepse Node mungon në runtime-in lokal Linux. CI vazhdon të ekzekutojë kontratat Node.
- 116 endpoint-e të deklaruara në router-a; 571 kombinime kërkese/roli/CSRF/akses anonim. Login POST dhe simulator POST kanë teste të dedikuara dhe nuk përfshihen në matricën e refuzimit CSRF.
- 405 funksione në `app/`; 314 me të paktën një rresht trupi të ekzekutuar. Inventari i plotë: [FUNCTION_CATALOG.md](FUNCTION_CATALOG.md).
- Mbulimi i rreshtave të ekzekutueshëm: 68.8% (3442/5001); mbulimi i degëve: 55.0% (930/1690). Kjo mat ekzekutimin, jo korrektësinë e çdo funksioni.
- Testet u ekzekutuan pa internet në namespace të veçantë, vetëm loopback lokal, si UID/GID 65534, pa grupe shtesë, me mjedis të pastër, burim/runtime vetëm për lexim dhe shkrime vetëm në scratch. Kufijtë: 1 CPU, 180 s CPU, 2 GiB RAM, 128 procese, 32 MiB/skedar, 512 MiB scratch dhe 300 s kohë reale.
- Rezultatet u mbajtën jashtë repository-t me kopjim të kufizuar, pa ndjekur symlink-e. Nuk u dërguan email/Slack/traps drejt marrësve realë; testi SNMP përdor loopback.

## Kontrolli sipas funksionalitetit

| Pjesa | Çfarë u verifikua | Kufiri praktik |
|---|---|---|
| Login, përdoruesit dhe rolet | Argon2, lockout, cookie secure, logout, revokimi i sesioneve, CSRF, admin/operator/viewer/auditor, ndryshime konkurruese të adminëve | Nuk ka autentikim me përdorues/grupe AD ose SSO |
| Profiles & VLANs | Krijim në një transaksion, ruajtje e inputit kur dështon, copy, delete, rrjete të përdorura dhe zgjedhje ekskluzive profile/VLAN | VLAN ID është etiketë; Squid zbaton rrjetin CIDR |
| Access: aplikacione, domain dhe IP | Ruajtje e thjeshtë, scope, rregulla sistem/custom, protokolle dhe të dhëna Google pa caktim automatik | Ruajtja e domain-it nuk pret DNS; Squid bën zgjidhjen kur përpunon trafikun |
| Discovery dhe veprimet pas login/klikimit | HAR dhe kapje e skedës për review, heqje e sekreteve, kufij importi, izolimi i proxy-t të discovery | Skanimi automatik nuk garanton çdo veprim të mundshëm. Korrelacioni nga IP nuk provon se cili aplikacion e nisi kërkesën |
| Save/Apply, expiry dhe rollback | Dështim publikimi, punë pending, ndryshime konkurruese, skadim pa publikuar punë të tjera, ruajtja e historikut | Helper-i real root, Squid reload dhe shërbimet e VM-së kërkojnë kontroll në instalim |
| Connection, PAC, bypass dhe Windows | Adresë e përbashkët PAC, HTTPS PAC, paketë Windows, ruajtje switch-esh dhe konfigurim fail-open | DIRECT kërkon DNS/router/Internet të pavarur. Dështimi i VM-së nuk mund të anashkalojë bllokim në firewall ose mungesë rruge direkte |
| Certifikatat TLS | Përputhje key/cert/hostname, skadim, validim dhe rollback i reload-it me fixture | Besimi i CA-së në PC dhe rrugët reale nginx duhen verifikuar në VM |
| Trafiku dhe PC activity | Source IP, filtra, pagination, emra DNS në background, historik për IP, izolimi i eksportit dhe timestamp/VLAN i filtruar | NAT bashkon PC-të; DHCP mund të ndryshojë pronarin. HTTPS CONNECT tregon domain/port, jo përmbajtjen e enkriptuar. DIRECT nuk shfaqet në Squid |
| Eksport CSV/XLSX | Formulat mbeten tekst dhe XML nuk prishet nga karaktere kontrolli | CSV i ndryshuar nga programe të tjera duhet inspektuar para riimportit |
| Health, email dhe Slack | Pragje të përbashkëta, stale samples, dedup, recovery, retry, sekretet e maskuara, kategori dhe mention-e Slack | Dorëzimi real kërkon SMTP/webhook të konfiguruar dhe test të autorizuar nga GUI |
| SNMP polling dhe traps | Read-only, filtër burimi dhe trap lokal | SNMPv2c; nuk ka SNMPv3. Duhet kufizuar me rrjet/firewall dhe community të përshtatshme |
| Backup/restore dhe storage | Arkiv me anëtarë të rregullt, refuzim link-esh, checksum legacy, retention dhe pragje hapësire | Restore i plotë, lejet e host-it dhe rikuperimi i VM-së nuk u ekzekutuan |
| Instalimi dhe përditësimi | Krahasim source i payload-it install/upgrade dhe i moduleve që ngarkon helper-i | Instaluesi nuk u nis: do të ndryshonte host-in dhe do të shkarkonte paketa |
| GUI dhe navigimi | Renderim i faqeve në matricën e roleve dhe ruajtja e rrjedhës së unifikuar | Nuk u bë inspektim i ri vizual me browser gjatë kësaj pakete të izoluar |

## Korrigjimet e këtij kontrolli

1. Activity GET nuk pastron më flags pending gjatë leximit; viewer/auditor mund ta lexojnë, ndërsa publikimi mbetet vetëm admin.
2. Ndryshimet konkurruese të adminëve serializohen para kontrollit të adminit të fundit.
3. Hash i dëmtuar i fjalëkalimit refuzohet si login i pasuksesshëm, pa HTTP 500.
4. Filtra të pavlefshëm trafiku kthejnë HTTP 400, përfshirë ID mbi kufirin SQLite, IP/port/data dhe interval të përmbysur.
5. Krijimi/ndryshimi i domain-it nuk bllokohet nga DNS i jashtëm.
6. Profile i fshirë nuk riaktivizohet nga endpoint-i i statusit.
7. XLSX pastron karakteret që nuk lejohen në XML.
8. Importi i ri HAR lexon vetëm kufirin + 1 byte dhe refuzon tepricën përpara krijimit të aplikacionit.
9. Instalimi i ri kopjon edhe `privileged`, që moduli i rinovimit TLS të jetë në release-in aktiv njësoj si në upgrade.
10. Activity dallon tentativën e fundit nga baseline-i i fundit i suksesshëm; një publikim i dështuar nuk paraqitet si pikë e suksesshme rikuperimi.

## Security-audit skill

U lexua skill-i i instaluar [Cloudflare security-audit](https://github.com/cloudflare/security-audit-skill). Preferenca ruhet te `AGENTS.md`. Për këtë punë u përdorën rregullat e provave, kufijtë e ekzekutimit dhe reconnaissance me katër kontrolle të veçanta source. Kontrolli funksional dhe korrigjimet janë punë implementimi të autorizuara veçmas.

Kjo **nuk është një përfundim i auditimit të plotë të sigurisë**: hunting me ledger, kritikët e mbulimit dhe verifikimi i pavarur i çdo gjetjeje nuk u përfunduan. Run-i fillestar i auditimit shënohet `incomplete`; asnjë pretendim vulnerabiliteti nuk publikohet si i konfirmuar. Nuk ka ledger të mëparshëm të pajtueshëm. Kalimi i testeve nuk provon mungesën e vulnerabiliteteve.

## Çfarë mbetet për pranim në ambient

Në një PC pilot: shpërndarja/refresh i PAC me GPO ose installer, bypass i domain-it të brendshëm, komunikimi normal me AD/DNS dhe DIRECT gjatë ndërprerjes së VM-së. Në VM: konfigurimi aktiv nginx/Squid/systemd, lejet e socket-it dhe skedarëve, certifikatat, log-et me source IP të papërkthyer dhe backup/restore. Në sistemin e monitorimit: polling/traps SNMP dhe marrja reale e njoftimeve të konfiguruara. Këto nuk mund të deklarohen të kaluara nga source ose mocks.

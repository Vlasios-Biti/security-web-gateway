Proxy Control v1.3.1
==================================

Installed GUI:
C:\Program Files\Security Web Gateway\Proxy Control\Proxy-Control.exe

Start Menu:
Proxy Control
  -> Proxy Control

The GUI contains:
- STATUS
- START SWG
- STOP SWG
- REFRESH
- UNINSTALL

Status is readable by a standard Windows user.
Start/Stop/Uninstall require Windows Administrator credentials through UAC.

PAC:
http://10.100.254.13:8081/proxy.pac

When ENABLED:
- PAC is machine-wide.
- Standard user cannot change proxy/PAC settings.
- Manual proxy is OFF.
- WPAD/automatic detection is disabled.

When STOPPED:
- PAC is removed.
- Internet is DIRECT.
- Proxy settings remain locked from standard users.

Server-side fail-open remains controlled by PAC:
PROXY 10.100.254.13:3128; DIRECT

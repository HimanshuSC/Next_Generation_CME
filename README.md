# Next_Generation_CME
NXT GEN Network Checker (nxt_gen_nxc) is a Python-based network scanner supporting SMB, SSH, RDP, FTP, NFS, WMI, MSSQL, LDAP, VNC, and WinRM. It enumerates SMB shares with READ/WRITE permissions, checks service authentication, and provides clear, structured output for security assessments

# HELP MENU
$ python nxt_gen_cme.py --help                                                     

███╗   ██╗██╗  ██╗████████╗     ██████╗ ███████╗███╗   ██╗
████╗  ██║██║  ██║╚══██╔══╝    ██╔════╝ ██╔════╝████╗  ██║
██╔██╗ ██║   ██║     ██║       ██║  ███╗█████╗  ██╔██╗ ██║
██║╚██╗██║██╔══██║   ██║       ██║   ██║██╔══╝  ██║╚██╗██║
██║ ╚████║██║  ██║   ██║       ╚██████╔╝███████╗██║ ╚████║
╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝        ╚═════╝ ╚══════╝╚═╝  ╚═══╝
          NXT GEN Network Checker (v2.0)

usage: nxt_gen_cme.py [-h] [-u USERNAME] [-p PASSWORD] [--all] protocol target

nxt_gen_nxc - safe scanner

positional arguments:
  protocol              Protocol to check (smb, ssh, rdp, ftp, nfs, wmi, mssql, ldap, vnc, winrm, all)
  target                Target IP or domain

options:
  -h, --help            show this help message and exit
  -u, --username USERNAME
                        Username for authentication
  -p, --password PASSWORD
                        Password for authentication
  --all                 Run all checks



We can check all the protools by providing --all flag in the command

$ python nxt_gen_cme.py smb 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' --all 

███╗   ██╗██╗  ██╗████████╗     ██████╗ ███████╗███╗   ██╗
████╗  ██║██║  ██║╚══██╔══╝    ██╔════╝ ██╔════╝████╗  ██║
██╔██╗ ██║   ██║     ██║       ██║  ███╗█████╗  ██╔██╗ ██║
██║╚██╗██║██╔══██║   ██║       ██║   ██║██╔══╝  ██║╚██╗██║
██║ ╚████║██║  ██║   ██║       ╚██████╔╝███████╗██║ ╚████║
╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝        ╚═════╝ ╚══════╝╚═╝  ╚═══╝
          NXT GEN Network Checker (v2.0)

SMB         10.10.11.35    445    CICADA-DC         [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:CICADA) (signing:True) (dialect:SMBv3.0)
SMB         10.10.11.35    445    CICADA-DC         [+] CICADA\emily.oscars:<PASSWORD>
SMB         10.10.11.35    445    CICADA-DC         [*] Enumerated shares
SMB         10.10.11.35    445    CICADA-DC         Share           Permissions     Remark
SMB         10.10.11.35    445    CICADA-DC         -----           -----------     ------
SMB         10.10.11.35    445    CICADA-DC         ADMIN$         READ           
SMB         10.10.11.35    445    CICADA-DC         C$             READ           
SMB         10.10.11.35    445    CICADA-DC         DEV            ACCESS_DENIED  
SMB         10.10.11.35    445    CICADA-DC         HR             READ           
SMB         10.10.11.35    445    CICADA-DC         NETLOGON       READ           
SMB         10.10.11.35    445    CICADA-DC         SYSVOL         READ           
SSH         10.10.11.35    22     10.10.11.35       [-] SSH login failed: timed out
RDP         10.10.11.35    3389   10.10.11.35       [-] RDP port closed/unreachable: timed out
FTP         10.10.11.35    21     10.10.11.35       [-] FTP failed: timed out
NFS         10.10.11.35    2049   10.10.11.35       [-] NFS port unreachable: timed out
WMI         10.10.11.35    135    10.10.11.35       [*] RPC (135) reachable — WMI may be available (impacket WMI not used)
MSSQL       10.10.11.35    1433   10.10.11.35       [-] MSSQL TCP failed: timed out
LDAP        10.10.11.35    389    10.10.11.35       [-] LDAP bind failed: automatic bind not successful - invalidCredentials
VNC         10.10.11.35    5900   10.10.11.35       [-] VNC TCP failed: timed out
WINRM       10.10.11.35    5985   10.10.11.35       [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
                                                                                                          

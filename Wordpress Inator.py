import os
import re
import json
import time
import subprocess
import datetime
import sys
import hashlib
import argparse

# ================= CONFIGURATION =================
WAIT_MINUTES = 3
MAX_CONTEXT_HOPS = 1
MIN_SCORE_THRESHOLD = 50

# Filenames
REPORT_FILENAME = "final_security_report.md"
VULN_FILENAME = "CONFIRMED_VULNERABILITIES.md"
SCAN_DB_FILE = "scan_results_temp.json"
PROGRESS_FILE = "audit_progress.json"

# Global Ignore Lists
FILES_TO_IGNORE = {'.css', '.js', '.png', '.jpg', '.svg', '.html', '.txt', '.md', '.json', '.po', '.mo', '.lock'}
DIRS_TO_IGNORE = {'.git', 'node_modules', 'vendor', 'tests', 'assets', 'images', 'dist', 'lang', 'docs', '.idea', '.vscode'}

# Context Exclusions
CONTEXT_EXCLUSIONS = {
    "cli": {"RCE_CRITICAL", "RCE_CALLBACK"}, 
    "bin": {"RCE_CRITICAL", "RCE_CALLBACK"},
    "install.php": {"SQL_INJECTION_RAW"}, 
    "upgrade.php": {"SQL_INJECTION_RAW"},
    "importer": {"PHP_OBJECT_INJECTION", "ARBITRARY_FILE_UPLOAD"},
    "logger": {"ARBITRARY_FILE_UPLOAD"}, 
    "logs": {"ARBITRARY_FILE_UPLOAD"}
}

# ================= COLORS =================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# ================= SCANNER PATTERNS (WORDFENCE BOUNTY OPTIMIZED) =================
PATTERNS = {
    # --- CRITICAL / HIGH PAYOUT ---
    "RCE_CRITICAL": { 
        "regex": r"(system|exec|passthru|shell_exec|eval|assert|proc_open|popen|pcntl_exec)\s*\(", 
        "score": 100, 
        "desc": "Direct Remote Code Execution (RCE)" 
    },
    "SQL_INJECTION_RAW": { 
        "regex": r"\$wpdb->(query|get_results|get_row|get_var|get_col|update|insert|delete|replace)", 
        "score": 95, 
        "desc": "Direct Database Access (SQLi)" 
    },
    "PHP_OBJECT_INJECTION": { 
        "regex": r"(unserialize|maybe_unserialize)\s*\(", 
        "score": 95, 
        "desc": "Insecure Deserialization (Object Injection)" 
    },
    "BROKEN_ACCESS_CONTROL": {
        # Looks for AJAX actions that grab POST data but might lack permission checks (AI will verify)
        "regex": r"add_action\s*\(\s*['\"]wp_ajax_(nopriv_)?", 
        "score": 90, 
        "desc": "Potential Missing Authorization in AJAX Handler" 
    },
    "ARBITRARY_FILE_UPLOAD": { 
        "regex": r"(move_uploaded_file|wp_handle_upload|wp_handle_sideload|fwrite|file_put_contents)\s*\(", 
        "score": 90, 
        "desc": "File Write/Upload logic" 
    },
    "LFI_RFI": { 
        "regex": r"(include|require|include_once|require_once)\s*\(?\s*\$_(GET|POST|REQUEST)", 
        "score": 90, 
        "desc": "Local/Remote File Inclusion (LFI/RFI)" 
    },

    # --- MEDIUM / COMMON PAYOUT ---
    "XSS_REFLECTION": { 
        "regex": r"(echo|print|printf|vprintf)\s+[^;]*\$", 
        "score": 80, 
        "desc": "Potential Reflected XSS (Outputting variables)" 
    },
    "CSRF_MISSING_NONCE": {
        # Looks for processing POST data. AI checks if check_admin_referer/wp_verify_nonce is missing.
        "regex": r"\$_POST\s*\[", 
        "score": 75, 
        "desc": "Potential CSRF (Processing POST data)" 
    },
    "IDOR_SUSPICION": { 
        "regex": r"\$_(POST|GET|REQUEST)\[['\"]?.*(id|ID|Id|user|post|order|key)['\"]?\]", 
        "score": 75, 
        "desc": "IDOR: Input Variable likely used as an Object Identifier" 
    },
    "SSRF_REQUEST": { 
        "regex": r"(wp_remote_get|wp_remote_post|curl_exec|file_get_contents|fsockopen)\s*\(", 
        "score": 70, 
        "desc": "Server-Side Request Forgery (SSRF) Sink" 
    },
    "OPEN_REDIRECT": {
        "regex": r"wp_redirect\s*\(\s*\$_(GET|POST|REQUEST)", 
        "score": 65, 
        "desc": "Open Redirect (User controlled redirect)"
    },

    # --- LOWER PRIORITY / MANUAL REVIEW ---
    "SENSITIVE_DATA": {
        "regex": r"(AWS_ACCESS_KEY|API_KEY|private_key|secret_token|password|auth_token)",
        "score": 60,
        "desc": "Hardcoded Secrets or Tokens"
    },
    "RCE_CALLBACK": { 
        "regex": r"(call_user_func|call_user_func_array|array_map|array_walk|usort|preg_replace_callback)\s*\(", 
        "score": 60, 
        "desc": "Unsafe Callback / Function Injection" 
    },
}

class AutoAuditor:
    def __init__(self, target_dir, filter_type=None):
        self.target_dir = os.path.abspath(target_dir)
        self.filter_type = filter_type.upper() if filter_type else None
        self.findings = []
        self.completed_ids = set()
        
        # Paths
        self.report_path = os.path.join(self.target_dir, REPORT_FILENAME)
        self.vuln_path = os.path.join(self.target_dir, VULN_FILENAME)
        self.scan_db_path = os.path.join(self.target_dir, SCAN_DB_FILE)
        self.progress_path = os.path.join(self.target_dir, PROGRESS_FILE)

        os.system('') # Init colors
        
        if not os.path.exists(self.target_dir):
            print(f"{Colors.RED}[!] Error: Directory '{self.target_dir}' does not exist.{Colors.RESET}")
            sys.exit(1)

    def generate_id(self, finding):
        unique_str = f"{finding['file']}:{finding['line']}:{finding['type']}"
        return hashlib.md5(unique_str.encode()).hexdigest()

    def load_progress(self):
        if os.path.exists(self.scan_db_path) and os.path.exists(self.progress_path):
            print(f"{Colors.CYAN}[?] Found previous session data in target folder.{Colors.RESET}")
            choice = input(f"    Do you want to {Colors.BOLD}RESUME{Colors.RESET} from where you left off? (y/n): ").strip().lower()
            if choice == 'y':
                with open(self.scan_db_path, 'r') as f:
                    self.findings = json.load(f)
                with open(self.progress_path, 'r') as f:
                    self.completed_ids = set(json.load(f))
                print(f"{Colors.GREEN}[*] Resumed. {len(self.findings)} total findings, {len(self.completed_ids)} already finished.{Colors.RESET}")
                return True
        return False

    def scan_files(self):
        if self.load_progress():
            return

        print(f"{Colors.BLUE}[*] Phase 1: Scanning directory: {self.target_dir}{Colors.RESET}")
        if self.filter_type:
            print(f"{Colors.YELLOW}[*] FILTER ACTIVE: Scanning only for '{self.filter_type}' vulnerabilities.{Colors.RESET}")

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in DIRS_TO_IGNORE]
            for file in files:
                if any(file.endswith(ext) for ext in FILES_TO_IGNORE): continue
                if file in [REPORT_FILENAME, VULN_FILENAME, SCAN_DB_FILE, PROGRESS_FILE]: continue
                
                self._analyze_file_content(os.path.join(root, file))
        
        self.findings.sort(key=lambda x: x['score'], reverse=True)
        
        with open(self.scan_db_path, "w") as f:
            json.dump(self.findings, f, indent=4)
        with open(self.progress_path, "w") as f:
            json.dump([], f)
            
        print(f"{Colors.GREEN}[*] Scan complete. Found {len(self.findings)} potential hotspots.{Colors.RESET}")
        print(f"{Colors.CYAN}[i] Results saved to: {self.scan_db_path}{Colors.RESET}")
        
        if self.findings:
            print(f"\n{Colors.BOLD}--- TOP FINDINGS (SORTED BY SEVERITY) ---{Colors.RESET}")
            for f in self.findings[:5]:
                c = Colors.RED if f['score'] >= 90 else Colors.YELLOW
                print(f"{c}[{f['score']}/100] {f['type']}{Colors.RESET} in {os.path.basename(f['file'])}:{f['line']}")
            if len(self.findings) > 5:
                print(f"... and {len(self.findings) - 5} more.")
            print("-----------------------------------------\n")
        else:
            print(f"\n{Colors.GREEN}[!] No vulnerabilities found matching your criteria.{Colors.RESET}\n")

    def _analyze_file_content(self, filepath):
        try:
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()
        except: return

        rel_path = os.path.relpath(filepath, self.target_dir).replace("\\", "/")
        ignore_types_for_this_file = set()
        for path_key, ignored_types in CONTEXT_EXCLUSIONS.items():
            if path_key in rel_path.split("/") or path_key in rel_path:
                ignore_types_for_this_file.update(ignored_types)

        file_risk_bonus = 0
        file_content_str = "".join(lines)
        if "wp_ajax_nopriv_" in file_content_str:
            file_risk_bonus = 10 

        for i, line in enumerate(lines):
            line_clean = line.strip()
            if not line_clean or line_clean.startswith(("//", "*", "#")): continue

            for type_key, data in PATTERNS.items():
                if self.filter_type:
                    if self.filter_type not in type_key and self.filter_type not in data['desc'].upper():
                        continue
                if type_key in ignore_types_for_this_file: continue

                if re.search(data['regex'], line_clean):
                    current_score = data['score'] + file_risk_bonus
                    
                    # Heuristics to refine score
                    if "$" in line_clean: current_score += 10
                    if any(x in line_clean for x in ["$_POST", "$_GET", "$_REQUEST"]): current_score += 15
                    
                    # Reduce score for sanitation/nonces
                    if any(x in line_clean for x in ["esc_html", "esc_attr", "wp_kses", "absint", "(int)", "wp_verify_nonce", "check_admin_referer"]): 
                        current_score -= 20
                    
                    # Prepare is good for SQLi
                    if type_key == "SQL_INJECTION_RAW" and "prepare" in line_clean: current_score -= 50
                    
                    final_score = max(0, min(100, current_score))
                    if final_score < 40: continue

                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    snippet = "".join(lines[start:end])

                    self.findings.append({
                        "file": filepath,
                        "line": i + 1,
                        "type": type_key,
                        "desc": data['desc'],
                        "score": final_score,
                        "snippet": snippet.strip()
                    })

    def run_audits(self):
        targets = [f for f in self.findings if f['score'] >= MIN_SCORE_THRESHOLD]
        targets.sort(key=lambda x: x['score'], reverse=True)

        remaining_targets = []
        for t in targets:
            tid = self.generate_id(t)
            if tid not in self.completed_ids:
                t['_id'] = tid
                remaining_targets.append(t)
        
        if not remaining_targets:
            print(f"{Colors.GREEN}[*] All targets audited.{Colors.RESET}")
            return

        print(f"{Colors.BLUE}[*] Phase 2: AI Deep Audit on {len(remaining_targets)} targets.{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Speed Limit: 1 audit every {WAIT_MINUTES} minutes.{Colors.RESET}")

        with open(self.report_path, "a") as f:
            f.write(f"\n\n# --- SESSION START ({datetime.datetime.now()}) ---\n")
            f.write(f"Target: {self.target_dir}\n")
        
        if not os.path.exists(self.vuln_path):
            with open(self.vuln_path, "w") as f:
                f.write("# CONFIRMED VULNERABILITIES\nThis file contains only issues confirmed by the AI.\n\n")

        for idx, finding in enumerate(remaining_targets):
            print(f"[{idx+1}/{len(remaining_targets)}] Auditing {os.path.basename(finding['file'])} (Line {finding['line']}) [Score: {finding['score']}]...")
            
            final_response = self._run_deep_audit_loop(finding)
            
            if "limit reached" in final_response.lower():
                print(f"\n{Colors.RED}[!] CRITICAL: Rate limit detected. Stopping.{Colors.RESET}")
                break

            self._process_verdict(finding, final_response)
            self._mark_as_complete(finding['_id'])
            
            if idx < len(remaining_targets) - 1:
                self._do_countdown()

    def _process_verdict(self, finding, response):
        with open(self.report_path, "a") as f:
            f.write(f"## [{finding['type']}] {finding['file']}:{finding['line']}\n")
            f.write(f"**Score:** {finding['score']}/100\n\n")
            f.write(f"### AI Analysis:\n{response}\n")
            f.write(f"\n---\n")

        verdict_color = Colors.YELLOW
        verdict_text = "MANUAL REVIEW REQUIRED"
        
        if "VERDICT: VULNERABLE" in response:
            verdict_color = Colors.RED
            verdict_text = "!!! VULNERABLE !!!"
            with open(self.vuln_path, "a") as f:
                f.write(f"## {finding['type']} in {finding['file']}:{finding['line']}\n")
                f.write(f"{response}\n\n---\n")
                
        elif "VERDICT: SAFE" in response:
            verdict_color = Colors.GREEN
            verdict_text = "SAFE / MITIGATED"

        print(f"   > Verdict: {verdict_color}{verdict_text}{Colors.RESET}")

    def _run_deep_audit_loop(self, finding):
        conversation_history = f"""
        [ROLE] Security Researcher
        [TASK] Analyze this code for False Positives.
        
        [CODE]
        File: {finding['file']}
        Line: {finding['line']}
        Found: {finding['type']}
        Snippet:
        ```php
        {finding['snippet']}
        ```
        
        [INSTRUCTION]
        1. If finding is 'BROKEN_ACCESS_CONTROL', check if the registered AJAX hook actually checks capabilities (current_user_can) in the snippet or called function.
        2. If finding is 'CSRF_MISSING_NONCE', check if a nonce verification exists nearby.
        3. If you need to see a function definition in another file, reply ONLY with:
           READ: path/to/file.php
        
        4. If you have enough info, you MUST start your final response with one of these exact headers:
           VERDICT: VULNERABLE
           VERDICT: SAFE
           VERDICT: MANUAL_REVIEW
           
           Then provide your explanation.
        """

        current_hop = 0
        while current_hop <= MAX_CONTEXT_HOPS:
            response = self._send_to_claude(conversation_history)
            
            match = re.search(r"READ:\s*(\S+)", response)
            if match and current_hop < MAX_CONTEXT_HOPS:
                requested_path = match.group(1).strip()
                full_request_path = os.path.join(self.target_dir, requested_path)
                
                if not os.path.exists(full_request_path):
                    file_dir = os.path.dirname(finding['file'])
                    full_request_path = os.path.join(file_dir, requested_path)

                print(f"   {Colors.CYAN}-> Agent requested file: {os.path.basename(requested_path)}{Colors.RESET}")
                file_content = self._read_file_safe(full_request_path)
                
                conversation_history += f"\n\n[AGENT REQUEST]: READ {requested_path}\n"
                conversation_history += f"[SYSTEM]: Content:\n```php\n{file_content}\n```\n"
                conversation_history += "\n[INSTRUCTION]: Analyze the original vulnerability with this new context."
                
                current_hop += 1
                time.sleep(2) 
            else:
                return response
        return response

    def _read_file_safe(self, filepath):
        if not os.path.exists(filepath): return "ERROR: File not found."
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                if len(content) > 10000: return content[:10000] + "\n...[TRUNCATED]..."
                return content
        except Exception as e: return f"ERROR: Could not read file. {str(e)}"

    def _send_to_claude(self, full_prompt):
        try:
            process = subprocess.Popen(
                ["claude"], 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=full_prompt)
            if stderr and "Error" in stderr: return f"CLI Error: {stderr}"
            return stdout
        except Exception as e: return f"Script Error: {str(e)}"

    def _mark_as_complete(self, finding_id):
        self.completed_ids.add(finding_id)
        with open(self.progress_path, "w") as f:
            json.dump(list(self.completed_ids), f)

    def _do_countdown(self):
        print(f"   Cooling down for {WAIT_MINUTES} mins...")
        for m in range(WAIT_MINUTES * 60, 0, -1):
            sys.stdout.write(f"\r   Next request in: {m} seconds   ")
            sys.stdout.flush()
            time.sleep(1)
        print("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WordPress Security Auto-Auditor")
    parser.add_argument("target", nargs="?", help="Path to the WordPress plugin folder")
    parser.add_argument("--type", help="Filter by vulnerability type (e.g. 'SQL', 'RCE', 'XSS', 'PRIV')")
    args = parser.parse_args()

    target_path = args.target
    if not target_path:
        target_path = input("Enter the path to the WordPress plugin folder: ").strip()

    app = AutoAuditor(target_path, filter_type=args.type)
    app.scan_files()
    app.run_audits()
    print(f"\n{Colors.GREEN}[+] All audits finished.{Colors.RESET}")
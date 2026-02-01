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
WAIT_MINUTES = 0
MAX_CONTEXT_HOPS = 3  # Reduced from 5
MIN_SCORE_THRESHOLD = 50

# Filenames
REPORT_FILENAME = "final_security_report.md"
VULN_FILENAME = "CONFIRMED_VULNERABILITIES.md"
SCAN_DB_FILE = "scan_results_temp.json"
PROGRESS_FILE = "audit_progress.json"
PATTERN_CACHE_FILE = "known_safe_patterns.json"  # NEW: Pattern learning

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
    "logs": {"ARBITRARY_FILE_UPLOAD"},
    "data-store": {"SQL_INJECTION_RAW"},
    "abstract-": {"SQL_INJECTION_RAW"},
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

# ================= SCANNER PATTERNS =================
PATTERNS = {
    "RCE_CRITICAL": {
        "regex": r"(system|exec|passthru|shell_exec|eval|assert|proc_open|popen|pcntl_exec)\s*\(",
        "score": 100,
        "desc": "Direct Remote Code Execution (RCE)"
    },
    "SQL_INJECTION_RAW": {
        "regex": r"\$wpdb->(query|get_results|get_row|get_var|get_col)",
        "score": 95,
        "desc": "Direct Database Access (SQLi)"
    },
    "PHP_OBJECT_INJECTION": {
        "regex": r"(unserialize|maybe_unserialize)\s*\(",
        "score": 95,
        "desc": "Insecure Deserialization (Object Injection)"
    },
    "BROKEN_ACCESS_CONTROL": {
        "regex": r"add_action\s*\(\s*['\"]wp_ajax_(nopriv_)?",
        "score": 90,
        "desc": "Potential Missing Authorization in AJAX Handler"
    },
    "ARBITRARY_FILE_UPLOAD": {
        "regex": r"(move_uploaded_file|wp_handle_upload|wp_handle_sideload)\s*\(",
        "score": 90,
        "desc": "File Write/Upload logic"
    },
    "LFI_RFI": {
        "regex": r"(include|require|include_once|require_once)\s*\(?\s*\$_(GET|POST|REQUEST)",
        "score": 90,
        "desc": "Local/Remote File Inclusion (LFI/RFI)"
    },
    "XSS_REFLECTION": {
        "regex": r"(echo|print|printf|vprintf)\s+[^;]*\$",
        "score": 80,
        "desc": "Potential Reflected XSS (Outputting variables)"
    },
    "CSRF_MISSING_NONCE": {
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

# ================= TOKEN-EFFICIENT PATTERNS =================
KNOWN_SAFE_PATTERNS = {
    "meta_box_save": {
        "indicators": ["woocommerce_process_", "do_action(", "phpcs:disable"],
        "explanation": "WordPress meta box with upstream nonce verification"
    },
    "wpdb_safe_methods": {
        "indicators": ["$wpdb->insert(", "$wpdb->update(", "$wpdb->prepare("],
        "explanation": "WordPress database methods with built-in escaping"
    },
    "background_processing": {
        "indicators": ["WP_Async_Request", "check_ajax_referer", "wp_ajax_nopriv_"],
        "explanation": "Background processing library with nonce verification"
    },
    "capability_protected": {
        "indicators": ["current_user_can(", "manage_options", "edit_posts"],
        "explanation": "Protected by capability check"
    },
    "safe_unserialize": {
        "indicators": ["get_post_meta", "get_option", "get_transient"],
        "explanation": "Unserializing from WordPress internal storage"
    }
}

class AutoAuditor:
    def __init__(self, target_dir, filter_type=None):
        self.target_dir = os.path.abspath(target_dir)
        self.filter_type = filter_type.upper() if filter_type else None
        self.findings = []
        self.completed_ids = set()
        self.pattern_cache = {}  # Cache of known safe patterns

        # Paths
        self.report_path = os.path.join(self.target_dir, REPORT_FILENAME)
        self.vuln_path = os.path.join(self.target_dir, VULN_FILENAME)
        self.scan_db_path = os.path.join(self.target_dir, SCAN_DB_FILE)
        self.progress_path = os.path.join(self.target_dir, PROGRESS_FILE)
        self.cache_path = os.path.join(self.target_dir, PATTERN_CACHE_FILE)

        os.system('')

        if not os.path.exists(self.target_dir):
            print(f"{Colors.RED}[!] Error: Directory '{self.target_dir}' does not exist.{Colors.RESET}")
            sys.exit(1)

        # Load pattern cache
        self._load_pattern_cache()

    def _load_pattern_cache(self):
        """Load known safe patterns from previous scans"""
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, 'r') as f:
                    self.pattern_cache = json.load(f)
                print(f"{Colors.CYAN}[i] Loaded {len(self.pattern_cache)} cached patterns{Colors.RESET}")
            except: pass

    def _save_pattern_cache(self):
        """Save learned patterns for future scans"""
        try:
            with open(self.cache_path, 'w') as f:
                json.dump(self.pattern_cache, f, indent=2)
        except: pass

    def _check_known_pattern(self, finding, context_lines):
        """Check if this matches a known safe pattern (avoids AI call)"""
        context_str = "".join(context_lines).lower()

        for pattern_name, pattern_data in KNOWN_SAFE_PATTERNS.items():
            matches = sum(1 for indicator in pattern_data["indicators"] if indicator.lower() in context_str)
            if matches >= 2:  # Need at least 2 indicators
                return pattern_name, pattern_data["explanation"]

        # Check cache
        snippet_hash = hashlib.md5(finding['snippet'].encode()).hexdigest()
        if snippet_hash in self.pattern_cache:
            cached = self.pattern_cache[snippet_hash]
            return "cached", cached.get("reason", "Previously analyzed as safe")

        return None, None

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
                if file in [REPORT_FILENAME, VULN_FILENAME, SCAN_DB_FILE, PROGRESS_FILE, PATTERN_CACHE_FILE]: continue

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

                    # Enhanced heuristics (same as v2)
                    if "$" in line_clean: current_score += 10
                    if any(x in line_clean for x in ["$_POST", "$_GET", "$_REQUEST"]): current_score += 15

                    if any(x in line_clean for x in ["esc_html", "esc_attr", "wp_kses", "absint", "(int)", "intval"]):
                        current_score -= 20

                    # SQL improvements
                    if type_key == "SQL_INJECTION_RAW":
                        if re.search(r"\$wpdb->(insert|update|delete|replace)\s*\(", line_clean):
                            current_score -= 60
                        if "prepare" in line_clean:
                            current_score -= 50
                        if re.search(r"\{\$wpdb->(prefix|posts|postmeta|users|usermeta|options|terms|term_taxonomy|term_relationships)", line_clean):
                            current_score -= 30
                        context_start = max(0, i - 3)
                        context_lines = lines[context_start:i+1]
                        context_str = "".join(context_lines)
                        if "prepare(" in context_str or "$wpdb->prepare" in context_str:
                            current_score -= 40

                    # CSRF improvements
                    if type_key == "CSRF_MISSING_NONCE":
                        if "phpcs:ignore" in line_clean or "phpcs:disable" in line_clean:
                            if "NonceVerification" in line_clean:
                                current_score -= 40
                        context_start = max(0, i - 20)
                        context_end = min(len(lines), i + 5)
                        context_lines = lines[context_start:context_end]
                        context_str = "".join(context_lines)
                        if any(x in context_str for x in ["wp_verify_nonce", "check_admin_referer", "check_ajax_referer"]):
                            current_score -= 35
                        if "do_action(" in context_str or "apply_filters(" in context_str:
                            current_score -= 25

                    # Access control improvements
                    if type_key == "BROKEN_ACCESS_CONTROL":
                        context_start = max(0, i - 30)
                        context_end = min(len(lines), i + 30)
                        context_lines = lines[context_start:context_end]
                        context_str = "".join(context_lines)
                        if "WP_Async_Request" in context_str or "WP_Background_Process" in context_str:
                            if "check_ajax_referer" in context_str or "wp_verify_nonce" in context_str:
                                current_score -= 50
                        if any(x in context_str for x in ["check_ajax_referer", "wp_verify_nonce"]):
                            current_score -= 30
                        if "current_user_can(" in context_str:
                            current_score -= 25

                    # Object injection improvements
                    if type_key == "PHP_OBJECT_INJECTION":
                        if any(x in line_clean for x in ["get_post_meta", "get_option", "get_user_meta", "get_transient"]):
                            current_score -= 50
                        context_start = max(0, i - 5)
                        context_lines = lines[context_start:i+1]
                        context_str = "".join(context_lines)
                        if any(x in context_str for x in ["$wpdb->get_", "get_post_meta", "get_option"]):
                            current_score -= 40
                        if "wc_deprecated_function" in context_str:
                            current_score -= 60

                    # IDOR improvements
                    if type_key == "IDOR_SUSPICION":
                        context_start = max(0, i - 15)
                        context_end = min(len(lines), i + 10)
                        context_lines = lines[context_start:context_end]
                        context_str = "".join(context_lines)
                        if any(x in context_str for x in ["current_user_can(", "check_admin_referer", "check_ajax_referer"]):
                            current_score -= 40
                        if any(x in line_clean for x in ["get_", "wp_get_", "isset(", "empty("]):
                            if not any(x in line_clean for x in ["update", "delete", "insert", "save", "set_"]):
                                current_score -= 30
                        if any(x in rel_path for x in ["tracking", "analytics", "telemetry"]):
                            current_score -= 35

                    # File upload improvements
                    if type_key == "ARBITRARY_FILE_UPLOAD":
                        if "wp_handle_upload" in line_clean or "wp_handle_sideload" in line_clean:
                            current_score -= 30
                        context_start = max(0, i - 20)
                        context_end = min(len(lines), i + 5)
                        context_lines = lines[context_start:context_end]
                        context_str = "".join(context_lines)
                        if any(x in context_str for x in ["check_admin_referer", "current_user_can("]):
                            current_score -= 25

                    # RCE improvements
                    if type_key == "RCE_CRITICAL":
                        context_start = max(0, i - 20)
                        context_lines = lines[context_start:i+1]
                        context_str = "".join(context_lines)
                        if any(x in context_str for x in ["install_plugins", "manage_options", "current_user_can("]):
                            current_score -= 40
                        if "WP_Filesystem()" in line_clean:
                            current_score -= 50

                    final_score = max(0, min(100, current_score))
                    if final_score < 45: continue

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
        print(f"{Colors.CYAN}[i] Token Optimization: Pattern caching + smart context extraction{Colors.RESET}")

        with open(self.report_path, "a") as f:
            f.write(f"\n\n# --- SESSION START ({datetime.datetime.now()}) ---\n")
            f.write(f"Target: {self.target_dir}\n")

        if not os.path.exists(self.vuln_path):
            with open(self.vuln_path, "w") as f:
                f.write("# CONFIRMED VULNERABILITIES\nThis file contains only issues confirmed by the AI.\n\n")

        skipped_by_cache = 0

        for idx, finding in enumerate(remaining_targets):
            print(f"[{idx+1}/{len(remaining_targets)}] Auditing {os.path.basename(finding['file'])} (Line {finding['line']}) [Score: {finding['score']}]...")

            # Check known patterns first (saves tokens!)
            try:
                with open(finding['file'], 'r', errors='ignore') as f:
                    lines = f.readlines()
                context_start = max(0, finding['line'] - 25)
                context_end = min(len(lines), finding['line'] + 15)
                context_lines = lines[context_start:context_end]
            except:
                context_lines = []

            pattern_name, explanation = self._check_known_pattern(finding, context_lines)

            if pattern_name:
                print(f"   {Colors.GREEN}✓ Matched known safe pattern: {pattern_name}{Colors.RESET}")
                response = f"VERDICT: SAFE\n\n**Pattern Matched:** {pattern_name}\n**Explanation:** {explanation}\n\n**Auto-cleared by pattern recognition (token-efficient mode)**"
                skipped_by_cache += 1
            else:
                # Run AI audit with token-efficient prompts
                final_response = self._run_token_efficient_audit(finding)

                if "limit reached" in final_response.lower():
                    print(f"\n{Colors.RED}[!] CRITICAL: Rate limit detected. Stopping.{Colors.RESET}")
                    break

                response = final_response

                # Learn from AI verdict (cache for future)
                if "VERDICT: SAFE" in response:
                    snippet_hash = hashlib.md5(finding['snippet'].encode()).hexdigest()
                    self.pattern_cache[snippet_hash] = {
                        "type": finding['type'],
                        "reason": "AI determined safe",
                        "timestamp": str(datetime.datetime.now())
                    }

            self._process_verdict(finding, response)
            self._mark_as_complete(finding['_id'])

            if idx < len(remaining_targets) - 1 and not pattern_name:
                self._do_countdown()

        print(f"\n{Colors.CYAN}[i] Pattern cache saved {skipped_by_cache} AI calls (${skipped_by_cache * 0.50:.2f} saved){Colors.RESET}")
        self._save_pattern_cache()

    def _extract_function_from_file(self, filepath, target_name=None):
        """Extract just the relevant function, not entire file (saves tokens)"""
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()

            # If no specific target, return limited content
            if not target_name:
                return content[:3000] + "\n...[truncated for tokens]"

            # Try to find the function
            pattern = rf"(function\s+{re.escape(target_name)}\s*\([^)]*\)\s*\{{[^}}]*?\}})"
            match = re.search(pattern, content, re.DOTALL)

            if match:
                return match.group(1)[:2000]  # Max 2000 chars per function

            # Fallback: Return around the first mention
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if target_name in line:
                    start = max(0, i - 15)
                    end = min(len(lines), i + 20)
                    return '\n'.join(lines[start:end])

            return content[:2000]
        except:
            return "ERROR: Could not read file"

    def _run_token_efficient_audit(self, finding):
        """Token-efficient audit with structured prompts"""

        # ULTRA-COMPACT PROMPT (50% token reduction)
        prompt = f"""[SECURITY AUDIT]
File: {os.path.basename(finding['file'])}:{finding['line']}
Type: {finding['type']}
Score: {finding['score']}

CODE:
```php
{finding['snippet'][:500]}
```

RULES:
- CSRF: Check for wp_verify_nonce/check_admin_referer nearby
- SQLi: $wpdb->insert/update/prepare are safe
- Access: wp_ajax_nopriv needs capability check
- Object injection: get_post_meta/get_option are safe sources

RESPOND:
If you need context, reply: "READ: filename.php [function_name]"
Otherwise start with: "VERDICT: VULNERABLE|SAFE|MANUAL_REVIEW"
"""

        hops = 0
        conversation = prompt

        while hops < MAX_CONTEXT_HOPS:
            response = self._send_to_claude(conversation)

            # Check for file read request
            match = re.search(r"READ:\s*(\S+)(?:\s+\[([^\]]+)\])?", response)
            if match and hops < MAX_CONTEXT_HOPS:
                requested_file = match.group(1).strip()
                requested_function = match.group(2).strip() if match.group(2) else None

                full_path = os.path.join(self.target_dir, requested_file)
                if not os.path.exists(full_path):
                    file_dir = os.path.dirname(finding['file'])
                    full_path = os.path.join(file_dir, requested_file)

                print(f"   {Colors.CYAN}→ Reading: {os.path.basename(requested_file)}{f' [{requested_function}]' if requested_function else ''}{Colors.RESET}")

                # Smart extraction (saves 70% tokens)
                content = self._extract_function_from_file(full_path, requested_function)

                conversation += f"\n\nCONTEXT:\n```php\n{content}\n```\nRESPOND WITH VERDICT:"
                hops += 1
                time.sleep(1)
            else:
                return response

        return response

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
    parser = argparse.ArgumentParser(description="WordPress Security Auto-Auditor (Token-Efficient v3)")
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

import re
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

from wifi_risk.services.assessment_service import add_assessment_check
from wifi_risk.services.finding_service import import_findings
from wifi_risk.utils.file_loader import save_json


def fetch_web_page(url: str, timeout: float = 4.0) -> dict[str, Any]:
    """
    Safely fetch a web page from the target device without destructive actions.
    """
    try:
        import requests
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        return {
            "success": True,
            "status_code": response.status_code,
            "url": response.url,
            "headers": dict(response.headers),
            "cookies": [
                {
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain,
                    "path": c.path,
                    "secure": c.secure,
                    "httponly": c.has_nonstandard_attr("HttpOnly"),
                }
                for c in response.cookies
            ],
            "html": response.text,
            "error": None,
        }
    except Exception as exc:
        return {
            "success": False,
            "status_code": 0,
            "url": url,
            "headers": {},
            "cookies": [],
            "html": "",
            "error": str(exc),
        }


def analyze_html_content(html_content: str, base_url: str = "") -> dict[str, Any]:
    """
    Analyze HTML content for security flaws, hardcoded credentials, hidden fields, and auth logic.
    """
    if not html_content or not html_content.strip():
        return {
            "title": "",
            "hidden_fields": [],
            "visible_inputs": [],
            "has_hidden_admin": False,
            "has_visible_user_field": False,
            "has_visible_pass_field": False,
            "has_forms": False,
            "has_basic_cookie_logic": False,
            "logout_links_count": 0,
            "logout_links": [],
            "firmware_clue": "",
            "is_dashboard": False,
        }

    soup = BeautifulSoup(html_content, "html.parser")

    hidden_fields: list[dict[str, str]] = []
    visible_inputs: list[dict[str, str]] = []
    forms = soup.find_all("form")

    for inp in soup.find_all("input"):
        inp_type = inp.get("type", "text").lower()
        inp_name = inp.get("name", "")
        inp_id = inp.get("id", "")
        inp_val = inp.get("value", "")

        field_info = {
            "type": inp_type,
            "name": inp_name,
            "id": inp_id,
            "value": inp_val,
        }

        if inp_type == "hidden":
            hidden_fields.append(field_info)
        else:
            visible_inputs.append(field_info)

    # Check for hardcoded credentials in hidden fields or HTML text
    has_hidden_admin = any(
        f.get("value", "").lower() == "admin" and ("user" in f.get("name", "").lower() or "pwd" in f.get("name", "").lower() or "pass" in f.get("name", "").lower())
        for f in hidden_fields
    )

    # Check for visible credentials input fields
    has_visible_user_field = any("user" in f.get("name", "").lower() or "user" in f.get("id", "").lower() for f in visible_inputs)
    has_visible_pass_field = any(f.get("type") == "password" or "pass" in f.get("name", "").lower() or "pwd" in f.get("name", "").lower() for f in visible_inputs)

    # Search for client-side Authorization cookie or Basic auth scripts
    scripts_text = " ".join([s.get_text() for s in soup.find_all("script")])
    full_text = html_content

    has_basic_cookie_logic = bool(
        re.search(r"document\.cookie\s*=\s*['\"].*Authorization=", scripts_text, re.IGNORECASE)
        or re.search(r"Basic\s+[a-zA-Z0-9+/=]{8,}", scripts_text)
    )

    # Check for visible logout links
    logout_links = []
    for a_tag in soup.find_all("a"):
        href = a_tag.get("href", "").lower()
        text = a_tag.get_text().lower()
        if "logout" in href or "logout" in text:
            logout_links.append({"href": a_tag.get("href"), "text": a_tag.get_text().strip()})

    # Look for firmware version clues
    fw_match = re.search(r"(?:firmware|version|ver)[:\s]+([0-9a-zA-Z\.\-_]+)", full_text, re.IGNORECASE)
    firmware_clue = fw_match.group(1) if fw_match else ""

    is_dashboard = any(
        kw in full_text.lower()
        for kw in ["router status", "wireless settings", "ap mode", "repeater mode", "device information"]
    )

    return {
        "title": soup.title.string.strip() if soup.title and soup.title.string else "",
        "hidden_fields": hidden_fields,
        "visible_inputs": visible_inputs,
        "has_hidden_admin": has_hidden_admin,
        "has_visible_user_field": has_visible_user_field,
        "has_visible_pass_field": has_visible_pass_field,
        "has_forms": len(forms) > 0,
        "has_basic_cookie_logic": has_basic_cookie_logic,
        "logout_links_count": len(logout_links),
        "logout_links": logout_links,
        "firmware_clue": firmware_clue,
        "is_dashboard": is_dashboard,
    }


def evaluate_web_rules(
    device_id: str,
    assessment_id: str,
    target_url: str,
    html_analysis: dict[str, Any],
    is_reachable: bool = True,
    headers: dict[str, Any] | None = None,
    cookies: list[dict[str, Any]] | None = None,
    observed_login_url: str | None = None,
    manual_observations: dict[str, bool] | None = None,
) -> list[dict[str, Any]]:
    """
    Evaluate web interface behaviors against security rules and return confirmed findings.
    Only evaluates rules if the target is genuinely reachable or manual observations were provided.
    """
    findings: list[dict[str, Any]] = []
    obs = manual_observations or {}

    # If the target web service is completely unreachable and no manual observations were given, return 0 findings
    if not is_reachable and not obs:
        return []

    # Rule 1: HTTP Plaintext (Only if web service is actually running on HTTP)
    if is_reachable and target_url.lower().startswith("http://"):
        findings.append(
            {
                "id": f"{device_id}-F_HTTP_ADMIN",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Web management interface served over unencrypted HTTP",
                "category": "Sensitive Data Exposure / Transport Security",
                "severity": "Medium",
                "level": "Medium",
                "status": "Confirmed",
                "cwe": "CWE-319 (Cleartext Transmission of Sensitive Information) / CWE-352 (Cross-Site Request Forgery)",
                "threat_scenario": "An attacker on the same local Wi-Fi or upstream network can capture cleartext HTTP authentication traffic and session tokens via Wi-Fi sniffing or ARP spoofing. Without transport encryption or CSRF tokens, attackers can also forge router reconfiguration requests.",
                "evidence": f"Web interface responded on {target_url} without TLS encryption.",
                "impact": "All web interactions, login attempts, and configurations are sent in plaintext and vulnerable to local eavesdropping.",
                "recommendation": "Configure HTTPS encryption for the web management portal.",
                "hardening_coverage": "1. Embed lightweight TLS support (e.g. mbedTLS / WolfSSL) into the embedded web server.\n2. Enable automatic redirection from HTTP port 80 to HTTPS port 443 with HSTS headers.\n3. Implement unique cryptographic certificates per device.",
                "module": "Web Interface Checks",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    # Rule 2: Default admin credentials in login HTML
    if html_analysis.get("has_hidden_admin") or obs.get("hidden_credentials_in_html", False):
        findings.append(
            {
                "id": f"{device_id}-F03",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Default admin credentials exposed in login page HTML",
                "category": "Authentication Security / Insecure Defaults",
                "severity": "High",
                "level": "High",
                "status": "Confirmed",
                "cwe": "CWE-798 (Use of Hardcoded Credentials) / CWE-200 (Exposure of Sensitive Information)",
                "threat_scenario": "An attacker inspecting client-side HTML or automated crawlers can immediately harvest default administrative credentials without guessing or brute-forcing.",
                "evidence": "Login page HTML contains hidden username or password values (e.g. 'admin').",
                "impact": "The login page HTML reveals default credentials to anyone viewing the source code.",
                "recommendation": "Remove hardcoded credentials from client-side HTML.",
                "hardening_coverage": "1. Remove all hardcoded default credentials from client-side HTML, JavaScript, and hidden form fields.\n2. Authenticate credentials strictly on the server side.\n3. Enforce a mandatory setup wizard requiring unique password configuration.",
                "module": "Web Interface Checks",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    # Rule 3: Login without user-supplied credentials (Only if forms exist and password field is absent, or manual observation confirms)
    if (html_analysis.get("has_forms") and not html_analysis.get("has_visible_pass_field") and len(html_analysis.get("visible_inputs", [])) > 0) or obs.get("login_without_credentials", False):
        findings.append(
            {
                "id": f"{device_id}-F02",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Web interface allows login without user-supplied credentials",
                "category": "Authentication Security",
                "severity": "High",
                "level": "High",
                "status": "Confirmed",
                "cwe": "CWE-306 (Missing Authentication for Critical Function) / CWE-287 (Improper Authentication)",
                "threat_scenario": "Any unauthenticated attacker on the local Wi-Fi network can bypass authentication and access the router management portal by simply submitting an empty form or clicking login.",
                "evidence": "Login form allows access without entering a password.",
                "impact": "The login page does not require user credentials, allowing anyone on the network to access the admin dashboard.",
                "recommendation": "Require users to configure and enter a unique administrator password during initial setup.",
                "hardening_coverage": "1. Require a mandatory user-defined administrator password during initial device onboarding.\n2. Reject empty password authentication attempts on the backend.\n3. Disable bypass authentication routes in web server CGI handlers.",
                "module": "Web Interface Checks",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    # Rule 4: Admin credentials stored in Base64 Authorization cookie
    cookie_list = cookies or []
    has_insecure_auth_cookie = any(
        c.get("name", "").lower() == "authorization" and not c.get("httponly", False)
        for c in cookie_list
    ) or obs.get("insecure_auth_cookie", False) or html_analysis.get("has_basic_cookie_logic", False)

    if has_insecure_auth_cookie:
        findings.append(
            {
                "id": f"{device_id}-F04",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Admin credentials stored in Base64 Authorization cookie",
                "category": "Session Management",
                "severity": "High",
                "level": "High",
                "status": "Confirmed",
                "cwe": "CWE-312 (Cleartext Storage of Sensitive Information) / CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)",
                "threat_scenario": "Because Base64 is trivially reversible and the cookie lacks HttpOnly/Secure flags, any client-side script (XSS) or local network eavesdropper can decode the plaintext admin credentials directly from the cookie header.",
                "evidence": "Authorization cookie or script stores Base64 encoded credentials without HttpOnly/Secure flags.",
                "impact": "The cookie can expose admin credentials because Base64 is reversible and the cookie lacks HttpOnly/Secure flags.",
                "recommendation": "Use secure server-side session tokens with HttpOnly, Secure and SameSite attributes.",
                "hardening_coverage": "1. Implement cryptographically random session tokens (e.g. 128-bit tokens) stored in server memory.\n2. Set 'HttpOnly', 'Secure', and 'SameSite=Strict' flags on all session cookies.\n3. Never store credentials or reversible encodings in client cookies.",
                "module": "Web Interface Checks",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    # Rule 5: Credentials exposed in URL query parameters
    check_url = observed_login_url or target_url
    parsed_query = parse_qs(urlparse(check_url).query)
    if ("pcPassword" in parsed_query or "password" in parsed_query or obs.get("credentials_in_url", False)) and observed_login_url:
        findings.append(
            {
                "id": f"{device_id}-F07",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "Admin credentials exposed in URL query parameters during login",
                "category": "Sensitive Data Exposure",
                "severity": "High",
                "level": "High",
                "status": "Confirmed",
                "cwe": "CWE-598 (Use of GET Request Method with Sensitive Query Strings) / CWE-319 (Cleartext Transmission)",
                "threat_scenario": "Credentials transmitted in GET query strings are permanently retained in browser history, proxy logs, server access logs, and referrer headers, facilitating passive credential compromise.",
                "evidence": f"Login URL contained credential parameters: {check_url}",
                "impact": "Credentials sent via GET query parameters are stored in browser history, server logs, web caches and proxy logs.",
                "recommendation": "Submit credentials using POST requests over HTTPS and never transmit sensitive parameters in URL query strings.",
                "hardening_coverage": "1. Transmit authentication credentials strictly via HTTP POST requests in the request body over HTTPS.\n2. Strip query string parameters on the server side.\n3. Prevent GET-based authentication in CGI binaries.",
                "module": "Web Interface Checks",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    # Rule 6: No logout option on authenticated dashboard
    if (html_analysis.get("is_dashboard") and html_analysis.get("logout_links_count") == 0) or obs.get("no_logout_option", False):
        findings.append(
            {
                "id": f"{device_id}-F06",
                "device_id": device_id,
                "assessment_id": assessment_id,
                "title": "No logout option to terminate admin session",
                "category": "Session Management",
                "severity": "Medium",
                "level": "Medium",
                "status": "Confirmed",
                "cwe": "CWE-613 (Insufficient Session Expiration)",
                "threat_scenario": "Without an explicit logout mechanism, administrative sessions remain valid on shared client workstations and mobile browsers, allowing subsequent users to access the router dashboard.",
                "evidence": "Management interface lacks a visible logout mechanism.",
                "impact": "Users cannot explicitly terminate the admin session from the interface, leaving administrative access open indefinitely on shared clients.",
                "recommendation": "Add a logout function that clears and invalidates the session.",
                "hardening_coverage": "1. Provide a visible 'Logout' button on all dashboard navigation menus.\n2. Invalidate server-side session tokens upon logout request.\n3. Instruct client browsers to clear authentication cookies on session termination.",
                "module": "Web Interface Checks",
                "date_observed": datetime.now().isoformat(timespec="seconds"),
            }
        )

    return findings


def perform_web_checks(
    target_ip: str | None = None,
    device_id: str = "Target",
    assessment_id: str = "ASM-001",
    target_url: str | None = None,
    raw_html: str | None = None,
    observed_login_url: str | None = None,
    manual_observations: dict[str, bool] | None = None,
    progress_callback: Any = None,
) -> dict[str, Any]:
    """
    Perform web interface inspection, evaluate rules, generate findings and store evidence.
    """
    if not target_url and not target_ip:
        target_ip = "192.168.11.1"
    elif target_url and not target_ip:
        parsed = urlparse(target_url)
        target_ip = parsed.hostname or "192.168.11.1"

    url = target_url or f"http://{target_ip}/"
    headers: dict[str, Any] = {}
    cookies: list[dict[str, Any]] = []
    html_content = ""
    is_reachable = False
    check_method = "live_fetch"

    if progress_callback:
        progress_callback(10, f"Connecting to web management portal on {url}...")

    if raw_html:
        html_content = raw_html
        check_method = "html_import"
        is_reachable = True
        if progress_callback:
            progress_callback(40, "Importing and analyzing raw HTML document...")
    elif manual_observations:
        check_method = "manual_observation"
        is_reachable = True
        if progress_callback:
            progress_callback(40, "Evaluating manual observation parameters...")
    else:
        if progress_callback:
            progress_callback(20, f"Fetching HTTP response from {url}...")
        fetch_res = fetch_web_page(url)
        is_reachable = fetch_res["success"]
        headers = fetch_res["headers"]
        cookies = fetch_res["cookies"]
        html_content = fetch_res["html"]
        if not is_reachable:
            if progress_callback:
                progress_callback(40, f"Port 80 unreachable. Checking alternative port 8080...")
            # Try port 8080 fallback
            url_8080 = f"http://{target_ip}:8080/"
            fetch_res_8080 = fetch_web_page(url_8080, timeout=2.0)
            if fetch_res_8080["success"]:
                url = url_8080
                is_reachable = True
                headers = fetch_res_8080["headers"]
                cookies = fetch_res_8080["cookies"]
                html_content = fetch_res_8080["html"]

    if progress_callback:
        progress_callback(60, "Parsing HTML DOM tree with BeautifulSoup...")
    html_analysis = analyze_html_content(html_content, base_url=url) if html_content else {}

    if progress_callback:
        progress_callback(80, "Evaluating web authentication, cookie and session rules...")

    findings = evaluate_web_rules(
        device_id=device_id,
        assessment_id=assessment_id,
        target_url=url,
        html_analysis=html_analysis,
        is_reachable=is_reachable,
        headers=headers,
        cookies=cookies,
        observed_login_url=observed_login_url,
        manual_observations=manual_observations,
    )

    evidence_data = {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "target_url": url,
        "is_reachable": is_reachable,
        "check_method": check_method,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "headers": headers,
        "cookies_count": len(cookies),
        "html_analysis": html_analysis,
        "findings": findings,
    }

    evidence_file = f"data/evidence/{assessment_id}_web.json"
    save_json(evidence_file, evidence_data)

    check_record = {
        "module": "Web Interface Checks",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "target_url": url,
        "is_reachable": is_reachable,
        "check_method": check_method,
        "findings_count": len(findings),
        "evidence_file": evidence_file,
    }
    add_assessment_check(assessment_id, check_record)

    if findings:
        import_findings(findings)

    return {
        "assessment_id": assessment_id,
        "device_id": device_id,
        "target_url": url,
        "is_reachable": is_reachable,
        "check_method": check_method,
        "html_analysis": html_analysis,
        "findings": findings,
        "evidence_file": evidence_file,
    }

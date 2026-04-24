import requests
import re
import time
from concurrent.futures import ThreadPoolExecutor

TARGET_URL = "http://127.0.0.1:5000/login"
TOTAL_REQUESTS = 300      
CONCURRENCY = 30         
TIMEOUT = 3
CSRF_FIELD = "csrf_token"


def extract_csrf_token(html):
    pattern = r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']'
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)

    pattern = r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']'
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def send_request(i):
    try:
        session = requests.Session()
        login_page = session.get(TARGET_URL, timeout=TIMEOUT)
        data = {"username": "test", "password": "test"}
        csrf_token = extract_csrf_token(login_page.text)
        if csrf_token:
            data[CSRF_FIELD] = csrf_token

        response = session.post(
            TARGET_URL,
            data=data,
            timeout=TIMEOUT,
        )
        return response.status_code
    except requests.RequestException:
        return "error"


def main():
    print(f"[*] Starting DoS simulation on {TARGET_URL}")
    print(f"[*] Total requests: {TOTAL_REQUESTS}, concurrency: {CONCURRENCY}")

    start = time.time()

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        results = list(executor.map(send_request, range(TOTAL_REQUESTS)))

    end = time.time()

    success = sum(1 for r in results if r == 200)
    errors = sum(1 for r in results if r == "error")

    print(f"[+] Finished in {end - start:.2f}s")
    print(f"[+] Successful responses: {success}")
    print(f"[+] Errors / timeouts: {errors}")


if __name__ == "__main__":
    main()

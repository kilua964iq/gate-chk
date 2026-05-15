import re
import ssl
import socket
import asyncio
import aiohttp
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
from config import (
    PAYMENT_KEY_PATTERNS,
    SECURITY_HEADERS,
    SCAN_TIMEOUT,
    MAX_PAGES_SCAN,
    REQUEST_DELAY
)


class PaymentScanner:

    def __init__(self, target_url: str):
        self.target_url = self._normalize_url(target_url)
        self.domain = urlparse(self.target_url).netloc
        self.results = {
            "url": self.target_url,
            "domain": self.domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ssl_info": {},
            "security_headers": {},
            "exposed_keys": [],
            "payment_forms": [],
            "vulnerabilities": [],
            "score": 100,
            "risk_level": "LOW",
        }
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _deduct_score(self, points: int):
        self.results["score"] = max(0, self.results["score"] - points)

    # ══════════════════════════════════════
    #           فحص SSL
    # ══════════════════════════════════════
    def scan_ssl(self) -> dict:
        ssl_info = {
            "has_ssl": False,
            "valid": False,
            "expiry_date": None,
            "days_remaining": None,
            "issuer": None,
            "version": None,
            "issues": [],
        }

        try:
            if self.target_url.startswith("https://"):
                ssl_info["has_ssl"] = True
            else:
                ssl_info["issues"].append("الموقع لا يستخدم HTTPS")
                self._deduct_score(30)
                self.results["ssl_info"] = ssl_info
                return ssl_info

            context = ssl.create_default_context()
            with socket.create_connection(
                (self.domain, 443), timeout=SCAN_TIMEOUT
            ) as sock:
                with context.wrap_socket(
                    sock, server_hostname=self.domain
                ) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info["version"] = ssock.version()

                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        expiry_date = datetime.strptime(
                            expiry_str, "%b %d %H:%M:%S %Y %Z"
                        )
                        ssl_info["expiry_date"] = expiry_date.strftime(
                            "%Y-%m-%d"
                        )
                        days_remaining = (
                            expiry_date - datetime.now()
                        ).days
                        ssl_info["days_remaining"] = days_remaining
                        ssl_info["valid"] = True

                        if days_remaining < 0:
                            ssl_info["issues"].append(
                                "❌ الشهادة منتهية الصلاحية!"
                            )
                            self._deduct_score(40)
                        elif days_remaining < 30:
                            ssl_info["issues"].append(
                                f"⚠️ الشهادة ستنتهي خلال {days_remaining} يوم"
                            )
                            self._deduct_score(15)

                    issuer_data = dict(
                        x[0] for x in cert.get("issuer", [])
                    )
                    ssl_info["issuer"] = issuer_data.get(
                        "organizationName", "غير معروف"
                    )

        except ssl.SSLCertVerificationError:
            ssl_info["issues"].append("❌ شهادة SSL غير موثوقة")
            ssl_info["valid"] = False
            self._deduct_score(35)

        except ssl.SSLError as e:
            ssl_info["issues"].append(f"❌ خطأ SSL: {str(e)[:50]}")
            self._deduct_score(25)

        except (socket.timeout, ConnectionRefusedError):
            ssl_info["issues"].append("⚠️ تعذر الاتصال للتحقق من SSL")

        except Exception as e:
            ssl_info["issues"].append(f"خطأ: {str(e)[:50]}")

        self.results["ssl_info"] = ssl_info
        return ssl_info

    # ══════════════════════════════════════
    #       فحص Security Headers
    # ══════════════════════════════════════
    def scan_security_headers(self) -> dict:
        headers_result = {}

        try:
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=SCAN_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )
            response_headers = {
                k.lower(): v for k, v in response.headers.items()
            }

            for header, info in SECURITY_HEADERS.items():
                header_lower = header.lower()
                if header_lower in response_headers:
                    headers_result[header] = {
                        "present": True,
                        "value": response_headers[header_lower],
                        "severity": info["severity"],
                        "description": info["description"],
                    }
                else:
                    headers_result[header] = {
                        "present": False,
                        "recommended": info["recommended"],
                        "severity": info["severity"],
                        "description": info["description"],
                    }
                    deductions = {"HIGH": 10, "MEDIUM": 5, "LOW": 2}
                    self._deduct_score(
                        deductions.get(info["severity"], 2)
                    )

        except requests.exceptions.SSLError:
            headers_result["error"] = "خطأ في التحقق من SSL"
        except requests.exceptions.ConnectionError:
            headers_result["error"] = "تعذر الاتصال بالموقع"
        except requests.exceptions.Timeout:
            headers_result["error"] = "انتهت مهلة الاتصال"
        except Exception as e:
            headers_result["error"] = str(e)[:100]

        self.results["security_headers"] = headers_result
        return headers_result

    # ══════════════════════════════════════
    #       فحص المفاتيح المكشوفة
    # ══════════════════════════════════════
    def scan_exposed_keys(self) -> list:
        exposed = []
        pages_to_scan = [self.target_url]
        scanned_pages = set()

        try:
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=SCAN_TIMEOUT,
                verify=False,
            )
            soup = BeautifulSoup(response.text, "lxml")

            for tag in soup.find_all(["script", "a"], href=True):
                href = tag.get("href") or tag.get("src", "")
                if href:
                    full_url = urljoin(self.target_url, href)
                    if self.domain in full_url:
                        pages_to_scan.append(full_url)

            common_paths = [
                "/checkout", "/payment", "/cart",
                "/wp-content/themes/", "/assets/js/",
                "/static/js/", "/js/app.js",
            ]
            for path in common_paths:
                pages_to_scan.append(self.target_url + path)

        except Exception:
            pass

        for page_url in pages_to_scan[:MAX_PAGES_SCAN]:
            if page_url in scanned_pages:
                continue
            scanned_pages.add(page_url)

            try:
                resp = requests.get(
                    page_url,
                    headers=self.headers,
                    timeout=SCAN_TIMEOUT,
                    verify=False,
                )
                content = resp.text

                for key_type, patterns in PAYMENT_KEY_PATTERNS.items():
                    for pattern in patterns:
                        matches = re.findall(
                            pattern, content, re.IGNORECASE
                        )
                        for match in matches:
                            key_value = (
                                match if isinstance(match, str)
                                else match[0]
                            )
                            if len(key_value) > 10:
                                exposed.append({
                                    "type": key_type,
                                    "value_full": key_value,
                                    "page": page_url,
                                    "severity": "CRITICAL",
                                })
                                self._deduct_score(50)

                import time
                time.sleep(REQUEST_DELAY)

            except Exception:
                continue

        seen = set()
        unique_exposed = []
        for item in exposed:
            key = f"{item['type']}_{item['page']}"
            if key not in seen:
                seen.add(key)
                unique_exposed.append(item)

        self.results["exposed_keys"] = unique_exposed
        return unique_exposed

    # ══════════════════════════════════════
    #       فحص نماذج الدفع
    # ══════════════════════════════════════
    def scan_payment_forms(self) -> list:
        payment_forms = []

        try:
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=SCAN_TIMEOUT,
                verify=False,
            )
            soup = BeautifulSoup(response.text, "lxml")

            payment_keywords = [
                "card", "credit", "payment", "checkout",
                "billing", "cvv", "expiry", "cardnumber",
                "card-number", "card_number",
            ]

            for form in soup.find_all("form"):
                form_html = str(form).lower()
                is_payment_form = any(
                    kw in form_html for kw in payment_keywords
                )

                if is_payment_form:
                    form_info = {
                        "action": form.get("action", "غير محدد"),
                        "method": form.get("method", "GET").upper(),
                        "has_https": False,
                        "issues": [],
                    }

                    action = form.get("action", "")
                    if action.startswith("https://"):
                        form_info["has_https"] = True
                    elif action.startswith("http://"):
                        form_info["issues"].append(
                            "❌ نموذج الدفع يرسل البيانات عبر HTTP"
                        )
                        self._deduct_score(40)

                    if form_info["method"] == "GET":
                        form_info["issues"].append(
                            "⚠️ نموذج الدفع يستخدم GET بدلاً من POST"
                        )
                        self._deduct_score(20)

                    csrf_fields = form.find_all(
                        "input",
                        attrs={
                            "name": re.compile(
                                r"csrf|token|_token", re.I
                            )
                        }
                    )
                    if not csrf_fields:
                        form_info["issues"].append(
                            "⚠️ لا يوجد CSRF Token"
                        )
                        self._deduct_score(15)

                    payment_forms.append(form_info)

        except Exception as e:
            payment_forms.append({"error": str(e)[:100]})

        self.results["payment_forms"] = payment_forms
        return payment_forms

    # ══════════════════════════════════════
    #       حساب مستوى الخطر
    # ══════════════════════════════════════
    def _calculate_risk_level(self):
        score = self.results["score"]
        if score >= 80:
            self.results["risk_level"] = "LOW"
        elif score >= 60:
            self.results["risk_level"] = "MEDIUM"
        elif score >= 40:
            self.results["risk_level"] = "HIGH"
        else:
            self.results["risk_level"] = "CRITICAL"

    # ══════════════════════════════════════
    #       الفحص الشامل
    # ══════════════════════════════════════
    def run_full_scan(self) -> dict:
        import urllib3
        urllib3.disable_warnings(
            urllib3.exceptions.InsecureRequestWarning
        )

        self.scan_ssl()
        self.scan_security_headers()
        self.scan_exposed_keys()
        self.scan_payment_forms()
        self._calculate_risk_level()

        return self.results


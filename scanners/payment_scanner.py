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
    """
    ماسح شامل لثغرات بوابات الدفع والأمان العام للمواقع
    """

    def __init__(self, target_url: str):
        self.target_url = self._normalize_url(target_url)
        self.domain = urlparse(self.target_url).netloc
        self.results = {
            "url": self.target_url,
            "domain": self.domain,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ssl_info": {},
            "security_headers": {},
            "exposed_keys": [],      # سيحتوي على المفاتيح الكاملة
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

    # ══════════════════════════════════════
    #           الدوال المساعدة
    # ══════════════════════════════════════

    def _normalize_url(self, url: str) -> str:
        """تطبيع الرابط وإضافة البروتوكول إن لزم"""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _get_full_key(self, key: str) -> str:
        """إرجاع المفتاح كاملاً دون إخفاء"""
        return key

    def _deduct_score(self, points: int):
        """خصم نقاط من درجة الأمان"""
        self.results["score"] = max(0, self.results["score"] - points)

    # ══════════════════════════════════════
    #           فحص SSL
    # ══════════════════════════════════════

    def scan_ssl(self) -> dict:
        """فحص شهادة SSL بالتفصيل"""
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
            # فحص وجود HTTPS
            if self.target_url.startswith("https://"):
                ssl_info["has_ssl"] = True
            else:
                ssl_info["issues"].append("الموقع لا يستخدم HTTPS")
                self._deduct_score(30)
                self.results["ssl_info"] = ssl_info
                return ssl_info

            # جلب تفاصيل الشهادة
            context = ssl.create_default_context()
            with socket.create_connection(
                (self.domain, 443), timeout=SCAN_TIMEOUT
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info["version"] = ssock.version()

                    # تاريخ الانتهاء
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        expiry_date = datetime.strptime(
                            expiry_str, "%b %d %H:%M:%S %Y %Z"
                        )
                        ssl_info["expiry_date"] = expiry_date.strftime("%Y-%m-%d")
                        days_remaining = (expiry_date - datetime.now()).days
                        ssl_info["days_remaining"] = days_remaining
                        ssl_info["valid"] = True

                        if days_remaining < 0:
                            ssl_info["issues"].append("❌ الشهادة منتهية الصلاحية!")
                            self._deduct_score(40)
                        elif days_remaining < 30:
                            ssl_info["issues"].append(
                                f"⚠️ الشهادة ستنتهي خلال {days_remaining} يوم"
                            )
                            self._deduct_score(15)

                    # المُصدر
                    issuer_data = dict(x[0] for x in cert.get("issuer", []))
                    ssl_info["issuer"] = issuer_data.get("organizationName", "غير معروف")

        except ssl.SSLCertVerificationError:
            ssl_info["issues"].append("❌ شهادة SSL غير موثوقة أو منتهية")
            ssl_info["valid"] = False
            self._deduct_score(35)

        except ssl.SSLError as e:
            ssl_info["issues"].append(f"❌ خطأ SSL: {str(e)[:50]}")
            self._deduct_score(25)

        except (socket.timeout, ConnectionRefusedError):
            ssl_info["issues"].append("⚠️ تعذر الاتصال للتحقق من SSL")

        except Exception as e:
            ssl_info["issues"].append(f"خطأ أثناء فحص SSL: {str(e)[:50]}")

        self.results["ssl_info"] = ssl_info
        return ssl_info

    # ══════════════════════════════════════
    #       فحص Security Headers
    # ══════════════════════════════════════

    def scan_security_headers(self) -> dict:
        """فحص رؤوس الأمان HTTP"""
        headers_result = {}

        try:
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=SCAN_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )
            response_headers = {k.lower(): v for k, v in response.headers.items()}

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
                    # خصم نقاط حسب الخطورة
                    deductions = {"HIGH": 10, "MEDIUM": 5, "LOW": 2}
                    self._deduct_score(deductions.get(info["severity"], 2))

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
    #       فحص المفاتيح المكشوفة (كاملة)
    # ══════════════════════════════════════

    def scan_exposed_keys(self) -> list:
        """فحص المفاتيح المكشوفة في صفحات الموقع - إظهارها كاملة"""
        exposed = []
        pages_to_scan = [self.target_url]
        scanned_pages = set()

        try:
            # جلب روابط إضافية من الصفحة الرئيسية
            response = requests.get(
                self.target_url,
                headers=self.headers,
                timeout=SCAN_TIMEOUT,
                verify=False,
            )
            soup = BeautifulSoup(response.text, "lxml")

            # إضافة روابط JS وصفحات الدفع
            for tag in soup.find_all(["script", "a"], href=True):
                href = tag.get("href") or tag.get("src", "")
                if href:
                    full_url = urljoin(self.target_url, href)
                    if self.domain in full_url:
                        pages_to_scan.append(full_url)

            # إضافة مسارات شائعة
            common_paths = [
                "/checkout", "/payment", "/cart",
                "/wp-content/themes/", "/assets/js/",
                "/static/js/", "/js/app.js",
            ]
            for path in common_paths:
                pages_to_scan.append(self.target_url + path)

        except Exception:
            pass

        # فحص الصفحات
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

                # البحث عن المفاتيح - تخزينها كاملة
                for key_type, patterns in PAYMENT_KEY_PATTERNS.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            key_value = match if isinstance(match, str) else match[0]
                            if len(key_value) > 10:
                                exposed.append({
                                    "type": key_type,
                                    "value_full": key_value,      # 🔓 المفتاح كاملاً
                                    "page": page_url,
                                    "severity": "CRITICAL",
                                })
                                self._deduct_score(50)

                import time
                time.sleep(REQUEST_DELAY)

            except Exception:
                continue

        # إزالة التكرارات
        seen = set()
        unique_exposed = []
        for item in exposed:
            key = f"{item['type']}_{item['page']}_{item['value_full']}"
            if key not in seen:
                seen.add(key)
                unique_exposed.append(item)

        self.results["exposed_keys"] = unique_exposed
        return unique_exposed

    # ══════════════════════════════════════
    #       فحص نماذج الدفع
    # ══════════════════════════════════════

    def scan_payment_forms(self) -> list:
        """فحص نماذج الدفع وأمانها"""
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
                is_payment_form = any(kw in form_html for kw in payment_keywords)

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
                            "❌ نموذج الدفع يرسل البيانات عبر HTTP غير مشفر"
                        )
                        self._deduct_score(40)

                    if form_info["method"] == "GET":
                        form_info["issues"].append(
                            "⚠️ نموذج الدفع يستخدم GET بدلاً من POST"
                        )
                        self._deduct_score(20)

                    # فحص CSRF token
                    csrf_fields = form.find_all(
                        "input",
                        attrs={"name": re.compile(r"csrf|token|_token", re.I)}
                    )
                    if not csrf_fields:
                        form_info["issues"].append(
                            "⚠️ لا يوجد CSRF Token في نموذج الدفع"
                        )
                        self._deduct_score(15)

                    payment_forms.append(form_info)

        except Exception as e:
            payment_forms.append({"error": str(e)[:100]})

        self.results["payment_forms"] = payment_forms
        return payment_forms

    # ══════════════════════════════════════
    #       تحديد مستوى الخطر
    # ══════════════════════════════════════

    def _calculate_risk_level(self):
        """حساب مستوى الخطر الإجمالي"""
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
    #       دالة لتوليد التقرير الكامل
    # ══════════════════════════════════════

    def generate_full_report(self) -> str:
        """توليد تقرير كامل مع المفاتيح مكشوفة بالكامل"""
        report = []
        report.append("╔══════════════════════════════╗")
        report.append("║   🔍 تقرير فحص الأمان الشامل   ║")
        report.append("╚══════════════════════════════╝")
        report.append("")
        report.append(f"🌐 الموقع: {self.results['url']}")
        report.append(f"🏷️ النطاق: {self.results['domain']}")
        report.append(f"🕐 وقت الفحص: {self.results['scan_time']}")
        report.append("")
        report.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        report.append(f"📊 درجة الأمان: {self.results['score']}/100")
        bar_length = 20
        filled = int(bar_length * self.results['score'] / 100)
        bar = "█" * filled + "░" * (bar_length - filled)
        report.append(f"[{bar}] {self.results['score']}%")
        
        risk_icons = {"LOW": "🟢 منخفض", "MEDIUM": "🟡 متوسط", "HIGH": "🟠 مرتفع", "CRITICAL": "🔴 خطر حرج"}
        report.append(f"⚠️ مستوى الخطر: {risk_icons.get(self.results['risk_level'], 'غير معروف')}")
        report.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        report.append("")
        
        # SSL Info
        ssl_info = self.results.get("ssl_info", {})
        report.append("🔒 فحص SSL/HTTPS")
        report.append("")
        report.append(f"  {'✅' if ssl_info.get('has_ssl') else '❌'} الموقع {'يستخدم' if ssl_info.get('has_ssl') else 'لا يستخدم'} HTTPS")
        if ssl_info.get('has_ssl'):
            report.append(f"  {'✅' if ssl_info.get('valid') else '❌'} الشهادة {'صالحة' if ssl_info.get('valid') else 'غير صالحة'}")
            if ssl_info.get('expiry_date'):
                report.append(f"  📅 تنتهي في: {ssl_info['expiry_date']} ({ssl_info.get('days_remaining', '?')} يوم)")
            if ssl_info.get('issuer'):
                report.append(f"  🏢 المُصدر: {ssl_info['issuer']}")
            if ssl_info.get('version'):
                report.append(f"  🔐 الإصدار: {ssl_info['version']}")
        for issue in ssl_info.get('issues', []):
            report.append(f"  {issue}")
        report.append("")
        
        # Security Headers
        headers_info = self.results.get("security_headers", {})
        report.append("🛡️ فحص Security Headers")
        report.append("")
        
        present_headers = []
        missing_headers = []
        
        for header, info in headers_info.items():
            if header == "error":
                continue
            if isinstance(info, dict) and info.get("present"):
                present_headers.append(f"  ✅ {header}")
            elif isinstance(info, dict):
                missing_headers.append(f"  ❌ {header} — {info.get('description', '')[:50]}")
        
        if present_headers:
            report.append("✅ موجودة:")
            report.extend(present_headers)
            report.append("")
        
        if missing_headers:
            report.append("🟢 مفقودة:")
            report.extend(missing_headers)
            report.append("")
        
        # 🔓 Exposed Keys - FULL (كاملاً)
        exposed = self.results.get("exposed_keys", [])
        if exposed:
            report.append("🔑 المفاتيح المكشوفة — 🔴 تحذير: {} مفتاح مكشوف!".format(len(exposed)))
            report.append("")
            for i, key_info in enumerate(exposed, 1):
                report.append(f"  {i}. 🔴 {key_info.get('type', 'مفتاح غير معروف')}")
                report.append(f"     📍 الصفحة: {key_info.get('page', 'غير معروف')}")
                report.append(f"     🔑 المفتاح (كاملاً): {key_info.get('value_full', 'غير معروف')}")
                report.append("")
            report.append("  ⚡ الإجراء الفوري المطلوب:")
            report.append("  • أوقف استخدام هذه المفاتيح فوراً")
            report.append("  • أنشئ مفاتيح جديدة من لوحة التحكم")
            report.append("  • لا تضع المفاتيح في كود Frontend أبداً")
            report.append("  • استخدم متغيرات البيئة Environment Variables")
            report.append("")
        else:
            report.append("🔑 المفاتيح المكشوفة — ✅ لم يتم العثور على مفاتيح مكشوفة")
            report.append("")
        
        # Payment Forms
        forms = self.results.get("payment_forms", [])
        if forms:
            report.append("💳 نماذج الدفع — تم العثور على {} نموذج".format(len(forms)))
            report.append("")
            for i, form in enumerate(forms, 1):
                if "error" in form:
                    report.append(f"  {i}. ❌ خطأ: {form['error']}")
                else:
                    report.append(f"  {i}. ⚠️ النموذج {i}")
                    report.append(f"     • Action: {form.get('action', 'غير محدد')}")
                    report.append(f"     • Method: {form.get('method', 'GET')}")
                    for issue in form.get('issues', []):
                        report.append(f"     {issue}")
                report.append("")
        else:
            report.append("💳 نماذج الدفع — ✅ لم يتم العثور على نماذج دفع")
            report.append("")
        
        # Recommendations
        report.append("💡 التوصيات والحلول")
        report.append("")
        report.append("  1. 🛡️ إضافة Security Headers")
        report.append("     أضف هذا في إعدادات السيرفر (Nginx):")
        report.append('add_header Strict-Transport-Security "max-age=31536000";')
        report.append('add_header X-Frame-Options "DENY";')
        report.append('add_header X-Content-Type-Options "nosniff";')
        report.append('add_header X-XSS-Protection "1; mode=block";')
        report.append("")
        
        if exposed:
            report.append("  2. 🔑 إخفاء المفاتيح السرية")
            report.append("     • احذف المفاتيح من الكود فوراً")
            report.append("     • استخدم متغيرات البيئة:")
            report.append("       export STRIPE_KEY=sk_live_xxxx")
            report.append("")
            report.append("     • في الكود:")
            report.append("       import os")
            report.append("       stripe_key = os.getenv('STRIPE_KEY')")
            report.append("")
        
        if forms:
            report.append("  3. 💳 تأمين نماذج الدفع")
            report.append("     • استخدم POST بدلاً من GET")
            report.append("     • أضف CSRF Token لكل نموذج")
            report.append("     • تأكد أن Action يبدأ بـ https://")
            report.append("")
        
        report.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        report.append("🤖 تم الفحص بواسطة Security Scanner Bot")
        report.append("⚠️ هذا الفحص للأغراض الدفاعية فقط")
        report.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        report.append("")
        report.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        report.append("👨‍💻 المطور: Mustafa")
        report.append("📱 تواصل: @o8380")
        report.append("📢 القناة: @Mustafa964iq")
        report.append("🔖 الإصدار: 2.0.0")
        report.append("©️ جميع الحقوق محفوظة © 2026")
        report.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        return "\n".join(report)

    # ══════════════════════════════════════
    #       الفحص الشامل
    # ══════════════════════════════════════

    def run_full_scan(self) -> dict:
        """تشغيل الفحص الكامل"""
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # تشغيل جميع الفحوصات
        self.scan_ssl()
        self.scan_security_headers()
        self.scan_exposed_keys()
        self.scan_payment_forms()
        self._calculate_risk_level()

        return self.results


# ════════════════════════════════════════════════════════════
#   مثال للتشغيل المباشر
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("🔗 أدخل رابط الموقع للفحص: ").strip()
    
    print("\n🚀 بدء الفحص الشامل...\n")
    scanner = PaymentScanner(url)
    results = scanner.run_full_scan()
    
    # طباعة التقرير الكامل
    report = scanner.generate_full_report()
    print(report)
    
    # حفظ التقرير في ملف
    with open(f"scan_report_{scanner.domain}.txt", "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n📁 تم حفظ التقرير في: scan_report_{scanner.domain}.txt")

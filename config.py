import os
from dotenv import load_dotenv

load_dotenv()

# ══════════════════════════════════════
#        إعدادات البوت الأساسية
# ══════════════════════════════════════
# التوكن يُقرأ من البيئة فقط - بدون قيمة افتراضية!
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_IDS = [int(x) for x in os.getenv("ADMIN_IDS", "0").split(",")]# ══════════════════════════════════════

# ══════════════════════════════════════
#     معلومات المطور وحقوق الملكية
# ══════════════════════════════════════
DEVELOPER = {
    "name":     "Mustafa",
    "username": "@o8380",
    "version":  "1.0.0",
}
#        إعدادات الفحص
# ══════════════════════════════════════
SCAN_TIMEOUT = 10          # ثواني
MAX_PAGES_SCAN = 5         # عدد الصفحات المفحوصة
REQUEST_DELAY = 0.5        # تأخير بين الطلبات

# ══════════════════════════════════════
#     أنماط المفاتيح المكشوفة
# ══════════════════════════════════════
PAYMENT_KEY_PATTERNS = {

    "Stripe Secret Key": [
        r"sk_live_[0-9a-zA-Z]{24,}",
        r"sk_test_[0-9a-zA-Z]{24,}",
    ],

    "Stripe Publishable Key": [
        r"pk_live_[0-9a-zA-Z]{24,}",
        r"pk_test_[0-9a-zA-Z]{24,}",
    ],

    "PayPal Client ID": [
        r"AZ[a-zA-Z0-9_-]{76}",
        r"client_id['\"\s]*[:=]['\"\s]*([A-Za-z0-9_-]{20,})",
    ],

    "PayPal Secret": [
        r"EL[a-zA-Z0-9_-]{76}",
        r"client_secret['\"\s]*[:=]['\"\s]*([A-Za-z0-9_-]{20,})",
    ],

    "Square Access Token": [
        r"sq0atp-[0-9a-zA-Z\-_]{22,}",
        r"sq0csp-[0-9a-zA-Z\-_]{43,}",
        r"EAAAE[a-zA-Z0-9_-]{60,}",
    ],

    "Braintree Token": [
        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    ],

    "Stripe Webhook Secret": [
        r"whsec_[a-zA-Z0-9]{32,}",
    ],

    "Generic API Key": [
        r"api[_-]?key['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_\-]{20,})",
        r"apikey['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_\-]{20,})",
        r"secret[_-]?key['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_\-]{20,})",
    ],
}

# ══════════════════════════════════════
#     Security Headers المطلوبة
# ══════════════════════════════════════
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "يحمي من هجمات MITM",
        "recommended": "max-age=31536000; includeSubDomains",
        "severity": "HIGH"
    },
    "Content-Security-Policy": {
        "description": "يمنع XSS وحقن الكود",
        "recommended": "default-src 'self'",
        "severity": "HIGH"
    },
    "X-Frame-Options": {
        "description": "يمنع Clickjacking",
        "recommended": "DENY أو SAMEORIGIN",
        "severity": "MEDIUM"
    },
    "X-Content-Type-Options": {
        "description": "يمنع MIME sniffing",
        "recommended": "nosniff",
        "severity": "MEDIUM"
    },
    "X-XSS-Protection": {
        "description": "حماية إضافية من XSS",
        "recommended": "1; mode=block",
        "severity": "MEDIUM"
    },
    "Referrer-Policy": {
        "description": "يتحكم في معلومات Referrer",
        "recommended": "strict-origin-when-cross-origin",
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "description": "يتحكم في صلاحيات المتصفح",
        "recommended": "geolocation=(), microphone=()",
        "severity": "LOW"
    },
}

# ══════════════════════════════════════
#     درجات الخطورة
# ══════════════════════════════════════
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}

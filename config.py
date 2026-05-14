import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_IDS = [int(x) for x in os.getenv("ADMIN_IDS", "0").split(",")]

if not BOT_TOKEN:
    raise ValueError("❌ BOT_TOKEN غير موجود!")

DEVELOPER = {
    "name":    "Mustafa",
    "username": "@your_username",
    "version":  "1",
 
}

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
AI_MODEL       = "gpt-4o"
AI_MAX_TOKENS  = 2000
AI_TEMPERATURE = 0.7

AI_SYSTEM_PROMPT = """
أنت مساعد ذكي احترافي متخصص في:
1. برمجة Python بشكل عام
2. تطوير بوتات تيليغرام بـ Aiogram
3. أمن المواقع وبوابات الدفع
4. اكتشاف وإصلاح الثغرات الأمنية
5. تكامل بوابات الدفع Stripe وPayPal
6. تطوير الويب بشكل عام

قواعد:
- أجب دائماً بالعربية بشكل واضح ومنظم
- اكتب الكود كاملاً وقابلاً للتشغيل
- اشرح كل خطوة بوضوح
- استخدم Emoji لتنظيم الإجابات
- إذا طُلب تعديل كود أعده كاملاً
- لا تساعد في أي شيء غير قانوني
"""

SCAN_TIMEOUT   = 10
MAX_PAGES_SCAN = 5
REQUEST_DELAY  = 0.5

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

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}

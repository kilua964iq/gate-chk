from openai import OpenAI
from config import (
    OPENAI_API_KEY,
    AI_MODEL,
    AI_MAX_TOKENS,
    AI_TEMPERATURE,
    AI_SYSTEM_PROMPT,
)

client = OpenAI(api_key=OPENAI_API_KEY)


class AIAssistant:

    def __init__(self):
        self.conversations = {}

    async def chat(self, user_id: int, user_message: str) -> str:
        try:
            if user_id not in self.conversations:
                self.conversations[user_id] = [
                    {"role": "system", "content": AI_SYSTEM_PROMPT}
                ]

            self.conversations[user_id].append({
                "role": "user",
                "content": user_message
            })

            if len(self.conversations[user_id]) > 20:
                self.conversations[user_id] = (
                    [self.conversations[user_id][0]] +
                    self.conversations[user_id][-18:]
                )

            response = client.chat.completions.create(
                model=AI_MODEL,
                messages=self.conversations[user_id],
                max_tokens=AI_MAX_TOKENS,
                temperature=AI_TEMPERATURE,
            )

            ai_reply = response.choices[0].message.content

            self.conversations[user_id].append({
                "role": "assistant",
                "content": ai_reply
            })

            return ai_reply

        except Exception as e:
            return self._handle_error(e)

    async def analyze_scan_results(self, scan_results: dict) -> str:
        try:
            score        = scan_results.get("score", 0)
            risk         = scan_results.get("risk_level", "UNKNOWN")
            ssl_info     = scan_results.get("ssl_info", {})
            headers      = scan_results.get("security_headers", {})
            exposed_keys = scan_results.get("exposed_keys", [])
            forms        = scan_results.get("payment_forms", [])

            missing_headers = [
                h for h, info in headers.items()
                if isinstance(info, dict) and not info.get("present")
            ]

            prompt = f"""
حلل نتائج فحص الأمان التالية وقدم تقرير احترافي:

الموقع: {scan_results.get('url', 'N/A')}
درجة الأمان: {score}/100
مستوى الخطر: {risk}

SSL:
- HTTPS: {'نعم' if ssl_info.get('has_ssl') else 'لا'}
- الشهادة صالحة: {'نعم' if ssl_info.get('valid') else 'لا'}
- أيام متبقية: {ssl_info.get('days_remaining', 'N/A')}
- المُصدر: {ssl_info.get('issuer', 'N/A')}

Headers المفقودة: {', '.join(missing_headers) if missing_headers else 'لا يوجد'}
مفاتيح مكشوفة: {len(exposed_keys)}
نماذج دفع: {len(forms)}

اكتب تقرير يشمل:
1. ملخص الوضع الأمني
2. أخطر 3 مشاكل يجب حلها فوراً
3. خطوات الحل لكل مشكلة
4. توصيات إضافية
5. الوقت المتوقع للإصلاح
"""

            response = client.chat.completions.create(
                model=AI_MODEL,
                messages=[
                    {"role": "system", "content": AI_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.4,
            )

            return response.choices[0].message.content

        except Exception as e:
            return self._handle_error(e)

    async def review_code(self, user_id: int, code: str) -> str:
        try:
            prompt = f"""
راجع الكود التالي وقدم:
1. الأخطاء الموجودة
2. الثغرات الأمنية
3. تحسينات الأداء
4. الكود المصحح كاملاً

الكود:
```
{code}
```
"""
            response = client.chat.completions.create(
                model=AI_MODEL,
                messages=[
                    {"role": "system", "content": AI_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.3,
            )

            return response.choices[0].message.content

        except Exception as e:
            return self._handle_error(e)

    def _handle_error(self, e: Exception) -> str:
        error = str(e).lower()
        if "api_key" in error or "authentication" in error:
            return "❌ مفتاح OpenAI غير صحيح"
        elif "rate_limit" in error:
            return "⚠️ تجاوزت حد الطلبات، انتظر دقيقة"
        elif "insufficient_quota" in error:
            return "❌ رصيد OpenAI منتهي"
        elif "context_length" in error:
            return "⚠️ الرسالة طويلة جداً، اختصرها"
        else:
            return f"❌ خطأ: {str(e)[:150]}"

    def clear_conversation(self, user_id: int):
        if user_id in self.conversations:
            del self.conversations[user_id]

    def get_stats(self, user_id: int) -> dict:
        msgs = self.conversations.get(user_id, [])
        return {
            "messages":    len(msgs),
            "has_context": user_id in self.conversations,
        }


ai_assistant = AIAssistant()

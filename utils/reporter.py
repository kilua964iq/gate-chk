from config import SEVERITY_EMOJI


class ReportGenerator:

    def __init__(self, scan_results: dict):
        self.results = scan_results

    def _build_score_bar(self, score: int) -> str:
        filled = int(score / 10)
        empty  = 10 - filled
        bar    = "█" * filled + "░" * empty
        return f"`[{bar}]` {score}%"

    def _build_header(self) -> str:
        risk  = self.results.get("risk_level", "UNKNOWN")
        score = self.results.get("score", 0)

        risk_badges = {
            "CRITICAL": "🔴 خطر حرج",
            "HIGH":     "🟠 خطر عالي",
            "MEDIUM":   "🟡 خطر متوسط",
            "LOW":      "🟢 آمن نسبياً",
        }

        return (
            "╔══════════════════════════════╗\n"
            "║   🔍 تقرير فحص الأمان الشامل   ║\n"
            "╚══════════════════════════════╝\n\n"
            f"🌐 **الموقع:** `{self.results.get('url', 'N/A')}`\n"
            f"🏷️ **النطاق:** `{self.results.get('domain', 'N/A')}`\n"
            f"🕐 **وقت الفحص:** `{self.results.get('scan_time', 'N/A')}`\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📊 **درجة الأمان:** {score}/100\n"
            f"{self._build_score_bar(score)}\n"
            f"⚠️ **مستوى الخطر:** {risk_badges.get(risk, risk)}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        )

    def _build_ssl_section(self) -> str:
        ssl_info = self.results.get("ssl_info", {})
        if not ssl_info:
            return ""

        lines = ["🔒 **فحص SSL/HTTPS**\n"]

        if ssl_info.get("has_ssl"):
            lines.append("  ✅ الموقع يستخدم HTTPS")
        else:
            lines.append("  ❌ الموقع لا يستخدم HTTPS")

        if ssl_info.get("valid"):
            lines.append("  ✅ الشهادة صالحة")

        if ssl_info.get("expiry_date"):
            days  = ssl_info.get("days_remaining", 0)
            emoji = "✅" if days > 30 else "⚠️" if days > 0 else "❌"
            lines.append(
                f"  {emoji} تنتهي في: `{ssl_info['expiry_date']}` "
                f"({days} يوم)"
            )

        if ssl_info.get("issuer"):
            lines.append(f"  🏢 المُصدر: `{ssl_info['issuer']}`")

        if ssl_info.get("version"):
            lines.append(f"  🔐 الإصدار: `{ssl_info['version']}`")

        for issue in ssl_info.get("issues", []):
            lines.append(f"  {issue}")

        return "\n".join(lines) + "\n\n"

    def _build_headers_section(self) -> str:
        headers = self.results.get("security_headers", {})
        if not headers or "error" in headers:
            error = headers.get("error", "خطأ غير معروف")
            return f"🛡️ **Security Headers**\n  ⚠️ {error}\n\n"

        lines          = ["🛡️ **فحص Security Headers**\n"]
        missing_high   = []
        missing_medium = []
        missing_low    = []
        present_headers = []

        for header, info in headers.items():
            if isinstance(info, dict):
                if info.get("present"):
                    present_headers.append(f"  ✅ `{header}`")
                else:
                    severity = info.get("severity", "LOW")
                    entry = (
                        f"  ❌ `{header}` — "
                        f"{info.get('description', '')}"
                    )
                    if severity == "HIGH":
                        missing_high.append(entry)
                    elif severity == "MEDIUM":
                        missing_medium.append(entry)
                    else:
                        missing_low.append(entry)

        if present_headers:
            lines.append("**✅ موجودة:**")
            lines.extend(present_headers)

        if missing_high:
            lines.append("\n**🔴 مفقودة (عالية الخطورة):**")
            lines.extend(missing_high)

        if missing_medium:
            lines.append("\n**🟡 مفقودة (متوسطة الخطورة):**")
            lines.extend(missing_medium)

        if missing_low:
            lines.append("\n**🟢 مفقودة (منخفضة الخطورة):**")
            lines.extend(missing_low)

        return "\n".join(lines) + "\n\n"

    def _build_exposed_keys_section(self) -> str:
        keys = self.results.get("exposed_keys", [])

        if not keys:
            return (
                "🔑 **المفاتيح المكشوفة**\n"
                "  ✅ لم يتم اكتشاف مفاتيح مكشوفة\n\n"
            )

        lines = [
            f"🔑 **المفاتيح المكشوفة** — "
            f"🔴 تحذير: {len(keys)} مفتاح مكشوف!\n"
        ]

        for i, key in enumerate(keys, 1):
            lines.append(
                f"  {i}. 🔴 **{key['type']}**\n"
                f"     📍 الصفحة: `{key['page'][:60]}`\n"
                f"     🔑 المفتاح الكامل: `{key['value_full']}`\n"
            )

        lines.append(
            "  ⚡ **الإجراء الفوري المطلوب:**\n"
            "  • أوقف استخدام هذه المفاتيح فوراً\n"
            "  • أنشئ مفاتيح جديدة من لوحة التحكم\n"
            "  • لا تضع المفاتيح في كود Frontend\n"
            "  • استخدم متغيرات البيئة\n"
        )

        return "\n".join(lines) + "\n"

    def _build_payment_forms_section(self) -> str:
        forms = self.results.get("payment_forms", [])

        if not forms:
            return (
                "💳 **نماذج الدفع**\n"
                "  ℹ️ لم يتم العثور على نماذج دفع\n\n"
            )

        lines = [
            f"💳 **نماذج الدفع** — "
            f"تم العثور على {len(forms)} نموذج\n"
        ]

        for i, form in enumerate(forms, 1):
            if "error" in form:
                lines.append(f"  {i}. ⚠️ خطأ: {form['error']}")
                continue

            status = "✅" if not form.get("issues") else "⚠️"
            action = form.get("action", "N/A")[:50]
            method = form.get("method", "N/A")

            lines.append(f"  {i}. {status} النموذج {i}")
            lines.append(f"     • Action: `{action}`")
            lines.append(f"     • Method: `{method}`")

            for issue in form.get("issues", []):
                lines.append(f"     {issue}")

        return "\n".join(lines) + "\n\n"

    def _build_recommendations_section(self) -> str:
        lines   = ["💡 **التوصيات والحلول**\n"]
        ssl_info = self.results.get("ssl_info", {})
        headers  = self.results.get("security_headers", {})
        keys     = self.results.get("exposed_keys", [])
        forms    = self.results.get("payment_forms", [])
        rec_num  = 1

        if not ssl_info.get("has_ssl"):
            lines.append(
                f"  {rec_num}. 🔒 **تفعيل HTTPS**\n"
                "     احصل على شهادة SSL من Let's Encrypt\n"
                "     https://letsencrypt.org\n"
            )
            rec_num += 1

        days = ssl_info.get("days_remaining", 999)
        if 0 < days < 30:
            lines.append(
                f"  {rec_num}. 🔄 **تجديد شهادة SSL**\n"
                f"     الشهادة ستنتهي خلال {days} يوم\n"
            )
            rec_num += 1

        missing_headers = [
            h for h, info in headers.items()
            if isinstance(info, dict) and not info.get("present")
        ]

        if missing_headers:
            lines.append(
                f"  {rec_num}. 🛡️ **إضافة Security Headers**\n"
                "     أضف في إعدادات Nginx:\n"
                "```\n"
                "add_header Strict-Transport-Security "
                "\"max-age=31536000\";\n"
                "add_header X-Frame-Options \"DENY\";\n"
                "add_header X-Content-Type-Options \"nosniff\";\n"
                "add_header X-XSS-Protection \"1; mode=block\";\n"
                "```\n"
            )
            rec_num += 1

        if keys:
            lines.append(
                f"  {rec_num}. 🔑 **إخفاء المفاتيح السرية**\n"
                "     • احذف المفاتيح من الكود فوراً\n"
                "     • استخدم متغيرات البيئة:\n"
                "```python\n"
                "import os\n"
                "stripe_key = os.getenv('STRIPE_KEY')\n"
                "```\n"
            )
            rec_num += 1

        has_form_issues = any(
            form.get("issues")
            for form in forms
            if isinstance(form, dict)
        )
        if has_form_issues:
            lines.append(
                f"  {rec_num}. 💳 **تأمين نماذج الدفع**\n"
                "     • استخدم POST بدلاً من GET\n"
                "     • أضف CSRF Token\n"
                "     • تأكد أن Action يبدأ بـ https://\n"
            )
            rec_num += 1

        if rec_num == 1:
            lines.append("  ✅ لا توجد توصيات، الموقع آمن!\n")

        return "\n".join(lines) + "\n"

    def _build_footer(self) -> str:
        return (
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "🤖 **تم الفحص بواسطة Security Scanner Bot**\n"
            "⚠️ هذا الفحص للأغراض الدفاعية فقط\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )

    def generate_full_report(self) -> str:
        report  = ""
        report += self._build_header()
        report += self._build_ssl_section()
        report += self._build_headers_section()
        report += self._build_exposed_keys_section()
        report += self._build_payment_forms_section()
        report += self._build_recommendations_section()
        report += self._build_footer()
        return report

    def generate_short_report(self) -> str:
        score     = self.results.get("score", 0)
        risk      = self.results.get("risk_level", "UNKNOWN")
        keys_count = len(self.results.get("exposed_keys", []))
        ssl_ok    = self.results.get("ssl_info", {}).get("valid", False)

        risk_badges = {
            "CRITICAL": "🔴 خطر حرج",
            "HIGH":     "🟠 خطر عالي",
            "MEDIUM":   "🟡 خطر متوسط",
            "LOW":      "🟢 آمن نسبياً",
        }

        return (
            f"📊 **ملخص الفحص**\n\n"
            f"🌐 `{self.results.get('url', 'N/A')}`\n"
            f"📈 الدرجة: **{score}/100**\n"
            f"⚠️ الخطر: {risk_badges.get(risk, risk)}\n"
            f"🔒 SSL: {'✅' if ssl_ok else '❌'}\n"
            f"🔑 مفاتيح مكشوفة: "
            f"{'🔴 ' + str(keys_count) if keys_count else '✅ لا يوجد'}\n"
        )

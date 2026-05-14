from config import SEVERITY_EMOJI


class ReportGenerator:
    """
    مولّد تقارير احترافي لنتائج الفحص
    """

    def __init__(self, scan_results: dict):
        self.results = scan_results

    # ══════════════════════════════════════
    #       الرأس والمعلومات العامة
    # ══════════════════════════════════════

    def _build_header(self) -> str:
        risk = self.results.get("risk_level", "UNKNOWN")
        score = self.results.get("score", 0)

        risk_badges = {
            "CRITICAL": "🔴 خطر حرج",
            "HIGH":     "🟠 خطر عالي",
            "MEDIUM":   "🟡 خطر متوسط",
            "LOW":      "🟢 آمن نسبياً",
        }

        score_bar = self._build_score_bar(score)

        return (
            f"╔══════════════════════════════╗\n"
            f"║   🔍 تقرير فحص الأمان الشامل   ║\n"
            f"╚══════════════════════════════╝\n\n"
            f"🌐 **الموقع:** `{self.results.get('url', 'N/A')}`\n"
            f"🏷️ **النطاق:** `{self.results.get('domain', 'N/A')}`\n"
            f"🕐 **وقت الفحص:** `{self.results.get('scan_time', 'N/A')}`\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📊 **درجة الأمان:** {score}/100\n"
            f"{score_bar}\n"
            f"⚠️ **مستوى الخطر:** {risk_badges.get(risk, risk)}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        )

    def _build_score_bar(self, score: int) -> str:
        """بناء شريط مرئي لدرجة الأمان"""
        filled = int(score / 10)
        empty = 10 - filled
        bar = "█" * filled + "░" * empty
        return f"`[{bar}]` {score}%"

    # ══════════════════════════════════════
    #       قسم SSL
    # ══════════════════════════════════════

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
            lines.append(f"  ✅ الشهادة صالحة")

        if ssl_info.get("expiry_date"):
            days = ssl_info.get("days_remaining", 0)
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

    # ══════════════════════════════════════
    #       قسم Security Headers
    # ══════════════════════════════════════

    def _build_headers_section(self) -> str:
        headers = self.results.get("security_headers", {})
        if not headers or "error" in headers:
            error = headers.get("error", "خطأ غير معروف")
            return f"🛡️ **Security Headers**\n  ⚠️ {error}\n\n"

        lines = ["🛡️ **فحص Security Headers**\n"]

        missing_high = []
        missing_medium = []
        missing_low = []
        present_headers = []

        for header, info in headers.items():
            if isinstance(info, dict):
                if info.get("present"):
                    present_headers.append(f"  ✅ `{header}`")
                else:
                    severity = info.get("severity", "LOW")
                    entry = f"  ❌ `{header}` — {info.get('description', '')}"
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

    # ══════════════════════════════════════
    #       قسم المفاتيح المكشوفة
    # ══════════════════════════════════════

    def _build_exposed_keys_section(self) -> str:
        keys = self.results.get("exposed_keys", [])

        if not keys:
            return "🔑 **المفاتيح المكشوفة**\n  ✅ لم يتم اكتشاف مفاتيح مكشوفة\n\n"

        lines = [
            f"🔑 **المفاتيح المكشوفة** — "
            f"🔴 تحذير: {len(keys)} مفتاح مكشوف!\n"
        ]

        for i, key in enumerate(keys, 1):
            lines.append(
                f"  {i}. 🔴 **{key['type']}**\n"
                f"     📍 الصفحة: `{key['page'][:60]}...`\n"
                f"     🔑 المفتاح: `{key['value_masked']}`\n"
            )

        lines.append(
            "  ⚡ **الإجراء الفوري المطلوب:**\n"
            "  • أوقف استخدام هذه المفاتيح فوراً\n"
            "  • أنشئ مفاتيح جديدة من لوحة التحكم\n"
            "  • لا تضع المفاتيح في كود Frontend أبداً\n"
            "  • استخدم متغيرات البيئة Environment Variables\n"
        )

        return "\n".join(lines) + "\n"

    # ══════════════════════════════════════
    #       قسم نماذج الدفع
    # ══════════════════════════════════════

    def _build_payment_forms_section(self) -> str:
        forms = self.results.get("payment_forms", [])

        if not forms:
            return "💳 **نماذج الدفع**\n  ℹ️ لم يتم العثور على نماذج دفع\n\n"

        lines = [f"💳 **نماذج الدفع** — تم العثور على {len(forms)} نموذج\n"]

        for i, form in enumerate(forms, 1):
            if "error" in form:
                lines.append(f"  {i}. ⚠️ خطأ: {form['error']}")
                continue

            status = "✅" if not form.get("issues") else "⚠️"
            lines.append(
                f"  {i}. {status} النموذج {i}\n"
                f"     • Action: `{form.get('action', 'N/A')[:50]}`\n"
                f"


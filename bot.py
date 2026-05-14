import asyncio
import logging
import urllib3
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    Message,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    CallbackQuery,
)
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

from config import BOT_TOKEN, ADMIN_IDS
from scanners.payment_scanner import PaymentScanner
from utils.reporter import ReportGenerator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ══════════════════════════════════════
#           إعداد اللوغينق
# ══════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════
#           إعداد البوت
# ══════════════════════════════════════
bot = Bot(token=BOT_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(storage=storage)


# ══════════════════════════════════════
#           حالات FSM
# ══════════════════════════════════════
class ScanStates(StatesGroup):
    waiting_for_url = State()


# ══════════════════════════════════════
#       لوحة المفاتيح الرئيسية
# ══════════════════════════════════════
def get_main_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton(
                text="🔍 فحص موقع جديد",
                callback_data="start_scan"
            )
        ],
        [
            InlineKeyboardButton(
                text="📖 كيف يعمل البوت؟",
                callback_data="how_it_works"
            ),
            InlineKeyboardButton(
                text="⚙️ الفحوصات المتاحة",
                callback_data="scan_types"
            ),
        ],
        [
            InlineKeyboardButton(
                text="👨‍💻 تواصل مع المطور",
                url="https://t.me/your_username"
            )
        ],
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def get_cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ إلغاء", callback_data="cancel")]
    ])


def get_after_scan_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [
            InlineKeyboardButton(
                text="🔍 فحص موقع آخر",
                callback_data="start_scan"
            )
        ],
        [
            InlineKeyboardButton(
                text="🏠 القائمة الرئيسية",
                callback_data="main_menu"
            )
        ],
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


# ══════════════════════════════════════
#       /start
# ══════════════════════════════════════
@dp.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    user_name = message.from_user.first_name or "مستخدم"

    welcome_text = (
        f"👋 أهلاً **{user_name}**!\n\n"
        "🤖 أنا بوت فحص أمان بوابات الدفع\n\n"
        "🛡️ **ما الذي أفحصه؟**\n"
        "  🔒 شهادة SSL وصلاحيتها\n"
        "  🛡️ رؤوس الأمان HTTP Headers\n"
        "  🔑 المفاتيح المكشوفة (Stripe, PayPal...)\n"
        "  💳 أمان نماذج الدفع\n"
        "  📊 تقرير شامل مع الحلول\n\n"
        "⚡ اضغط الزر أدناه لبدء الفحص!"
    )

    await message.answer(
        welcome_text,
        reply_markup=get_main_keyboard(),
        parse_mode="Markdown"
    )


# ══════════════════════════════════════
#       /scan
# ══════════════════════════════════════
@dp.message(Command("scan"))
async def cmd_scan(message: Message, state: FSMContext):
    await state.set_state(ScanStates.waiting_for_url)
    await message.answer(
        "🔍 **أرسل رابط الموقع المراد فحصه:**\n\n"
        "📌 **أمثلة:**\n"
        "  • `https://example.com`\n"
        "  • `example.com`\n"
        "  • `www.example.com`\n\n"
        "⚠️ تأكد أن الموقع عام وليس خاصاً",
        reply_markup=get_cancel_keyboard(),
        parse_mode="Markdown"
    )


# ══════════════════════════════════════
#       /help
# ══════════════════════════════════════
@dp.message(Command("help"))
async def cmd_help(message: Message):
    help_text = (
        "📚 **دليل الاستخدام**\n\n"
        "**الأوامر المتاحة:**\n"
        "  /start — الصفحة الرئيسية\n"
        "  /scan — بدء فحص موقع\n"
        "  /help — هذه الرسالة\n\n"
        "**كيفية الاستخدام:**\n"
        "  1️⃣ اضغط /scan أو زر الفحص\n"
        "  2️⃣ أرسل رابط الموقع\n"
        "  3️⃣ انتظر نتائج الفحص\n"
        "  4️⃣ اقرأ التقرير والحلول\n\n"
        "**ملاحظة مهمة:**\n"
        "  ⚠️ استخدم البوت فقط على مواقعك\n"
        "  ✅ البوت للفحص الدفاعي فقط\n"
    )
    await message.answer(help_text, parse_mode="Markdown")


# ══════════════════════════════════════
#       Callback Handlers
# ══════════════════════════════════════
@dp.callback_query(F.data == "start_scan")
async def cb_start_scan(callback: CallbackQuery, state: FSMContext):
    await state.set_state(ScanStates.waiting_for_url)
    await callback.message.edit_text(
        "🔍 **أرسل رابط الموقع المراد فحصه:**\n\n"
        "📌 **أمثلة:**\n"
        "  • `https://example.com`\n"
        "  • `example.com`\n"
        "  • `www.example.com`\n\n"
        "⚠️ تأكد أن الموقع عام وليس خاصاً",
        reply_markup=get_cancel_keyboard(),
        parse_mode="Markdown"
    )
    await callback.answer()


@dp.callback_query(F.data == "main_menu")
async def cb_main_menu(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await callback.message.edit_text(
        "🏠 **القائمة الرئيسية**\n\n"
        "اختر ما تريد:",
        reply_markup=get_main_keyboard(),
        parse_mode="Markdown"
    )
    await callback.answer()


@dp.callback_query(F.data == "cancel")
async def cb_cancel(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await callback.message.edit_text(
        "❌ **تم الإلغاء**\n\n"
        "يمكنك البدء من جديد:",
        reply_markup=get_main_keyboard(),
        parse_mode="Markdown"
    )
    await callback.answer("تم الإلغاء")


@dp.callback_query(F.data == "how_it_works")
async def cb_how_it_works(callback: CallbackQuery):
    text = (
        "📖 **كيف يعمل البوت؟**\n\n"
        "1️⃣ **فحص SSL**\n"
        "   يتحقق من صلاحية الشهادة وتاريخ انتهائها\n\n"
        "2️⃣ **Security Headers**\n"
        "   يفحص 7 رؤوس أمان أساسية\n\n"
        "3️⃣ **المفاتيح المكشوفة**\n"
        "   يبحث عن مفاتيح Stripe وPayPal وغيرها\n\n"
        "4️⃣ **نماذج الدفع**\n"
        "   يتحقق من أمان نماذج إدخال بيانات البطاقة\n\n"
        "5️⃣ **التقرير النهائي**\n"
        "   درجة أمان + مستوى الخطر + الحلول\n"
    )
    back_btn = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔙 رجوع", callback_data="main_menu")]
    ])
    await callback.message.edit_text(
        text,
        reply_markup=back_btn,
        parse_mode="Markdown"
    )
    await callback.answer()


@dp.callback_query(F.data == "scan_types")
async def cb_scan_types(callback: CallbackQuery):
    text = (
        "⚙️ **الفحوصات المتاحة**\n\n"
        "🔒 **SSL/HTTPS**\n"
        "   • صلاحية الشهادة\n"
        "   • تاريخ الانتهاء\n"
        "   • المُصدر والإصدار\n\n"
        "🛡️ **Security Headers**\n"
        "   • HSTS\n"
        "   • CSP\n"
        "   • X-Frame-Options\n"
        "   • X-Content-Type-Options\n"
        "   • وأكثر...\n\n"
        "🔑 **المفاتيح المكشوفة**\n"
        "   • Stripe (Live & Test)\n"
        "   • PayPal Client ID & Secret\n"
        "   • Square Access Token\n"
        "   • Braintree Token\n"
        "   • Generic API Keys\n\n"
        "💳 **نماذج الدفع**\n"
        "   • بروتوكول الإرسال\n"
        "   • CSRF Protection\n"
        "   • HTTP vs HTTPS\n"
    )
    back_btn = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔙 رجوع", callback_data="main_menu")]
    ])
    await callback.message.edit_text(
        text,
        reply_markup=back_btn,
        parse_mode="Markdown"
    )
    await callback.answer()


# ══════════════════════════════════════
#       استقبال الرابط وتشغيل الفحص
# ══════════════════════════════════════
@dp.message(ScanStates.waiting_for_url)
async def process_url(message: Message, state: FSMContext):
    url = message.text.strip()

    # التحقق من الرابط
    if len(url) < 4 or " " in url:
        await message.answer(
            "❌ **رابط غير صالح!**\n\n"
            "أرسل رابطاً صحيحاً مثل:\n"
            "`https://example.com`",
            parse_mode="Markdown"
        )
        return

    # رسالة الانتظار
    wait_msg = await message.answer(
        "⏳ **جاري الفحص...**\n\n"
        "🔒 فحص SSL...\n"
        "🛡️ فحص Security Headers...\n"
        "🔑 البحث عن مفاتيح مكشوفة...\n"
        "💳 فحص نماذج الدفع...\n\n"
        "⏱️ قد يستغرق هذا 30-60 ثانية",
        parse_mode="Markdown"
    )

    await state.clear()

    try:
        # تشغيل الفحص في thread منفصل
        loop = asyncio.get_event_loop()
        scanner = PaymentScanner(url)
        results = await loop.run_in_executor(
            None, scanner.run_full_scan
        )

        # توليد التقرير
        reporter = ReportGenerator(results)
        full_report = reporter.generate_full_report()

        # حذف رسالة الانتظار
        await wait_msg.delete()

        # إرسال التقرير
        # تقسيم التقرير إن كان طويلاً
        if len(full_report) > 4000:
            parts = [
                full_report[i:i+4000]
                for i in range(0, len(full_report), 4000)
            ]
            for i, part in enumerate(parts):
                if i == len(parts) - 1:
                    await message.answer(
                        part,
                        parse_mode="Markdown",
                        reply_markup=get_after_scan_keyboard()
                    )
                else:
                    await message.answer(part, parse_mode="Markdown")
        else:
            await message.answer(
                full_report,
                parse_mode="Markdown",
                reply_markup=get_after_scan_keyboard()
            )

        # لوغ للأدمن
        logger.info(
            f"✅ فحص مكتمل | المستخدم: {message.from_user.id} | "
            f"الموقع: {url} | الدرجة: {results.get('score', 0)}"
        )

    except Exception as e:
        await wait_msg.delete()
        logger.error(f"❌ خطأ في الفحص: {e}")
        await message.answer(
            "❌ **حدث خطأ أثناء الفحص!**\n\n"
            f"السبب: `{str(e)[:100]}`\n\n"
            "تأكد من:\n"
            "  • صحة الرابط\n"
            "  • أن الموقع يعمل\n"
            "  • اتصالك بالإنترنت",
            reply_markup=get_after_scan_keyboard(),
            parse_mode="Markdown"
        )


# ══════════════════════════════════════
#       تشغيل البوت
# ══════════════════════════════════════
async def main():
    logger.info("🚀 البوت يعمل...")
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    asyncio.run(main())

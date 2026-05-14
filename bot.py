import asyncio
import logging
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
        f"🤖 أنا بوت فحص أمان بوابات الدفع\n\n"
        f"🛡️ **ما الذي أفحصه؟**\n"
        f"  🔒 شهادة SSL وصلاحيتها\n"
        f"  🛡️ رؤوس الأمان HTTP Headers\n"
        f"  🔑 المفاتيح المكشوفة (Stripe, PayPal...)\n"
        f"  💳 أمان نماذج الدفع\n"
        f"  📊 تقرير شامل مع الحلول\n\n"
        f"⚡ اضغط الزر أدناه لبدء الفحص!"
    )

    await message.answer(
        welcome_text,
        reply_markup=get_main_keyboard(),
        parse_mode="Markdown"
    )


# ══════════════════════════════════════
#       /scan (أمر مباشر)
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

    # التحقق البسيط من الرابط
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

    await state.clear
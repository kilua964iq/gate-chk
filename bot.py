import asyncio
import logging
import urllib3
from aiogram import Bot, Dispatcher, F
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

from config import BOT_TOKEN, ADMIN_IDS, DEVELOPER, OPENAI_API_KEY
from scanners.payment_scanner import PaymentScanner
from utils.reporter import ReportGenerator
from ai_assistant import ai_assistant

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

bot     = Bot(token=BOT_TOKEN)
storage = MemoryStorage()
dp      = Dispatcher(storage=storage)


class BotStates(StatesGroup):
    waiting_for_url     = State()
    chatting_with_ai    = State()
    waiting_code_review = State()


def get_copyright_footer() -> str:
    return (
        "\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👨‍💻 **المطور:** {DEVELOPER['name']}\n"
        f"📱 **تواصل:** {DEVELOPER['username']}\n"
        f"📢 **القناة:** {DEVELOPER['channel']}\n"
        f"🔖 **الإصدار:** {DEVELOPER['version']}\n"
        f"©️ {DEVELOPER['rights']}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )


def get_main_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="🔍 فحص موقع",
                callback_data="start_scan"
            ),
            InlineKeyboardButton(
                text="🤖 المساعد الذكي",
                callback_data="start_ai_chat"
            ),
        ],
        [
            InlineKeyboardButton(
                text="👨‍💻 مراجعة كود",
                callback_data="code_review"
            ),
            InlineKeyboardButton(
                text="⚙️ الفحوصات",
                callback_data="scan_types"
            ),
        ],
        [
            InlineKeyboardButton(
                text="📖 كيف يعمل؟",
                callback_data="how_it_works"
            ),
            InlineKeyboardButton(
                text="ℹ️ عن البوت",
                callback_data="about"
            ),
        ],
        [
            InlineKeyboardButton(
                text="👨‍💻 المطور",
                callback_data="developer_info"
            ),
            InlineKeyboardButton(
                text="📢 القناة",
                url=f"https://t.me/{DEVELOPER['channel'].replace('@', '')}"
            ),
        ],
    ])


def get_cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ إلغاء", callback_data="cancel")]
    ])


def get_ai_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="🗑️ مسح المحادثة",
                callback_data="clear_ai_chat"
            ),
            InlineKeyboardButton(
                text="🏠 القائمة",
                callback_data="cancel"
            ),
        ],
    ])


def get_after_scan_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="🤖 تحليل بالذكاء الاصطناعي",
                callback_data="ai_analyze_scan"
            ),
        ],
        [
            InlineKeyboardButton(
                text="🔍 فحص موقع آخر",
                callback_data="start_scan"
            ),
            InlineKeyboardButton(
                text="🏠 القائمة",
                callback_data="main_menu"
            ),
        ],
    ])


def get_back_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔙 رجوع", callback_data="main_menu")]
    ])


@dp.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    user_name = message.from_user.first_name or "مستخدم"
    ai_status = "✅ GPT-4o مفعل" if OPENAI_API_KEY else "❌ غير مفعل"

    text = (
        "╔══════════════════════════════╗\n"
        "║  🔐 بوت فحص أمان بوابات الدفع  ║\n"
        "╚══════════════════════════════╝\n\n"
        f"👋 أهلاً **{user_name}**!\n\n"
        "🛡️ **مميزات البوت:**\n"
        "  🔍 فحص أمان المواقع الشامل\n"
        "  🔒 فحص SSL وHTTPS\n"
        "  🛡️ فحص Security Headers\n"
        "  🔑 اكتشاف المفاتيح المكشوفة\n"
        "  💳 فحص نماذج الدفع\n"
        f"  🤖 المساعد الذكي: {ai_status}\n\n"
        "⚡ اختر من القائمة أدناه!"
        f"{get_copyright_footer()}"
    )

    await message.answer(
        text,
        reply_markup=get_main_keyboard(),
        parse_mode="Markdown"
    )


@dp.message(Command("ai"))
async def cmd_ai(message: Message, state: FSMContext):
    if not OPENAI_API_KEY:
        await message.answer("❌ المساعد الذكي غير مفعل")
        return
    await state.set_state(BotStates.chatting_with_ai)
    await message.answer(
        "🤖 **المساعد الذكي GPT-4o**\n\n"
        "اكتب سؤالك أو اطلب مني كتابة كود! 👇",
        reply_markup=get_ai_keyboard(),
        parse_mode="Markdown"
    )


@dp.message(Command("scan"))
async def cmd_scan(message: Message, state: FSMContext):
    await state.set_state(BotStates.waiting_for_url)
    await message.answer(
        "🔍 **أرسل رابط الموقع المراد فحصه:**\n\n"
        "📌 **أمثلة:**\n"
        "  • `https://example.com`\n"
        "  • `example.com`\n",
        reply_markup=get_cancel_keyboard(),
        parse_mode="Markdown"
    )


@dp.message(Command("help"))
async def cmd_help(message: Message):
    await message.answer(
        "📚 **دليل الاستخدام**\n\n"
        "/start — الصفحة الرئيسية\n"
        "/scan  — فحص موقع\n"
        "/ai    — المساعد الذكي\n"
        "/help  — هذه الرسالة\n"
        f"{get_copyright_footer()}",
        reply_markup=get_back_keyboard(),
        parse_mode="Markdown"
    )


@dp.message(BotStates.chatting_with_ai)
async def process_ai_message(message: Message, state: FSMContext):
    user_id      = message.from_user.id
    user_message = message.text.strip()
    thinking_msg = await message.answer("🤔 جاري التفكير...")

    try:
        response = await ai_assistant.chat(user_id, user_message)
        await thinking_msg.delete()

        if len(response) > 4000:
            parts = [response[i:i+4000] for i in range(0, len(response), 4000)]
            for i, part in enumerate(parts):
                if i == len(parts) - 1:
                    await message.answer(
                        part,
                        reply_markup=get_ai_keyboard(),
                        parse_mode="Markdown"
                    )
                else:
                    await message.answer(part, parse_mode="Markdown")
        else:
            await message.answer(
                response,
                reply_markup=get_ai_keyboard(),
                parse_mode="Markdown"
            )

    except Exception as e:
        await thinking_msg.delete()
        await message.answer(f"❌ خطأ: {str(e)[:100]}")


@dp.message(BotStates.waiting_code_review)
async def process_code_review(message: Message, state: FSMContext):
    user_id      = message.from_user.id
    code         = message.text.strip()
    thinking_msg = await message.answer("🔍 جاري مراجعة الكود...")

    try:
        response = await ai_assistant.review_code(user_id, code)
        await thinking_msg.delete()
        await state.set_state(BotStates.chatting_with_ai)

        if len(response) > 4000:
            parts = [response[i:i+4000] for i in range(0, len(response), 4000)]
            for i, part in enumerate(parts):
                if i == len(parts) - 1:
                    await message.answer(
                        part,
                        reply_markup=get_ai_keyboard(),
                        parse_mode="Markdown"
                    )
                else:
                    await message.answer(part, parse_mode="Markdown")
        else:
            await message.answer(
                response,
                reply_markup=get_ai_keyboard(),
                parse_mode="Markdown"
            )

    except Exception as e:
        await thinking_msg.delete()
        await message.answer(f"❌ خطأ: {str(e)[:100]}")


@dp.message(BotStates.waiting_for_url)
async def process_url(message: Message, state: FSMContext):
    url = message.text.strip()

    if len(url) < 4 or " " in url:
        await message.answer(
            "❌ رابط غير صالح!\n"
            "أرسل رابطاً صحيحاً مثل:\n"
            "`https://example.com`",
            parse_mode="Markdown"
        )
        return

    wait_msg = await message.answer(
        "⏳ **جاري الفحص...**\n\n"
        "🔒 فحص SSL...\n"
        "🛡️ فحص Security Headers...\n"
        "🔑 البحث عن مفاتيح مكشوفة...\n"
        "💳 فحص نماذج الدفع...\n\n"
        "⏱️ قد يستغرق 30-60 ثانية",
        parse_mode="Markdown"
    )

    await state.clear()

    try:
        loop    = asyncio.get_event_loop()
        scanner = PaymentScanner(url)
        results = await loop.run_in_executor(None, scanner.run_full_scan)

        reporter    = ReportGenerator(results)
        full_report = reporter.generate_full_report()
        full_report += get_copyright_footer()

        await wait_msg.delete()

        # حفظ نتائج الفحص للتحليل بالذكاء
        await state.update_data(last_scan=results)

        if len(full_report) > 4000:
            parts = [full_report[i:i+4000] for i in range(0, len(full_report), 4000)]
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

        logger.info(
            f"✅ فحص مكتمل | "
            f"المستخدم: {message.from_user.id} | "
            f"الموقع: {url} | "
            f"الدرجة: {results.get('score', 0)}"
        )

    except Exception as e:
        await wait_msg.delete()
        logger.error(f"❌ خطأ: {e}")
        await message.answer(
            "❌ **حدث خطأ أثناء الفحص!**\n\n"
            f"السبب: `{str(e)[:100]}`\n\n"
            "تأكد من صحة الرابط وأن الموقع يعمل"
            f"{get_copyright_footer()}",
            reply_markup=get_after_scan_keyboard(),
            parse_mode="Markdown"
        )


@dp.callback_query(F.data == "start_scan")
async def cb_start_scan(callback: CallbackQuery, state: FSMContext):
    await state.set_state(BotStates.waiting_for_url)
    await callback.message.edit_text(
        "🔍 **أرسل رابط الموقع المراد فحصه:**\n\n"
        "📌 **أمثلة:**\n"
        "  • `https://example.com`\n"
        "  • `example.com`\n",
        reply_markup=get_cancel_keyboard(),
        parse_mode="Markdown"
    )
    await callback.answer()


@dp.callback_query(F.data == "start_ai_chat")
async def cb_start_ai_chat(callback: CallbackQuery, state: FSMContext):
    if not OPENAI_API_KEY:
        await callback.answer("❌ المساعد الذكي غير مفعل!", show_alert=True)
        return
    await state.set_state(BotStates.chatting_with_ai)
    await callback.message.edit_text(
        "🤖 **المساعد الذكي GPT-4o**\n\n"
        "أنا مساعدك في:\n"
        "  🐍 برمجة Python\n"
        "  🤖 بوتات تيليغرام\n"
        "  🔒 أمن المواقع\n"
        "  💳 بوابات الدفع\n\n"
        "اكتب سؤالك! 👇",
        reply_markup=get_ai_keyboard(),
        parse_mode="Markdown"
    )
    await callback.answer()


@dp.callback_query(F.data == "code_review")
async def cb_code_review(callback: CallbackQuery, state: FSMContext):
    if not OPENAI_API_KEY:
        await callback.answer("❌ المساعد الذكي غير مفعل!", show_alert=True)
        return
    await state.set_state(BotStates.waiting_code_review)
    await callback.message.edit_text(
        "👨‍💻 **مراجعة الكود**\n\n"
        "أرسل الكود وسأقوم بـ:\n"
        "  🐛 اكتشاف الأخطاء\n"
        "  🔒 فحص الثغرات\n"
        "  ⚡ اقتراح تحسينات\n"
        "  ✅ الكود المصحح كاملاً\n\n"
        "أرسل الكود الآن 👇",
        reply_markup=get_cancel_keyboard(),
        parse_mode="Markdown"
    )
    await callback.answer()


@dp.callback_query(F.data == "ai_analyze_scan")
async def cb_ai_analyze_scan(callback: CallbackQuery, state: FSMContext):
    if not OPENAI_API_KEY:
        await callback.answer("❌ المساعد الذكي غير مفعل!", show_alert=True)
        return

    data      = await state.get_data()
    last_scan = data.get("last_scan")

    if not last_scan:
        await callback.answer("❌ لا يوجد فحص سابق!", show_alert=True)
        return

    thinking_msg = await callback.message.answer("🤖 جاري التحليل بالذكاء الاصطناعي...")

    try:
        analysis = await ai_assistant.analyze_scan_results(last_scan)
        await thinking_msg.delete()

        if len(analysis) > 4000:
            parts = [analysis[i:i+4000] for i in range(0, len(analysis), 4000)]
            for i, part in enumerate(parts):
                if i == len(parts) - 1:
                    await callback.message.answer(
                        part,
                        parse_mode="Markdown",
                        reply_markup=get_back_keyboard()
                    )
                else:
                    await callback.message.answer(part, parse_mode="Markdown")
        else:
            await callback.message.answer(
                analysis,
                parse_mode="Markdown",
                reply_markup=get_back_keyboard()
            )

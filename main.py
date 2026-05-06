import asyncio
import aiohttp
import json
import re
from groq import Groq
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, CallbackQueryHandler
import yt_dlp
import os

# ── KEYS ────────────────────────────────────────────────
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
GROQ_API_KEY   = os.getenv("GROQ_API_KEY")
IPINFO_KEY     = os.getenv("IPINFO_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
SHODAN_KEY     = os.getenv("SHODAN_KEY")
# ────────────────────────────────────────────────────────
MI_ID = {6687308605,6958181174}
groq_client = Groq(api_key=GROQ_API_KEY)
CURRENT_MODEL = "llama-3.3-70b-versatile"

# ====================== FUNCIONES DE RECOLECCIÓN ======================

def solo_yo(update):
    return update.effective_user.id in MI_ID

async def get_ipapi(session, ip):
    try:
        async with session.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,lat,lon,timezone,mobile,proxy,hosting") as r:
            return await r.json()
    except:
        return {}

async def get_ipinfo(session, ip):
    try:
        async with session.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_KEY}") as r:
            return await r.json()
    except:
        return {}

async def get_virustotal_ip(session, ip):
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        async with session.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers) as r:
            return await r.json()
    except:
        return {}

async def get_virustotal_url(session, url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_KEY}
        data = {"url": url}
        async with session.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data) as r:
            resp = await r.json()
            analysis_id = resp.get("data", {}).get("id")
            if not analysis_id:
                return {}
            await asyncio.sleep(8)
            async with session.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers) as r2:
                return await r2.json()
    except:
        return {}

async def get_whois(session, ip):
    try:
        async with session.get(f"https://rdap.arin.net/registry/ip/{ip}") as r:
            data = await r.json()
            return {
                "name": data.get("name", "N/A"),
                "handle": data.get("handle", "N/A"),
                "country": data.get("country", "N/A"),
            }
    except:
        return {}

# ====================== ANÁLISIS CON IA (más breve) ======================

def analizar_con_ia(target, datos, es_url=False):
    tipo = "URL" if es_url else "IP"
    prompt = f"""Eres un experto en ciberseguridad. Analiza de forma breve y directa estos datos OSINT de {tipo} {target}.

Datos:
{json.dumps(datos, indent=2, ensure_ascii=False)}

Responde en español, máximo 10-12 líneas. Incluye:
- Ubicación y propietario
- Nivel de riesgo (bajo/medio/alto) con breve justificación
- Tipo de conexión (proxy, vpn, hosting, residencial, etc.)
- Si está reportada como maliciosa
- Conclusión corta

Sé directo y usa emojis solo cuando sea necesario."""

    try:
        resp = groq_client.chat.completions.create(
            model=CURRENT_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
            temperature=0.6,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"Error en análisis IA: {str(e)}"

# ====================== DETECCIÓN ======================

def es_ip_valida(target):
    ipv4 = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)
    ipv6 = re.match(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:", target)
    return bool(ipv4) or bool(ipv6)

# ====================== COMANDO SCAN ======================

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not solo_yo(update):
        return 
    if not context.args:
        await update.message.reply_text("❌ Uso: `/scan <IP o URL>`\nEjemplo: `/scan 8.8.8.8`", parse_mode="Markdown")
        return

    target = context.args[0].strip()
    es_url = target.startswith(("http://", "https://"))

    await update.message.reply_text(f"🔍 Escaneando **{target}**... espera", parse_mode="Markdown")

    async with aiohttp.ClientSession() as session:
        if es_url:
            vt_data = await get_virustotal_url(session, target)
            datos = {"virustotal_url": vt_data, "tipo": "URL"}
            reporte_raw = f"🌐 *URL:* {target}\n\n🤖 Analizando con IA..."
        else:
            # IP Scan (sin Shodan)
            resultados = await asyncio.gather(
                get_ipapi(session, target),
                get_ipinfo(session, target),
                get_virustotal_ip(session, target),
                get_whois(session, target),
            )
            datos = {
                "ip_api": resultados[0],
                "ipinfo": resultados[1],
                "virustotal": resultados[2],
                "whois": resultados[3],
                "tipo": "IP"
            }

            ipapi = datos["ip_api"]
            reporte_raw = (
                f"📍 *{target}*\n"
                f"🌍 {ipapi.get('country','?')} — {ipapi.get('city','?')}\n"
                f"🏢 ISP: {ipapi.get('isp','?')}\n"
                f"🔒 Proxy: {ipapi.get('proxy','?')} | Hosting: {ipapi.get('hosting','?')}\n"
                f"📡 Puertos: Sin información Shodan\n"
                f"\n🤖 Analizando con IA..."
            )

    await update.message.reply_text(reporte_raw, parse_mode="Markdown")

    analisis = analizar_con_ia(target, datos, es_url)

    await update.message.reply_text(
        f"<b>Análisis IA ({CURRENT_MODEL})</b>\n\n{analisis}",
        parse_mode="HTML"
    )

    # Botones
    keyboard = [
        [InlineKeyboardButton("📄 Exportar TXT", callback_data=f"export_txt:{target}")]
    ]
    await update.message.reply_text("¿Qué deseas hacer?", reply_markup=InlineKeyboardMarkup(keyboard))


DOWNLOADS_DIR = "downloads"
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

def _download_media(url: str, is_audio: bool = False) -> str | None:
    ydl_opts = {
        'outtmpl': os.path.join(DOWNLOADS_DIR, '%(title)s.%(ext)s'),
        'quiet': True,
        'no_warnings': True,
        'noplaylist': True,
    }
    if is_audio:
        ydl_opts.update({
            'format': 'bestaudio/best',
            'postprocessors': [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '192',
            }],
        })
    else:
        ydl_opts.update({
            # ← ESTE ES EL FIX PRINCIPAL
            'format': 'bestvideo[height<=720][ext=mp4]+bestaudio[ext=m4a]/bestvideo[height<=720]+bestaudio/best[height<=720]/best',
            'merge_output_format': 'mp4',
        })

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(url, download=True)
        if is_audio:
            filename = ydl.prepare_filename(info).rsplit('.', 1)[0] + '.mp3'
        else:
            filename = ydl.prepare_filename(info)
        if os.path.exists(filename):
            return filename
        for f in os.listdir(DOWNLOADS_DIR):
            if info.get('title', '').lower() in f.lower():
                return os.path.join(DOWNLOADS_DIR, f)
    return None

# ====================== CALLBACKS ======================

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query.from_user.id != MI_ID:
        return
    await query.answer()

    if query.data.startswith("export_txt:"):
        target = query.data.split(":", 1)[1]
        texto = f"Reporte OSINT - {target}\n\n{query.message.text}"
        await query.message.reply_document(
            document=bytes(texto, "utf-8"),
            filename=f"reporte_{target}.txt"
        )

async def video_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not solo_yo(update): return
    if not context.args:
        await update.message.reply_text("❌ Uso: `/video <URL>`", parse_mode="Markdown")
        return
    url = ' '.join(context.args)
    await update.message.reply_text("⬇️ Descargando **video** (720p)... espera", parse_mode="Markdown")
    try:
        filename = await asyncio.to_thread(_download_media, url, False)
        if filename and os.path.exists(filename):
            with open(filename, "rb") as f:
                await update.message.reply_video(video=f, caption=f"✅ {os.path.basename(filename)}", supports_streaming=True)
            os.remove(filename)
        else:
            await update.message.reply_text("❌ No se pudo descargar.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)[:150]}")

async def audio_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not solo_yo(update): return
    if not context.args:
        await update.message.reply_text("❌ Uso: `/audio <URL>`", parse_mode="Markdown")
        return
    url = ' '.join(context.args)
    await update.message.reply_text("⬇️ Descargando **audio** (mp3 192kbps)... espera", parse_mode="Markdown")
    try:
        filename = await asyncio.to_thread(_download_media, url, True)
        if filename and os.path.exists(filename):
            with open(filename, "rb") as f:
                await update.message.reply_audio(audio=f, caption=f"✅ {os.path.basename(filename)}")
            os.remove(filename)
        else:
            await update.message.reply_text("❌ No se pudo descargar.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)[:150]}")

# ====================== OTROS COMANDOS ======================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not solo_yo(update):
        return
    
    await update.message.reply_text(
    "*🚀 Bot Multifunción*\n\n"
    "Comandos:\n"
    "/scan <IP o URL> — Análisis OSINT\n"
    "/model <llama|mixtral> — Cambiar modelo IA\n"
    "/video <URL> — Descargar video (720p)\n"
    "/audio <URL> — Descargar audio (mp3)\n\n"
    "Ej:\n"
    "`/scan 8.8.8.8`\n"
    "`/video https://...`\n"
    "`/audio https://...`",
    parse_mode="Markdown"
)
async def set_model(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not solo_yo(update):
        return
    
    global CURRENT_MODEL
    if not context.args:
        await update.message.reply_text(f"Modelo actual: **{CURRENT_MODEL}**", parse_mode="Markdown")
        return
    m = context.args[0].lower()
    if "llama" in m:
        CURRENT_MODEL = "llama-3.3-70b-versatile"
    elif "mixtral" in m:
        CURRENT_MODEL = "mixtral-8x7b-32768"
    else:       
        await update.message.reply_text("Opciones: llama o mixtral")
        return
    await update.message.reply_text(f"✅ Modelo cambiado a **{CURRENT_MODEL}**")

# ====================== MAIN ======================

app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()

app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("scan", scan))
app.add_handler(CommandHandler("model", set_model))
app.add_handler(CallbackQueryHandler(button_handler))
app.add_handler(CommandHandler("video", video_cmd))
app.add_handler(CommandHandler("audio", audio_cmd))

print("✅ Bot OSINT corriendo (sin Shodan - más estable)")
app.run_polling()

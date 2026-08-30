/**
 * ===============================================================================
 * КОДЕКС АРХИВА «ПОСЛЕДНИЙ КОДЕКС» // ГОД 3047
 * CLOUDFLARE WORKER: HAPP TOP 50 SUBSCRIPTION PROXY & SERVE
 * ===============================================================================
 */

// URL сгенерированной и обработанной подписки ТОП-50 (уже в base64, с флагами стран и отфильтрованными дохлыми серверами)
// Генерируется скриптом happ_top50_hub.py через GitHub Actions каждые 2 часа.
const GITHUB_RAW_SUB = "https://raw.githubusercontent.com/jgchkcu-maker/romlik/main/happ_subscription_b64.txt";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Загружаем актуальную подписку из облачного хранилища GitHub
    const resp = await fetch(GITHUB_RAW_SUB, {
      headers: { "User-Agent": "Mozilla/5.0" },
      cf: { cacheTtl: 300, cacheEverything: true }
    });

    if (!resp.ok) {
      return new Response("Error loading subscription from archive.", { status: 502 });
    }

    // Файл уже закодирован в base64 скриптом генерации — отдаём как есть
    const b64Data = await resp.text();

    // Заголовки совместимости с HApp, V2Box, Sing-box, Marzban
    const headers = new Headers();
    headers.set("Content-Type", "text/plain; charset=utf-8");
    headers.set("Content-Disposition", 'attachment; filename="happ_sub.txt"');
    headers.set("profile-update-interval", "6"); // Автообновление в HApp каждые 6 часов
    headers.set("subscription-userinfo", "upload=0; download=0; total=107374182400; expire=0");
    headers.set("Access-Control-Allow-Origin", "*");

    return new Response(b64Data, { headers });
  }
};

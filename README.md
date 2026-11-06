# Bridge configs

A list of free public configs, rebuilt every day for [Bridge](https://github.com/m4hdisa/Bridge-app).

**Nobody knows who runs these servers, and that includes this project.** They can see your IP address and which sites you open. Use them to get online and for ordinary browsing, not for logins, banking or anything sensitive.

- `clean.txt`: the list, one share link per line.
- `cloudflare.txt`: configs behind Cloudflare's CDN, moved onto a Cloudflare address that answers from Iran. Each one comes twice: as it is, and with its TLS hello split.
- `warp.txt`: WARP starter accounts, one Bridge WARP link per line (see below).
- `stats.json`: how the last run went.
- `channels.txt`: the public Telegram channels it reads, one per line.

## WARP starter accounts

To use Cloudflare WARP, Bridge first needs a WARP account from Cloudflare's sign-up service, which is often blocked in Iran. When Bridge can't reach it, directly or through a server of the user's own, it connects once with a random account from `warp.txt`, makes the user's own account through that tunnel, and uses that from then on. The same Action makes these accounts every day outside Iran with the official [Aether](https://github.com/CluvexStudio/Aether) core (`warp-accounts.cjs`, built from `scripts/warp-accounts.ts` in Bridge-app with `npm run bundle-warp-accounts`). They are public, so they are only a way in: anyone can use them, and several people may share one for a moment.

## How the list is made

Once a day a GitHub Action gathers links from public GitHub lists and the public preview pages of the channels. It drops anything that isn't encrypted, doesn't check the server's certificate, or points at a local or `.ir` address. It then tests the rest with the real sing-box and Xray cores, and keeps those that carry HTTPS with a valid certificate and leave outside Iran. Names from the sources, which are mostly adverts, are replaced.

For `cloudflare.txt`, every VLESS or Trojan config on WebSocket, HTTPUpgrade, XHTTP or gRPC with a Host is moved onto a Cloudflare address, with its Host as the server name, since Cloudflare picks the origin by name. This idea, and many of the sources, come from [patterniha/Free-Configs](https://github.com/patterniha/Free-Configs) (MIT); only what the official cores understand is used.

The tests run outside Iran, so they weed out dead servers, not filtered ones. Bridge tests the list again on your own network.

`collect.cjs` is built from `scripts/collect-configs.ts` in [Bridge-app](https://github.com/m4hdisa/Bridge-app) with `npm run bundle-collector`. GPL-3.0-or-later.

---

<div dir="rtl">

# کانفیگ‌های Bridge

فهرست کانفیگ‌های عمومی رایگان که هر روز برای [Bridge](https://github.com/m4hdisa/Bridge-app) دوباره ساخته می‌شود.

**معلوم نیست این سرورها را چه کسی اداره می‌کند، حتی برای خود این پروژه.** آن‌ها آی‌پی شما و سایت‌هایی را که باز می‌کنید می‌بینند. فقط برای وصل شدن به اینترنت و گشت‌وگذار معمولی از آن‌ها استفاده کنید، نه برای ورود به حساب‌ها، کارهای بانکی یا هر کار حساسی.

- `clean.txt`: خود فهرست، هر خط یک لینک.
- `cloudflare.txt`: کانفیگ‌های پشت CDN کلادفلر که روی یک آدرس Cloudflare که از ایران جواب می‌دهد برده شده‌اند؛ هر کدام دو بار، یک بار با تکه‌تکه شدن TLS hello.
- `warp.txt`: حساب‌های آماده‌ی WARP، هر خط یک لینک WARP مخصوص Bridge (توضیح پایین).
- `stats.json`: گزارش آخرین اجرا.
- `channels.txt`: کانال‌های عمومی تلگرام که خوانده می‌شوند، هر خط یکی.

**حساب‌های آماده‌ی WARP:** Bridge برای استفاده از WARP اول باید از سرویس ثبت‌نام Cloudflare یک حساب بگیرد که در ایران معمولاً فیلتر است. اگر Bridge نه مستقیم و نه از طریق سرور خود کاربر به آن نرسد، یک بار با یکی از حساب‌های `warp.txt` به‌صورت تصادفی وصل می‌شود، از داخل همان تونل حساب شخصی کاربر را می‌سازد و از آن به بعد از حساب شخصی استفاده می‌کند. همین Action هر روز این حساب‌ها را خارج از ایران با Aether رسمی می‌سازد. این حساب‌ها عمومی‌اند و فقط برای شروع به کار می‌آیند.

تست‌ها خارج از ایران انجام می‌شوند، پس سرورهای مرده را حذف می‌کنند، نه فیلترشده‌ها را. Bridge فهرست را دوباره روی شبکه‌ی خود شما تست می‌کند.

</div>

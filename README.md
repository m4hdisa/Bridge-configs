# Bridge configs

A list of free public configs, rebuilt every day for [Bridge](https://github.com/m4hdisa/Bridge-app).

**Nobody knows who runs these servers, and that includes this project.** They can see your IP address and which sites you open. Use them to get online and for ordinary browsing, not for logins, banking or anything sensitive.

- `clean.txt`: the list, one share link per line.
- `stats.json`: how the last run went.
- `channels.txt`: the public Telegram channels it reads, one per line.

## How the list is made

Once a day a GitHub Action gathers links from public GitHub lists and the public preview pages of the channels. It drops anything that isn't encrypted, doesn't check the server's certificate, or points at a local or `.ir` address. It then tests the rest with the real sing-box and Xray cores, and keeps those that carry HTTPS with a valid certificate and leave outside Iran. Names from the sources, which are mostly adverts, are replaced.

The tests run outside Iran, so they weed out dead servers, not filtered ones. Bridge tests the list again on your own network.

`collect.cjs` is built from `scripts/collect-configs.ts` in [Bridge-app](https://github.com/m4hdisa/Bridge-app) with `npm run bundle-collector`. GPL-3.0-or-later.

---

<div dir="rtl">

# کانفیگ‌های Bridge

فهرست کانفیگ‌های عمومی رایگان که هر روز برای [Bridge](https://github.com/m4hdisa/Bridge-app) دوباره ساخته می‌شود.

**معلوم نیست این سرورها را چه کسی اداره می‌کند، حتی برای خود این پروژه.** آن‌ها آی‌پی شما و سایت‌هایی را که باز می‌کنید می‌بینند. فقط برای وصل شدن به اینترنت و گشت‌وگذار معمولی از آن‌ها استفاده کنید، نه برای ورود به حساب‌ها، کارهای بانکی یا هر کار حساسی.

- `clean.txt`: خود فهرست، هر خط یک لینک.
- `stats.json`: گزارش آخرین اجرا.
- `channels.txt`: کانال‌های عمومی تلگرام که خوانده می‌شوند، هر خط یکی.

تست‌ها خارج از ایران انجام می‌شوند، پس سرورهای مرده را حذف می‌کنند، نه فیلترشده‌ها را. Bridge فهرست را دوباره روی شبکه‌ی خود شما تست می‌کند.

</div>

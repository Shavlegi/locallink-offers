# Local Link Offers — მეილების შეგროვება და შეთავაზებების გაგზავნა

სატესტო პროექტი: საჯარო რეგისტრაციის გვერდი (სახელი, გვარი, მეილი +
თანხმობის ჩექბოქსი, double opt-in) და პაროლით დაცული ადმინ პანელი, სადაც
შაო მონიშნავს გამომწერებს და აგზავნის შეთავაზებებს.

- **ტექნოლოგია:** Cloudflare Worker + D1 (იგივე ნიმუში, რაც Mini Link-სა და
  locallink-stock-ს აქვს). გაგზავნა Resend-ით (უფასო ტარი: 3,000/თვე,
  100/დღე — Worker თავად იცავს 100/დღე ლიმიტს).
- **სუბდომენი (ტესტი):** `offers.locallink.store` → `locallink.store`-დან
  ბმულით/ღილაკით.
- **ენა:** ქართული (v1).

## რა არის შიგნით

- `GET /` — რეგისტრაციის გვერდი (თანხმობის ჩექბოქსი წინასწარ არ არის მონიშნული).
- `POST /api/subscribe` — რეგისტრაცია; მეილზე დადასტურების ბმული იგზავნება.
- `GET /confirm?token=…` — გამოწერის დადასტურება (double opt-in).
- `GET /unsubscribe?token=…` — გამოწერის გაუქმება (ბმული ყველა მეილშია).
- `GET /admin` — ადმინ პანელი: შესვლა, გამომწერების სია + ძებნა, მონიშვნა,
  სათაური + ტექსტი, გაგზავნა, ისტორია, CSV ექსპორტი, წაშლა.
- `GET /api/health` — `{"ok":true}`.

მხოლოდ **დადასტურებულ** გამომწერებს ეგზავნებათ მეილები. გაუქმებულები და
დაუდასტურებლები გაგზავნიდან ავტომატურად გამოირიცხებიან.

## დაყენება (ხვალინდელი ჩექლისთი შაოსთვის)

1. **D1 ბაზა:** Cloudflare dashboard → Workers & Pages → D1 → Create
   database `locallink-offers-db` → `database_id` ჩასვი `wrangler.toml`-ში.
2. **Worker:** Workers & Pages → Create → Connect to Git → ეს რეპო
   (`Shavlegi/locallink-offers`).
3. **Secrets** (Worker → Settings → Variables and Secrets):
   - `ADMIN_PASSWORD_HASH` — გენერირდება `scripts/make-hash.html`-ით
     (ბრაუზერში იხსნება, პაროლი არსად იგზავნება).
   - `SESSION_SECRET` — გრძელი შემთხვევითი სტრიქონი (იგივე გვერდი აგენერირებს).
   - `RESEND_API_KEY` — Resend → API Keys → Create API Key.
   - სიქრეთების მნიშვნელობები არასოდეს ჩაწერო GitHub-ზე ან ჩატში.
4. **სუბდომენი:** Namecheap → `locallink.store` DNS → CNAME ჩანაწერი:
   host `offers`, value `locallink-offers.<account>.workers.dev`. მერე
   Cloudflare-ში Worker → Settings → Domains → Add Custom Domain →
   `offers.locallink.store`.
5. **გამგზავნი დომენი (Resend):** Resend → Domains → Add Domain →
   `locallink.store` → გამოჩენილი SPF/DKIM TXT ჩანაწერები ჩასვი Namecheap
   DNS-ში. სანამ დომენი არ დადასტურდება, Resend გაგზავნაზე უარს იტყვის —
   პანელი შეცდომას გაჩვენებს.
6. **locallink.store-დან ბმული:** მაღაზიის გვერდზე დაემატოს ღილაკი
   „შეთავაზებები" → `https://offers.locallink.store/`.
7. **შემოწმება:** გახსენი `https://offers.locallink.store/` → დარეგისტრირდი
   სატესტო მეილით → დაადასტურე მეილიდან → შედი `/admin`-ში → გაუგზავნე
   საკუთარ თავს სატესტო შეთავაზება.

## ლიმიტის მოხსნა (მოგვიანებით)

გაგზავნის კოდი ერთ ადგილასაა (`sendMail()` `src/index.js`-ში). Resend-ის
ნაცვლად საკუთარ SMTP სერვერზე გადასართავად საკმარისია `MAIL_SENDER=smtp`
და `SMTP_*` ცვლადების დამატება + `smtp` ბლოკის იმპლემენტაცია — პანელი და
ბაზა არ იცვლება. საკუთარი სერვერი: VPS ~5$/თვე + IP რეპუტაციის ნელ-ნელა
აწყობა; პირველ დღეს ათასობით მეილის გაგზავნა არ შეიძლება.

## ტესტები

```sh
npm test   # node test/offers-harness.mjs — D1Mock node:sqlite-ზე, deploy არ სჭირდება
```

ტესტები (test-only მონაცემები, არასდროს გამოიყენო production-ში):
რეგისტრაციის ვალიდაცია, დუბლიკატი, დადასტურება, გაუქმება, არასწორი/სწორი
პაროლი, გაგზავნა Resend-ის გარეშე (503), გაგზავნა mock-Resend-ით,
დღიური ლიმიტი, CSV ექსპორტი.

## უსაფრთხოება

- ადმინის პაროლი ინახება მხოლოდ PBKDF2 ჰეშის სახით (`ADMIN_PASSWORD_HASH`).
- სესიები ბაზაში ინახება ჰეშირებული ტოკენებით (`SESSION_SECRET`-ით).
- IP მისამართები არსად ინახება — მხოლოდ მათი ჰეში rate limiting-ისთვის.
- `RESEND_API_KEY` მხოლოდ Cloudflare secrets-ში.
- ყველა პასუხზე security headers (nosniff, frame deny, CSP).

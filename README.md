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
- In-Band (classic/error/union): `GET /products/search?q=...`, `GET /products/<pid>`
- Inferential blind/boolean: `GET /api/stock?id=...`
- Inferential time-based: `GET /api/shipping?zip=...`
- Second-order: `GET /admin/reports?u=...` (payload хранится в `users.bio` и позже вставляется в SQL)
- Out-of-band: можно тренировать через MySQL-функции/запросы, выполняемые в SQLi точках (зависит от среды и прав DB).

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
- No rate limiting: ограничения по частоте запросов на логине отсутствуют
- Default credentials: `alice/Hightower7`
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

## Реалистичный функционал магазина
- Каталог, карточка товара, корзина, checkout.
- Личный кабинет, редактирование профиля, адресная книга.
- Wishlist и центр поддержки (тикеты).
- Эндпоинты магазина: бренды (`/shop/brands`), подборки скидок (`/shop/deals`), диагностика доставки (`/shipping/carrier/diagnostics`), модерация отзывов (`/product/<pid>/reviews/moderation`), маркетинговый и каталог-импортные админ-процессы.
- Часть маршрутов реализована безопаснее, часть — намеренно уязвима для учебы.

## Seed users
- `admin / Riv3rN0rth!29`
- `alice / Hightower7`
- `bob / KestrelMoon84#`

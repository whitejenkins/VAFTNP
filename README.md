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
- `POST /api/reviews/search` (JSON фильтр)

### Command Injection
- `GET /tools/ping?host=...`

### Code Injection
- `POST /admin/eval` (параметр `expr`)

### Host Header Injection
- `POST /auth/forgot` (сброс использует `request.host`)

### XML Injection / XXE
- `POST /api/import-xml`

### SSTI
- `GET|POST /promo/preview`

### Auth/Session уязвимости
- Enumeration users: разные ответы в `/auth/login`
- Brute-force password / forgot / 2FA: слабые ограничения для обычных пользователей
- Weak rate limiting: минимальный in-memory счетчик
- Default credentials: `admin/admin123`
- Vulnerable password reset: токен предсказуем
- HTTP Verb tampering: `PUT /auth/login`
- Bypass 2FA via direct access + response replacement: `GET /admin.php` возвращает `302`, но в теле уже есть защищенный контент
- Bypass authentication via direct access + response replacement: тот же `GET /admin.php` (доступ к контенту при смене ответа с `302` на `200`)
- IDOR: `GET /orders/<id>`
- Privilege escalation: `POST /account/promote`

### Где есть защита (намеренно не всё уязвимо)
- Для `admin` входа добавлена отдельная защита от простого перебора: дополнительный `admin_otp` и lockout после неудачных попыток.

### File handling
- File upload bypasses: `POST /files/upload` (client-side checks, weak black/white/type filters)
- LFI / Path traversal: `GET /pages?page=...`
- RFI: `GET /remote/include?url=...`

## Защищенные участки
- Пример безопасного параметризованного SQL: `GET /safe/products?q=...`

## Seed users
- `admin / admin123`
- `alice / alice123`
- `bob / bob123`

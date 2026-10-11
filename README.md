# کنسول امنیت

صفحهٔ وب برای اجرای Semgrep و Checkov و دیدن خلاصهٔ SonarQube و هشدار Falco.
ورود با کوکی HttpOnly است. رمزها داخل کد نیستند.

## بالا آوردن روی هر سرور

روی سروری که Docker و Docker Compose دارد:

```bash
git clone https://github.com/Soheil-TM/security-console.git
cd security-console
./scripts/init-secrets.sh
docker compose up -d --build
```

صفحه روی پورت ۸۰۹۱ باز می‌شود. نام کاربر `admin` است. رمز را اسکریپت در `secrets/console_admin_password.txt` می‌سازد و آن فایل وارد git نمی‌شود.

اسکن Semgrep و Checkov و Trivy و SonarQube از سوکت Docker همان سرور یک کانتینر کوتاه می‌سازد و ایمیج ابزار را در صورت نبودن می‌گیرد. برای SonarQube آدرس سرور را بده:

```bash
SONAR_URL=https://sonar.example.com SONAR_PROJECT_KEY=my-project docker compose up -d --build
```

توکن SonarQube را جدا در `secrets/sonar_token.txt` بگذار. بدون آن، سه ابزار دیگر کار می‌کنند و SonarQube رد می‌شود.

## رازها

این چهار فایل را بساز و در git نگذار، یا `./scripts/init-secrets.sh` را اجرا کن:

- `secrets/console_admin_password.txt` حداقل ۱۲ نویسه
- `secrets/console_db_password.txt`
- `secrets/console_jwt_key.txt` حداقل ۳۲ نویسه
- `secrets/falco_ingest_token.txt`

نام کاربر اول `admin` است و فقط وقتی هیچ کاربری نباشد ساخته می‌شود.

## Docker

`docker compose up --build` یک Postgres مخصوص کنسول و خود کنسول را روی پورت ۸۰۹۱ بالا می‌آورد.

## Docker Swarm

ایمیج `security-console:16` باید روی work-01 باشد. استقرار:

```bash
docker stack deploy -c docker-stack.yml --resolve-image never console
```

روی این خوشه پایگاه کاربران، دیتابیس `security_console_db` روی Postgres موجود SonarQube است. کنسول با نقش `console` وصل می‌شود، نه با نقش برنامهٔ SonarQube.

## Kubernetes

مانیفست `deploy/kubernetes/console.yaml` همان ایمیج را با Postgres جدا بالا می‌آورد. مقدارهای `CHANGE_ME` را عوض کن. `COOKIE_SECURE` آنجا روشن است و جلوی کنسول باید TLS باشد.

اجرای بررسی هنوز یک کانتینر داکر روی سوکت Docker می‌سازد. بدون آن سوکت، ورود و دیدن نتیجه کار می‌کند و شروع بررسی خطا می‌دهد.

## تست

```bash
DATABASE_URL=postgresql://console:console@127.0.0.1:5432/security_console_db \
CONSOLE_JWT_KEY=test-jwt-key-must-be-32-characters \
FALCO_INGEST_TOKEN=falco-test-token \
pytest
```

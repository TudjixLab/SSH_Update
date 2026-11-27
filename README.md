# SSH Update

**SSH Update** — платформа TudjixLab для подготовки и установки обновлений программных проектов через управляемые серверные агенты.

В этой ветке опубликован **исходный код серверной alpha-версии SSH Update Agent 0.1.0**. Работают Linux-агент, локальное управление, проверка/подготовка подписанных пакетов и отдельные компоненты сборки Next.js. Полный автоматический цикл установки и отката ещё не подключён. Версия предназначена для разработки и изолированных тестов.

## SSH Update Agent

- Самостоятельный Rust-процесс, не зависящий от запуска Node.js/Next.js.
- SQLite Store, журнал заданий и ограниченный локальный Unix socket.
- Проверка подписанного `.uli4` и подготовка исходного дерева.
- Отдельная рабочая копия для сборки, журнал намерений, ограниченный build-worker.
- Шаблоны systemd и точечного разрешения управления службами.

Инструкции и точные ограничения: [серверный README](services/uli-ups/README.md).

## Фирменный стиль

Фирменный знак приложения: [SVG icon](assets/ssh-update-icon.svg). Правила использования и терминология: [BRANDING.md](docs/BRANDING.md).

## Сборка на Linux

Нужны Rust 1.100.0, C compiler и поддерживаемая Linux-файловая система.

```sh
cargo build -p uli-ups --release --locked
./target/release/uli-ups --version
```

Сервер находится в `services/uli-ups`, общие библиотеки — в `crates/uli4`, `crates/protocol` и `crates/state`. Они входят в workspace и необходимы для сборки. Тестовые ключи и файлы в fixtures синтетические и непригодны для production.

Проверки:

```sh
cargo test -p uli-ups --locked
cargo test -p uliup-state --tests --locked
cargo test -p uli4 --tests --locked
cargo clippy -p uli-ups --all-targets --no-deps --locked -- -D warnings
```

## Статус

Проверки процесса, Store, подписанного staging, журнала, экспорта файлов и компонентов Next.js/systemd выполнены в Ubuntu WSL. Запуск на Debian 13, полный автоматический deploy/rollback и самообновление ещё не приняты. Не запускайте незавершённые механизмы на рабочем сайте.

Windows/Linux desktop client, SSH/SFTP-интеграция и полный контроллер обновлений разрабатываются отдельно. Публичная концепция описывает целевой продукт: [концепция](CONCEPT.md), [дорожная карта](ROADMAP.md).

> Внутренние имена crates, бинарника и systemd unit пока сохранены для совместимости. Публичное название продукта — SSH Update.

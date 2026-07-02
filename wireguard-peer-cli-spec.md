# Спека: CLI управления WG-пирами (wgpeer)

> **Статус:** готова к реализации (pre-flight закрыт, 2026-06-20).
> Модуль `github.com/akovalenko/wgpeer`.
> Маленький Go-CLI для управления пирами WireGuard: с мобилы по ssh завести
> именованный ключ + сразу QR, найти по имени, убить. **Источник истины по
> пирам — сам wg `.conf`**, серверный `[Interface]` (opinionated: PreUp/PostUp,
> ip rule) **не трогается**. Дизайн-обоснование и развилки — в идее
> [[wireguard-peer-cli]].

## 1. Назначение и юзкейс

- С телефона (termux → ssh на сервер) выполнить **add** `<имя>` → получить
  клиентский конфиг + **QR**; позже **list**, **kill** `<имя>`.
- **ssh = граница доступа.** Отдельного UI/демона/авторизации нет.
- Серверный wg-конфиг opinionated (PreUp/PostUp/ip rule, нестандартный MTU из-за
  upstream wg-over-vxlan) — **беречь, не регенерировать**.

## 2. Архитектура

**Один Go-бинарь, два режима** (решение; альтернатива — два тонких бинаря над тем
же модулем):

- `wgpeer server --iface <wgN> <cmd>` — на сервере, под `sudo` (правит
  `/etc/wireguard`, гоняет `wg`). Безголовый: читает запрос (args + stdin-JSON),
  пишет ответ (stdout-JSON).
- `wgpeer client <cmd>` — на termux/лаптопе: генерит приватник **локально**,
  ssh-ит на сервер, дёргает `wgpeer server`, собирает конфиг + рисует QR.

**Инвариант:** общий пакет `protocol` (типы запрос/ответ) компилируется в оба
режима — версии не разъезжаются по построению.

**Мульти-интерфейс (решение):** серверный конфиг **по-интерфейсно** —
`/etc/wgpeer/<iface>.toml` (расширение `.toml`, чтобы не путать с
`/etc/wireguard/wg0.conf`). `wgpeer server --iface wg0` грузит
`/etc/wgpeer/wg0.toml`. **Нет конфига для интерфейса → отказ** работать с ним
(защита от случайного захвата чужого wg). На клиенте — конфиг-меню серверов и их
интерфейсов (§4).

**Поток `add`:**

```
client                                   server (sudo, via ssh)
------                                   ----------------------
genkey → (priv, pub)
genpsk → psk                  --ssh-->   AddRequest{name,pub,psk}
                                         flock(.conf)
                                         allocate next free IP
                                         append [Peer] + "# name:"
                                         wg syncconf
                              <--ssh--   AddResponse{ip, server_pub,
                                          endpoints[], mtu, dns,
                                          keepalive, allowed_ips}
assemble client config (priv local)
render QR (нативная go-qrcode, полублоки)
```

`list` / `kill` — только серверная половина по ssh (клиентский keygen не нужен).

## 3. Три формата (каждому своё)

| Формат | Что | Почему |
|--------|-----|--------|
| **INI** (`wg .conf`) | источник истины по пирам | диктует WireGuard, не наш выбор |
| **TOML** | серверный конфиг/дефолты шаблона | человеко-редактируемый, в git, комменты |
| **JSON** | протокол client↔server по ssh | машинный, эфемерный, тривиально в Go |

## 4. Конфиги (TOML)

### 4.1. Серверный — `/etc/wgpeer/<iface>.toml` (по одному на интерфейс)

Имя интерфейса задаётся **именем файла** (`wg0.toml` → `wg0`); отсутствие файла
для `--iface` = отказ. Дефолты сети + указатель на wg-конфиг.

```toml
conf_path     = "/etc/wireguard/wg0.conf"   # источник истины по пирам
subnet        = "10.10.0.0/24"              # пул адресов для пиров (v4-only в v1)
# зарезервированные/занятые вне пиров (сервер, шлюзы)
reserved      = ["10.10.0.1"]

[template]                                  # server-owned дефолты клиентского конфига
dns                  = ["10.10.0.1"]
allowed_ips          = ["0.0.0.0/0", "::/0"]  # full-tunnel по умолчанию
persistent_keepalive = 25
mtu                  = 1340                  # с учётом вложенной инкапсуляции (см. §9)
psk_default          = true                 # PSK новым пирам (флаг --no-psk отменяет)

# Меню endpoint-ов (vantage-зависим, клиент выбирает; первый — дефолт)
[[endpoint]]
name = "public"
addr = "vpn.example:51820"
[[endpoint]]
name = "tspu-443"
addr = "vpn.example:443"
[[endpoint]]
name = "lan"
addr = "10.0.0.2:51820"
```

### 4.2. Клиентский — `~/.config/wgpeer/client.toml` (меню серверов × интерфейсов)

```toml
default_server = "home"

[[server]]
name   = "home"
ssh    = "anton@vpn.example"   # ssh-таргет (или alias из ~/.ssh/config)
sudo   = true                  # префиксовать команду sudo на сервере
ifaces = ["wg0", "wg1"]        # доступные интерфейсы; первый — дефолт
```

`wgpeer client add --server home --iface wg0 "имя"`; без флагов — `default_server`
и `ifaces[0]`. Клиент собирает `ssh <ssh> [sudo] wgpeer server --iface <iface> …`.

## 5. Протокол (JSON)

Одна операция = один ssh-exec, запрос в stdin, ответ в stdout, код выхода = статус.

```jsonc
// AddRequest  (client → server)
{ "op":"add", "name":"для Васи", "public_key":"<base64>", "preshared_key":"<base64|null>" }

// AddResponse (server → client)
{ "ok":true,
  "ip":"10.10.0.7/32",
  "server_public_key":"<base64>",
  "endpoints":[{"name":"public","addr":"vpn.example:51820"}, ...],
  "dns":["10.10.0.1"], "allowed_ips":["0.0.0.0/0","::/0"],
  "persistent_keepalive":25, "mtu":1340 }

// ListResponse (v1: только из файла — без wg show)
{ "ok":true, "peers":[{"name":"для Васи","public_key":"...","ip":"10.10.0.7/32",
                       "psk":true}] }
//   на будущее: поле last_handshake/transfer из `wg show` (требует sudo) — отложено

// kill: KillRequest{op:"kill", name} → {ok:true, removed:{name,public_key}}
// ошибка: {ok:false, error:"name_taken|no_free_ip|not_found|locked|bad_request", message:"..."}
```

Имя/ярлык — **не личность**; настоящая личность пира = `public_key`. `kill`
резолвит имя → pubkey; на дубль имени в `add` — `name_taken`.

## 6. Команды

### `add <name> [--endpoint <menu-name>] [--no-psk] [--split] [--qr-png <file>] [--invert]`

Клиент: genkey (+genpsk если psk) → ssh `wgpeer server add` с pubkey(+psk) → из
ответа собирает `[Interface]`/`[Peer]` (приватник локально) → выбирает endpoint
(флаг или дефолт-меню[0]) → печатает конфиг + **QR в терминал**.

**QR — нативной либой, без внешних бинарей** (в termux нет `qrencode`):
`github.com/skip2/go-qrcode` — pure-Go, без cgo, собирается под android/arm64.

- терминал: `ToSmallString(invert)` — рендер **полублоками** (`▀▄`), вдвое ниже
  полноблочного, влезает в экран телефона;
- файл (`--qr-png`): `WritePNG` той же либой — одна зависимость на оба выхода.
- **ECC = L** (Low): конфиг с ключами ~300+ байт; экран не бумага, повреждений
  нет → низкая коррекция держит QR компактным.
- **quiet-zone** (рамка-отступ) обязательна, иначе часть сканеров не берёт.
- **`--invert`:** сканеру нужен тёмный-на-светлом, а терминал обычно
  светлый-на-тёмном → `ToSmallString(inverse)` переключает. Дефолт подобрать
  (многие телефоны берут и инвертированный).

### `list [--json]`

**v1: только из файла.** Сервер парсит `.conf` (имена из `# name:`, pubkey, IP,
наличие PSK). Человеко-таблица или JSON. Обогащение live-данными (`wg show`
latest-handshakes/transfer) — **на будущее** (требует ещё и sudo на `wg show`),
парсить `wg show` пока не хотим.

### `kill <name>`

Сервер: flock → найти блок по `# name:` → удалить → atomic rename → `wg syncconf`
(или `wg set <iface> peer <pub> remove` на лету + перезапись файла).

## 7. Манипуляция wg `.conf`

- **Парсинг:** свой мелкий INI-ридер; пир = опц. строка `# name: <...>` + блок
  `[Peer]` (`PublicKey`, `PresharedKey?`, `AllowedIPs`). Парсер терпим к любому
  разумному форматированию старых блоков.
- **Стратегия записи:** `[Interface]` (и любой неузнанный контент до первого
  `[Peer]`) **сохраняем ДОСЛОВНО** — opinionated-кусок с PreUp/PostUp/ip rule не
  трогаем. `[Peer]`-блоки тул **owns** и пишет в **каноничной** форме:

  ```ini
  # name: <name>
  [Peer]
  PublicKey = <base64>
  PresharedKey = <base64>      # строка только при PSK
  AllowedIPs = <ip>/32
  ```

  Порядок полей и место `# name:`-коммента фиксированы → **round-trip**
  парсер↔сериализатор держится; нормализация старых пир-блоков допустима (их
  значения сохраняем, форматирование канонизируем).
- **Аллокация IP:** собрать занятые из всех `AllowedIPs` (хост-части) + `reserved`
  → следующий свободный в `subnet`. Нет свободных → `no_free_ip`.
- **Атомарность + конкурентность:** `flock(conf_path)` на всю операцию; запись во
  временный файл рядом → `fsync` → `rename` (атомарная замена) → `wg syncconf`.
- **`syncconf`-примитив:** `wg syncconf <iface> <(wg-quick strip <iface>)` —
  применяет только дельту пиров, **не дёргает интерфейс и не запускает хуки**.

## 8. PSK

- По умолчанию новым пирам (`psk_default=true`), `--no-psk` отменяет. **Per-peer**
  — старые ключи без PSK сосуществуют.
- Симметричный секрет → на обеих сторонах (`PresharedKey` в `[Peer]` сервера и в
  `[Peer]` сервера у клиента). Генерит **клиентская половина** (`wg genpsk`),
  шлёт серверу в `AddRequest`. По ssh-каналу (он шифрован) передавать норм.

## 9. Клиентский шаблон: владение полями, MTU/MSS

**Кто владеет фактом** (детали и обоснование — в идее [[wireguard-peer-cli]]):

- **Сервер:** IP, server pubkey, PSK, `ListenPort`, **меню endpoint-ов**, сетевые
  дефолты (DNS, `PersistentKeepalive`, `AllowedIPs`, **`MTU`**).
- **Клиент:** приватник (**не уходит**), финальная сборка + QR, **переопределение
  vantage-полей** (`Endpoint` из меню, split/full, keepalive).

**MTU при вложенной инкапсуляции** (upstream сервера уходит в wg-over-vxlan):

- Бутылочное горло — **вниз по потоку за тоннелем**, клиент его **не видит** и
  PMTUD не дотягивается → `MTU` **сообщает сервер** (поле `template.mtu`).
- Значение = мин. внутренний MTU по цепочке; замер: `ping -M do -s N` к
  апстриму, `MTU = N + 28`.
- **MSS-clamp на сервере** (`clamp-mss-to-pmtu`) — пояс-и-подтяжки для **TCP** у
  клиентов со старым/неверным MTU; UDP/QUIC clamp не лечит → клиентский `MTU`
  обязателен всё равно. (Сам clamp — часть серверной обвязки, вне wgpeer; в спеке
  как требование к окружению.)

## 10. Безопасность

- **Авторизация = ssh** (ключи). Никаких токенов/паролей у wgpeer.
- **Привилегии:** серверная половина под `sudo`; в sudoers скоупить ровно
  `wgpeer server` (`NOPASSWD` опц.), а не root-шелл.
- **Права файлов:** `.conf` и клиентские конфиги `0600`; временные файлы — тоже,
  в той же директории (чтобы rename был атомарным на одной ФС).
- **Секреты:** приватник клиента не покидает клиента; PSK — общий, идёт по ssh;
  логи не должны печатать приватные ключи/PSK.

## 11. Коды возврата

`0` ок; `≠0` + JSON `{ok:false,error}`: `name_taken`, `no_free_ip`, `not_found`,
`locked` (не взял flock за таймаут), `bad_request`, `internal`.

## 12. Объём v1 (решено)

- **v4-only** — IPv6-пул отложен.
- **Метаданные пира — только `# name:`** (без даты/коммента/сайдкара).
- **`list` — только из файла** (без `wg show`); хендшейки/трафик — на будущее.
- **Ротация/expiry ключей — за рамками.**
- **Мульти-интерфейс** — конфиг по-интерфейсно `/etc/wgpeer/<iface>.toml`,
  `wgpeer server --iface`, отказ при отсутствии конфига; клиентское меню
  серверов × интерфейсов (§2, §4).
- **Клиент передаёт голый ssh-таргет** — своя ssh-конфигурация (`-F`/отдельный
  `ssh_config`, `ProxyCommand`, jump-host, нестандартные порт/`IdentityFile`) из
  клиентского меню **не задаётся**; пока это возможно только через host-алиас в
  `~/.ssh/config` (§14 — экзек системного `ssh`). **TODO:** поле ssh-опций в
  `[[server]]` (или проброс доп. ssh-флагов), чтобы сервер, достижимый лишь через
  `ProxyCommand`/бастион, настраивался средствами самого wgpeer.

## 13. Этапы реализации

От сути к полировке; серверная половина первой; каждый этап тестируется отдельно.

- **Этап 0 — скелет:** модуль, пакет `protocol` (типы + JSON), загрузка
  TOML-конфигов (серверный по-iface + клиентское меню), CLI-каркас
  (`server`/`client`, `--iface`/`--server`). Без wg-логики.
- **Этап 1 — модель wg.conf (КЛЮЧЕВОЙ, pure, без живого wg):** парсер пиров
  (`# name:` + `[Peer]`), сериализатор с **round-trip**, аллокатор IP, индекс
  имён. **Table-тесты на фикстурах.** Сердце и самое рисковое по корректности —
  первым, долбим тестами.
- **Этап 2 — серверные мутации + apply:** `flock`, atomic `temp→fsync→rename`,
  шелл-аут `wg syncconf`; `add`/`list`/`kill` на реальном `.conf` под `sudo`.
  Интеграционный тест в **netns** с одноразовым `wg0`.
- **Этап 3 — клиентская половина:** нативный keygen (curve25519) + PSK, ssh-exec
  на сервер, сборка клиентского конфига из `AddResponse`, выбор полей шаблона, QR
  (go-qrcode полублоки, `--invert`, `--qr-png`).
- **Этап 4 — полировка:** коды ошибок наружу, `list --json`, резолв меню
  серверов × интерфейсов, кросс-сборка под android/arm64 + linux/amd64.

Зависимости: 0 раньше всех; 1 раньше 2; 3 — после `protocol` (0), тестируется
против рабочего сервера (2).

## 14. Готовность к передаче (pre-flight)

**Тех-стек (дефолты, можно переопределить):**

- **Go 1.23**; путь модуля **`github.com/akovalenko/wgpeer`**.
- **keygen — нативный** `golang.org/x/crypto/curve25519` (priv = 32 rand
  clamped, pub = scalar-base-mult; PSK = 32 rand). **Не** шелл `wg genkey` —
  zero-deps на клиенте.
- **TOML** — `pelletier/go-toml/v2`; **JSON** — stdlib; **QR** —
  `skip2/go-qrcode`.
- **CLI** — stdlib `flag` (3 команды, cobra избыточен).
- **`flock`** — `gofrs/flock` или `syscall.Flock`.
- **ssh-транспорт — экзек системного `ssh`** (чтит `~/.ssh/config`, агент,
  алиасы; есть в termux). **Не** встроенный `x/crypto/ssh`.

**Решено (Антон, 2026-06-20):** модуль `github.com/akovalenko/wgpeer`; ssh —
экзек системного `ssh`; keygen нативный; формат `[Peer]`-блока зафиксирован
(§7, `[Interface]` дословно + каноничные пир-блоки).

**Тестовая стратегия:** unit (парсер/аллокатор/сериализатор round-trip) на
фикстурах + интеграция в netns под build-tag.

**Спека готова к вручению кодинг-агенту.**

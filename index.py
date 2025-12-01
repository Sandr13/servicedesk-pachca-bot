# pachca_sd_tracker_handler_with_boards.py
import json
import os
import requests
import hashlib
import hmac
from requests.auth import HTTPBasicAuth

# -------------------- Конфиг --------------------
API_BASE_URL = "https://api.pachca.com/api/shared/v1"
PACHKA_API_TOKEN = os.environ.get("PACHKA_API_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

BOT_HEADERS = {"Authorization": f"Bearer {os.environ['PACHKA_API_TOKEN']}"}
TRACKER_HEADERS = {
    "Authorization": f"OAuth {os.environ['TRACKER_API_TOKEN']}",
    "X-Org-ID": os.environ["TRACKER_ORG_ID"],
    "Content-Type": "application/json"
}
queueField = "66aa43bfc941f16869268d41--"
try:
    BOT_USER_ID = int(os.environ.get("BOT_USER_ID", "0") or 0)
except Exception:
    BOT_USER_ID = 0

# Tracker config (env)
TRACKER_CREATE_URL = os.environ.get("TRACKER_CREATE_URL", "")  # <- полный endpoint для создания issue
TRACKER_API_TOKEN = os.environ.get("TRACKER_API_TOKEN", "")  # optional OAuth token
TRACKER_BASIC_USER = os.environ.get("TRACKER_BASIC_USER", "")  # optional basic auth
TRACKER_BASIC_PASS = os.environ.get("TRACKER_BASIC_PASS", "")  # optional basic auth pass
TRACKER_ORG_ID = os.environ.get("TRACKER_ORG_ID", "")  # если есть — используем X-Org-Id
TRACKER_CLOUD_ORG_ID = os.environ.get("TRACKER_CLOUD_ORG_ID", "")  # если есть — используем X-Cloud-Org-Id
TRACKER_BOARD_ID = 1  # default board id = 1

# ya360 env
Y360_OAUTH = os.environ.get("Y360_OAUTH", "")
Y360_ORG_ID = os.environ.get("Y360_ORG_ID", "")

TRACKER_QUEUE = "SERVICEDESK"
TAG = "Создана в Пачке"

BOT_HEADERS = {
    "Authorization": f"Bearer {PACHKA_API_TOKEN}" if PACHKA_API_TOKEN else "",
    "Content-Type": "application/json"
}


# -------------------- Утилиты Pachca --------------------
def send_message(chat_id, text, buttons=None):
    payload = {"message": {"entity_id": chat_id, "content": text}}
    if buttons:
        payload["message"]["buttons"] = buttons
    print("send_message -> payload:", json.dumps(payload, ensure_ascii=False))
    try:
        r = requests.post(f"{API_BASE_URL}/messages", headers=BOT_HEADERS, json=payload, timeout=8)
        print("send_message -> status:", r.status_code, "body:", (r.text or "")[:1000])
        r.raise_for_status()
        try:
            return r.json()  # ожидаем структуру {"data": {...}}
        except Exception:
            return None
    except Exception as e:
        print("send_message error:", e)
        return None


# 2) Новая утилита: обновление issue в Tracker (PATCH)
def update_tracker_issue(issue_key, extra_fields):
    """
    Обновляет issue в Tracker, добавляя/обновляя поля из extra_fields (dict).
    issue_key — ключ типа SERVICEDESK-1234 (подходит для пути v3/issues/{key}).
    extra_fields — словарь полей для отправки в тело запроса.
    Возвращает (ok: bool, resp_json_or_text)
    """
    if not TRACKER_CREATE_URL:
        return False, "TRACKER_CREATE_URL not configured"

    url = f"https://api.tracker.yandex.net/v3/issues/{issue_key}"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    auth = None
    if TRACKER_API_TOKEN:
        headers["Authorization"] = f"OAuth {TRACKER_API_TOKEN}"
    elif TRACKER_BASIC_USER and TRACKER_BASIC_PASS:
        auth = HTTPBasicAuth(TRACKER_BASIC_USER, TRACKER_BASIC_PASS)

    if TRACKER_CLOUD_ORG_ID:
        headers["X-Cloud-Org-Id"] = TRACKER_CLOUD_ORG_ID
    elif TRACKER_ORG_ID:
        headers["X-Org-Id"] = TRACKER_ORG_ID
    else:
        return False, "No TRACKER_ORG_ID or TRACKER_CLOUD_ORG_ID configured"

    try:
        # PATCH — частичное обновление полей
        r = requests.patch(url, headers=headers, json=extra_fields, auth=auth, timeout=10)
        print("PATCH tracker -> status:", r.status_code, "body:", (r.text or "")[:2000])
        try:
            j = r.json()
        except Exception:
            j = r.text
        return (200 <= r.status_code < 300), j
    except Exception as e:
        print("update_tracker_issue exception:", e)
        return False, str(e)


def add_tracker_comment(issue_id, text):
    url = f"https://api.tracker.yandex.net/v2/issues/{issue_id}/comments"

    headers = {
        "Authorization": f"OAuth {os.environ['TRACKER_API_TOKEN']}",
        "X-Org-ID": os.environ['TRACKER_ORG_ID'],
        "Content-Type": "application/json"
    }

    payload = {"text": text}

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()


def extract_nicknames(text):
    return re.findall(r'@([\w\.-]+)', text or "")


def _safe_json(resp):
    try:
        return resp.json() if resp and resp.text else {}
    except Exception:
        return {}


def _users_from_response(j):
    if not j:
        return []
    if isinstance(j, list):
        return j
    if isinstance(j, dict):
        if "data" in j:
            d = j["data"]
            if isinstance(d, list):
                return d
            if isinstance(d, dict):
                return [d]
        for key in ("users", "items"):
            if key in j and isinstance(j[key], list):
                return j[key]
    return []


def get_user_info(user_id):
    if not user_id:
        return {}
    try:
        url = f"{API_BASE_URL.rstrip('/')}/users/{user_id}"
        print("get_user_info -> GET", url)
        r = requests.get(url, headers=BOT_HEADERS, timeout=6)
        print("GET /users/<id> -> status:", r.status_code)
        if r.status_code == 200:
            j = _safe_json(r)
            return j.get("data") if isinstance(j, dict) and "data" in j else j
    except Exception as e:
        print("get_user_info error:", e)
    return {}


def find_pachca_user_id_by_nickname(nickname):
    """
    Ищет user_id по никнейму через рабочий endpoint /users?query=<nickname>.
    Возвращает id только при уверенном совпадении:
      1) точное совпадение по полю 'nickname' в результатах
      2) либо совпадение localpart(email) == nickname
    Если не найдено — возвращает None.
    """
    if not nickname:
        return None

    try:
        url = f"{API_BASE_URL.rstrip('/')}/users"
        params = {"query": nickname}
        print("find: GET", url, "params:", params)
        r = requests.get(url, headers=BOT_HEADERS, params=params, timeout=6)
        print("-> status:", r.status_code)
        if r.status_code != 200:
            print("find: non-200 response:", (r.text or "")[:1000])
            return None

        j = _safe_json(r)
        users = _users_from_response(j)
        print(f"find: query returned {len(users)} users")

        # 1) ищем точное совпадение по полю nickname
        for u in users:
            if not isinstance(u, dict):
                continue
            if u.get("nickname") == nickname:
                print("find: exact nickname match ->", u.get("id"))
                return u.get("id")

        # 2) пытаемся сопоставить localpart(email) == nickname
        for u in users:
            if not isinstance(u, dict):
                continue
            email = u.get("email") or u.get("mail")
            if isinstance(email, str) and "@" in email:
                local = email.split("@", 1)[0]
                if local == nickname:
                    print("find: matched by email localpart ->", u.get("id"))
                    return u.get("id")

        print("find: no exact match for", nickname)
        return None

    except Exception as e:
        print("find: exception:", e)
        return None


def get_tracker_login_from_pachca_nickname(nickname):
    """
    Для заданного никнейма Пачки возвращает логин трекера (localpart email),
    или None если не удалось получить.
    """
    user_id = find_pachca_user_id_by_nickname(nickname)
    if not user_id:
        print(f"[WARN] Пользователь @{nickname} не найден в Пачке (query didn't match)")
        return None

    info = get_user_info(user_id)
    if not info:
        print(f"[WARN] get_user_info empty for user_id {user_id}")
        return None

    email = info.get("email") or info.get("mail")
    if email and isinstance(email, str) and "@" in email:
        login = email.split("@", 1)[0]
        print(f"→ {nickname} (id={user_id}) -> {login} via email")
        return login

    # если email нет, попробуем поля, которые выглядят как логин
    for k in ("login", "username", "nickname"):
        v = info.get(k)
        if v and isinstance(v, str) and "@" not in v:
            print(f"→ {nickname} (id={user_id}) -> {v} via field {k}")
            return v

    print(f"[WARN] No login/email for @{nickname} (user_id={user_id})")
    return None


def add_users_to_tracker_access(issue_key, text):
    """
    Совместимый drop-in: принимает (issue_key, text).
    - извлекает @ники из text,
    - резолвит их в tracker-logins через get_tracker_login_from_pachca_nickname,
    - получает текущее поле access у задачи,
    - добавляет новые логины (без дубликатов) и PATCH'ит полный список.
    Возвращает dict {"added": [...], "skipped": [...]}.
    """
    # 1) извлечь уникальные ники
    mentioned_nicks = extract_nicknames(text)
    if not mentioned_nicks:
        print("add_users_to_tracker_access: no mentions")
        return {"added": [], "skipped": []}

    seen = set()
    uniq_nicks = []
    for n in mentioned_nicks:
        if n not in seen:
            seen.add(n)
            uniq_nicks.append(n)
    print("Найденные упоминания (unique):", uniq_nicks)

    # 2) разрешить ники в логины трекера
    new_logins = []
    skipped_resolution = []
    for nick in uniq_nicks:
        try:
            login = get_tracker_login_from_pachca_nickname(nick)
        except Exception as e:
            print("get_tracker_login_from_pachca_nickname failed:", e)
            login = None
        if not login:
            skipped_resolution.append(nick)
            print(f"Skipped @{nick}: no tracker login found")
            continue
        new_logins.append(login)

    if not new_logins:
        print("add_users_to_tracker_access: no logins resolved, nothing to add")
        return {"added": [], "skipped": skipped_resolution}

    # 3) GET current issue and current access
    issue_url = f"https://api.tracker.yandex.net/v2/issues/{issue_key}"
    # build headers (use TRACKER_HEADERS if defined, otherwise fallback to env vars)
    headers = globals().get("TRACKER_HEADERS")
    if not headers:
        headers = {
            "Authorization": f"OAuth {os.environ.get('TRACKER_API_TOKEN', '')}",
            "X-Org-ID": os.environ.get("TRACKER_ORG_ID", ""),
            "Content-Type": "application/json"
        }

    try:
        issue_resp = requests.get(issue_url, headers=headers, timeout=10)
    except Exception as e:
        print("add_users_to_tracker_access: failed GET issue:", e)
        return {"added": [], "skipped": uniq_nicks}

    if issue_resp.status_code != 200:
        print(
            f"add_users_to_tracker_access: failed to fetch issue {issue_key}: {issue_resp.status_code} {issue_resp.text[:1000]}")
        return {"added": [], "skipped": uniq_nicks}

    try:
        issue_data = issue_resp.json()
    except Exception:
        issue_data = {}

    current_access = issue_data.get("access") or []
    # normalize existing access entries into a set of ids (strings)
    current_logins = set()
    for a in current_access:
        if isinstance(a, dict):
            aid = a.get("id")
            if aid:
                current_logins.add(str(aid))
        elif isinstance(a, str):
            current_logins.add(a)
        else:
            # ignore unknown formats
            pass

    # 4) merge: add only new, avoid duplicates
    added = []
    skipped = []
    for login in new_logins:
        if login in current_logins:
            skipped.append(login)
        else:
            current_logins.add(login)
            added.append(login)

    # 5) if nothing to add — return
    if not added:
        print("add_users_to_tracker_access: nothing new to add, skipped:", skipped, "resolution skipped:",
              skipped_resolution)
        return {"added": [], "skipped": skipped + skipped_resolution}

    # 6) build updated access payload and PATCH
    # Tracker expects access entries as objects like {"id": "<login>"} (tested)
    updated_access = [{"id": l} for l in sorted(current_logins)]  # sort for deterministic output
    patch_payload = {"access": updated_access}

    try:
        patch_resp = requests.patch(issue_url, headers=headers, json=patch_payload, timeout=10)
        print(f"PATCH access -> {added} | status: {patch_resp.status_code}")
        if patch_resp.status_code not in (200, 204):
            print("add_users_to_tracker_access: PATCH failed:", (patch_resp.text or "")[:2000])
            # consider rolling back current_logins change? we just report failure
            return {"added": [], "skipped": uniq_nicks}
    except Exception as e:
        print("add_users_to_tracker_access: PATCH exception:", e)
        return {"added": [], "skipped": uniq_nicks}

    print("add_users_to_tracker_access result: added:", added, "skipped:", skipped + skipped_resolution)
    return {"added": added, "skipped": skipped + skipped_resolution}


# -------------------- new helper: find tracker issue by pachcaMessageId ----
def find_tracker_issue_by_pachca_message_id(pachca_message_id):
    """
    Ищет issue в Tracker по локальному полю 66aa43...--pachcaMessageId == pachca_message_id.
    Возвращает первый найденный issue dict или None.
    """
    try:
        url_v3 = "https://api.tracker.yandex.net/v3/issues/_search"
        headers_tr = {"Content-Type": "application/json", "Accept": "application/json"}
        auth = None
        if TRACKER_API_TOKEN:
            headers_tr["Authorization"] = f"OAuth {TRACKER_API_TOKEN}"
        elif TRACKER_BASIC_USER and TRACKER_BASIC_PASS:
            auth = HTTPBasicAuth(TRACKER_BASIC_USER, TRACKER_BASIC_PASS)

        if TRACKER_CLOUD_ORG_ID:
            headers_tr["X-Cloud-Org-Id"] = TRACKER_CLOUD_ORG_ID
        elif TRACKER_ORG_ID:
            headers_tr["X-Org-Id"] = TRACKER_ORG_ID

        queue_id = "29"
        field_msg = f"{queueField}pachcaMessageId"

        body = {
            "filter": {
                "queue": {"id": queue_id},
                "tags": [TAG],
                # значение может быть строкой/числом — приводим к строке
                field_msg: str(pachca_message_id)
            },
            "order": "-updated"
        }

        params = {"perPage": 100, "page": 1, "expand": "transitions"}
        resp = requests.post(url_v3, headers=headers_tr, json=body, params=params, auth=auth, timeout=20)
        print("find_tracker_issue_by_pachca_message_id -> status:", resp.status_code)
        if resp.status_code != 200:
            print("find_tracker_issue_by_pachca_message_id -> non-200:", resp.text)
            return None

        j = resp.json()
        if isinstance(j, list):
            issues = j
        elif isinstance(j, dict):
            issues = j.get("issues") or j.get("data") or j.get("items") or []
        else:
            issues = []

        if not issues:
            print("find_tracker_issue_by_pachca_message_id -> no issues found")
            return None

        # возвращаем первый issue (можно расширить логику выбора)
        print("find_tracker_issue_by_pachca_message_id -> found issue:", issues[0].get("key") or issues[0].get("id"))
        return issues[0]
    except Exception as e:
        print("find_tracker_issue_by_pachca_message_id exception:", e)
        return None


# 3) Полная функция handle_view_submission (обновлённая)
def handle_view_submission(request_json):
    print("handle_view_submission -> request_json (truncated):", json.dumps(request_json, ensure_ascii=False)[:3000])

    # --- распаковка данных формы ---
    data = request_json.get("data") or {}
    if not data:
        state = request_json.get("state", {}) or {}
        values = state.get("values", {}) or {}
        for block_name, inner in values.items():
            for action_id, valobj in inner.items():
                v = valobj.get("value")
                if v is not None:
                    data[block_name] = v

    print("Extracted form data:", json.dumps(data, ensure_ascii=False))

    # --- private metadata (куда слать ответ) ---
    chat_id = None
    pm_raw = request_json.get("private_metadata")
    if pm_raw:
        try:
            pm = json.loads(pm_raw)
            chat_id = pm.get("chat_id")
            print("private_metadata parsed:", pm)
        except Exception:
            print("private_metadata present but not json:", pm_raw)

    # --- автор (user_id) для fallback-ответов ---
    user_id = request_json.get("user_id")
    print("Resolved webhook user_id:", user_id)

    # --- валидация: выбрана ровно одна подтема (topic_...) ---
    topic_fields = [k for k in data.keys() if k.startswith("topic_")]
    selected = [(k, data[k]) for k in topic_fields if data.get(k)]
    selected_topics = [v for _, v in selected]

    if len(selected) != 1:
        msg = "❌❌❌Ошибка отправки формы. Выберите одну тему обращения."
        print("Validation error:", msg, "selected_topics:", selected_topics)
        if chat_id:
            send_message(chat_id, msg)
        elif user_id:
            send_message(user_id, msg)
        return {"statusCode": 200, "body": "ok"}

    selected_block_name, selected_value = selected[0]
    print("Selected block:", selected_block_name, "selected value:", selected_value)

    # --- описание (обязательное поле) ---
    description = data.get("description") or ""
    if not (isinstance(description, str) and description.strip()):
        errors = {"description": "Опишите проблему — это поле обязательно."}
        body = json.dumps({"errors": errors}, ensure_ascii=False)
        print("Validation errors -> returning 400:", body)
        return {"statusCode": 400, "body": body, "headers": {"Content-Type": "application/json"}}

    # --- получаем user info (для имени/почты) ---
    user_info = get_user_info(user_id) or {}
    user_name = ((user_info.get("first_name") or "") + (
        " " + (user_info.get("last_name") or "") if user_info.get("last_name") else "")).strip()
    user_name = user_name or user_info.get("display_name") or user_info.get("nickname") or f"user_{user_id}"
    user_email = user_info.get("email") or user_info.get("login") or ""
    email_login = user_email.split("@", 1)[0] if user_email and "@" in user_email else user_email

    print("Resolved user_name:", user_name, "user_email:", user_email, "email_login:", email_login)

    # --- формируем summary из label выбранного radio-блока ---
    summary = None
    try:
        view_template = build_sd_view()
        for block in (view_template.get("blocks") or []):
            if block.get("type") == "radio" and block.get("name") == selected_block_name:
                summary = block.get("label") or None
                break
    except Exception as e:
        print("Error while reading view template for summary label:", e)

    if not summary:
        # fallback: используем текст выбранной опции
        summary = selected_value or "Обращение в ServiceDesk"

    print("Computed summary (label):", summary)

    # --- attachments для сообщения пользователю (в трекер пока не отправляем) ---
    attachments = data.get("attachments") or []
    attachments_list = []
    if isinstance(attachments, list):
        for a in attachments:
            if isinstance(a, dict):
                attachments_list.append(
                    a.get("name") or a.get("filename") or a.get("url") or json.dumps(a, ensure_ascii=False))
            else:
                attachments_list.append(str(a))
    attachments_text = ", ".join(attachments_list) if attachments_list else "-"

    # --- формируем description для трекера (подкатегория + описание) ---
    description_for_tracker = f"*Подкатегория:* {selected_value}\n*Описание проблемы:* {description.strip()}"
    reporter_name = user_name
    reporter_login = email_login

    print("description_for_tracker:", description_for_tracker)

    # --- определяем department (если доступно) ---
    department_id = None
    department = None
    try:
        if user_email:
            department_id = get_user_department_id(user_email)
            print("Resolved department_id:", department_id)
            depts_mapping = get_departments_mapping()
            print("Departments mapping:", depts_mapping)
            department = depts_mapping.get(department_id)
            print("Resolved department name:", department)
    except Exception as e:
        print("Error resolving department:", e)

    # --- создаём задачу в трекере ---
    queue = "SERVICEDESK"
    ok, key_or_err, raw_resp = create_tracker_issue(queue, summary, description_for_tracker, reporter_name,
                                                    reporter_login, department)
    if ok:
        issue_key = key_or_err
        issue_url = f"https://tracker.yandex.ru/{issue_key}"

        # --- отправляем сообщение пользователю и забираем его message_id ---
        user_message = (
            f"📩 Обращение в ServiceDesk\n"
            f"Тема: {summary}\n"
            f"Описание: {description}\n"
            f"Ссылка на задачу: {issue_url}"
        )
        print(f"Tracker created ({issue_key}), sending user_message: {user_message}, user_name: {user_name}")
        dest = chat_id or user_id
        sent_resp = None
        if dest:
            sent_resp = send_message(dest, user_message)
        else:
            print("No destination to send created-issue message; message:", user_message)

        # попытка вытянуть id сообщения из ответа Pachca
        pachca_message_id = None
        try:
            if isinstance(sent_resp, dict):
                # ожидаем {'data': {'id': 12345, ...}, ...}
                data_obj = sent_resp.get("data") or sent_resp
                if isinstance(data_obj, dict):
                    pachca_message_id = data_obj.get("id") or data_obj.get("message_id")
            # иногда API возвращает другой формат — пробуем простые ключи
            if not pachca_message_id and isinstance(sent_resp, dict):
                pachca_message_id = sent_resp.get("id")
        except Exception as e:
            print("Error extracting pachca_message_id from send_message response:", e)

        # --- формируем поля для обновления задачи в трекере ---
        extra_fields = {
            f"{queueField}pachcaUserId": user_id,
            f"{queueField}pachcaMessageId": pachca_message_id,
            f"{queueField}pachcaChatId": chat_id
        }

        # убираем None значения (чтобы не слать null если поле не определено)
        extra_fields = {k: v for k, v in extra_fields.items() if v is not None}

        if extra_fields:
            ok_upd, upd_resp = update_tracker_issue(issue_key, extra_fields)
            print("update_tracker_issue -> ok:", ok_upd, "resp:", upd_resp)
        else:
            print("No extra_fields to update on tracker.")

        # --- сообщаем пользователю (если сообщение было отправлено, уже отправлено выше) ---
        return {"statusCode": 200, "body": "ok"}
    else:
        error_info = key_or_err
        print("Tracker creation failed:", error_info, "raw_resp:", raw_resp)
        fail_msg = f"Не удалось создать задачу в трекере: {error_info}. Обратитесь в ServiceDesk или попробуйте позже."
        if chat_id:
            send_message(chat_id, fail_msg)
        elif user_id:
            send_message(user_id, fail_msg)
        else:
            print("No destination to send tracker-failure message:", fail_msg)
        return {"statusCode": 200, "body": "ok"}


# ---- Новый: отправка сообщения в тред (parent_message_id) ----
# ---- Создать тред для сообщения (если ещё не создан) ----
def create_thread_for_message(message_id):
    """
    POST /messages/{message_id}/thread
    Возвращает thread_id (int) или None.
    """
    if not message_id:
        return None
    try:
        url = f"{API_BASE_URL}/messages/{int(message_id)}/thread"
    except Exception:
        url = f"{API_BASE_URL}/messages/{message_id}/thread"
    try:
        r = requests.post(url, headers=BOT_HEADERS, timeout=8)
        print("POST /messages/{id}/thread -> status:", r.status_code, "body:", (r.text or "")[:1000])
        if 200 <= r.status_code < 300:
            j = r.json() if r.text else {}
            data = j.get("data") or j
            thread_id = data.get("id") or data.get("message_id")
            return thread_id
        else:
            # логируем причину (например 404 not_found)
            return None
    except Exception as e:
        print("create_thread_for_message exception:", e)
        return None


# ---- Упрощённая единичная отправка сообщения (thread-entity OR parent-reply) ----
def send_threaded_message(chat_id=None, text="", parent_message_id=None, thread_entity_id=None, buttons=None):
    """
    - Если thread_entity_id задан — постим в entity_type='thread' (entity_id = thread_entity_id).
    - Иначе — постим в чат (entity_id=chat_id). Если parent_message_id задан — это reply.
    Возвращает parsed JSON или None.
    """
    payload = {"message": {"content": text}}

    if thread_entity_id is not None:
        try:
            payload["message"]["entity_id"] = int(thread_entity_id)
        except Exception:
            payload["message"]["entity_id"] = thread_entity_id
        payload["message"]["entity_type"] = "thread"
        # не добавляем parent_message_id при прямой публикации в thread entity
    else:
        if chat_id is None:
            print("send_threaded_message: missing chat_id and no thread_entity_id")
            return None
        try:
            payload["message"]["entity_id"] = int(chat_id)
        except Exception:
            payload["message"]["entity_id"] = chat_id
        if parent_message_id is not None:
            try:
                payload["message"]["parent_message_id"] = int(parent_message_id)
            except Exception:
                payload["message"]["parent_message_id"] = parent_message_id

    if buttons:
        payload["message"]["buttons"] = buttons

    print("send_threaded_message -> payload:", json.dumps(payload, ensure_ascii=False))
    try:
        r = requests.post(f"{API_BASE_URL}/messages", headers=BOT_HEADERS, json=payload, timeout=8)
        print("send_threaded_message -> status:", r.status_code, "body:", (r.text or "")[:1000])
        try:
            return r.json()
        except Exception:
            return {"raw": r.text or "", "status": r.status_code}
    except Exception as e:
        print("send_threaded_message error:", e)
        return None


# ---- Простейшая идемпотентность (пример; в проде — внешнее хранилище) ----
_processed_comments_cache = set()


def already_processed_comment(comment_id):
    # В demo-реализации — процесс живёт в памяти (теряется при cold start).
    # Лучше: использовать Redis / Yandex DB / S3 с TTL.
    if not comment_id:
        return False
    return str(comment_id) in _processed_comments_cache


def mark_comment_processed(comment_id):
    if not comment_id:
        return
    _processed_comments_cache.add(str(comment_id))


import re

PACHCA_EMAIL_DOMAIN = os.environ.get("PACHCA_EMAIL_DOMAIN", "bnovo.ru")


def find_pachca_user_by_query(query):
    """
    Ищет пользователя в Pachca через /users/?query=<query>.
    Возвращает user dict (первый результат) или None.
    """
    try:
        url = f"{API_BASE_URL}/users/?query={requests.utils.requote_uri(str(query))}"
        print("find_pachca_user_by_query -> url:", url)
        r = requests.get(url, headers=BOT_HEADERS, timeout=6)
        print("find_pachca_user_by_query -> status:", r.status_code)
        if r.status_code == 200:
            j = r.json()
            data = j.get("data") if isinstance(j, dict) and "data" in j else j
            if isinstance(data, list) and data:
                print("find_pachca_user_by_query -> found user:", data[0])
                return data[0]
    except Exception as e:
        print("find_pachca_user_by_query error:", e)
    return None


# ---- Обновлённый обработчик комментария ----
def handle_issue_comment_event(request_json):
    print("handle_issue_comment_event ->", json.dumps(request_json, ensure_ascii=False)[:2000])

    issue = request_json.get("issue") or {}
    comment = request_json.get("comment") or {}

    pachca_chat_id = issue.get("pachcaChatId") or (issue.get("local") or {}).get("pachcaChatId")
    pachca_message_id = issue.get("pachcaMessageId") or (issue.get("local") or {}).get("pachcaMessageId")

    # Если трекер шлёт уникальный идентификатор комментария — используем его для идемпотентности
    comment_id = comment.get("id") or comment.get("commentId") or comment.get("key")
    if comment_id and already_processed_comment(comment_id):
        print("handle_issue_comment_event: comment already processed, skipping:", comment_id)
        return {"statusCode": 200, "body": "ok (dup)"}

    comment_text = comment.get("text") or comment.get("body") or ""
    author = comment.get("author")
    if isinstance(author, dict):
        author_name = author.get("display") or author.get("displayName") or author.get("name") or author.get(
            "login") or author.get("email")
    elif isinstance(author, str):
        author_name = author
    else:
        author_name = None
    author_name = author_name or "Неизвестный"
    issue_key = issue.get("key") or issue.get("issueKey") or "unknown"

    if not pachca_chat_id or not pachca_message_id:
        print("handle_issue_comment_event: missing pachcaChatId or pachcaMessageId — skipping send.",
              "pachca_chat_id:", pachca_chat_id, "pachca_message_id:", pachca_message_id)
        return {"statusCode": 200, "body": "ok (no pachca target)"}

    # короткий защищённый текст
    if isinstance(comment_text, str):
        comment_text_short = comment_text.strip()
        if len(comment_text_short) > 4000:
            comment_text_short = comment_text_short[:4000] + "…"
    else:
        comment_text_short = str(comment_text)

    # --- заменяем упоминания @login -> @pachca_nickname (если найдём в Pachca) ---
    try:
        # ищем упоминания вида @login (латиница, цифры, ., _, -)
        mentions = re.findall(r'@([A-Za-z0-9._-]+)', comment_text_short or "")
        if mentions:
            print("Found mentions in comment:", mentions)
            # уникальные вхождения
            for login in set(mentions):
                replaced = False
                # 1) попытаться найти прямо по login
                user = find_pachca_user_by_query(login)
                # 2) если не найдено — попробовать как email login@domain
                if not user and "@" not in login:
                    guess = f"{login}@{PACHCA_EMAIL_DOMAIN}"
                    user = find_pachca_user_by_query(guess)
                if user:
                    # выбрать наиболее подходящее поле для никнейма
                    nick = user.get("nickname") or user.get("login") or (user.get("email") or "").split("@")[
                        0] or user.get("display_name") or user.get("first_name")
                    nick = str(nick)
                    if nick:
                        # заменить все вхождения @login на @nick (граница слова — чтобы не сломать похожие)
                        new_text, n = re.subn(r'@' + re.escape(login) + r'\b', '@' + nick, comment_text_short)
                        if n:
                            print(f"Replaced @{login} -> @{nick} (replacements: {n})")
                            comment_text_short = new_text
                            replaced = True
                if not replaced:
                    print(f"No Pachca user found for mention @{login}; skipped replacement.")
    except Exception as e:
        print("Error while replacing mentions:", e)

    content = (
        f"🔔 Добавлен комментарий к задаче:\n\n"
        f"{author_name}:\n"
        f"{comment_text_short}"
    )

    # 1) попробуем получить message info и взять thread.id
    thread_entity_id = None
    try:
        msg_info = get_message_info(pachca_message_id)
        if isinstance(msg_info, dict):
            data_obj = msg_info.get("data") or msg_info
            thread_obj = data_obj.get("thread") or {}
            if isinstance(thread_obj, dict):
                thread_entity_id = thread_obj.get("id") or thread_obj.get("message_id") or thread_obj.get("thread_id")
                if thread_entity_id:
                    print("Found thread_entity_id from message:", thread_entity_id)
            # ещё проверим случай, когда сообщение само является thread (entity_type == 'thread')
            if not thread_entity_id:
                if data_obj.get("entity_type") == "thread" and data_obj.get("entity_id"):
                    thread_entity_id = data_obj.get("entity_id")
                    print("Found thread_entity_id from message.entity_id:", thread_entity_id)
    except Exception as e:
        print("Error while get_message_info for pachca_message_id:", pachca_message_id, e)

    # 2) если треда нет — создаём его один раз
    if not thread_entity_id:
        thread_entity_id = create_thread_for_message(pachca_message_id)
        if thread_entity_id:
            print("Created new thread -> id:", thread_entity_id)
        else:
            print("No thread created (server returned none) — will fallback to parent-reply")

    # 3) если есть thread_entity_id — постим прямо в thread-entity (без parent_message_id)
    if thread_entity_id:
        resp = send_threaded_message(thread_entity_id=thread_entity_id, text=content)
        print("handle_issue_comment_event: sent into pachca thread-entity, resp:",
              json.dumps(resp, ensure_ascii=False)[:400] if isinstance(resp, dict) else resp)
        if comment_id:
            mark_comment_processed(comment_id)
        return {"statusCode": 200, "body": "ok"}

    # 4) fallback — single reply (parent_message_id)
    resp = send_threaded_message(chat_id=pachca_chat_id, text=content, parent_message_id=pachca_message_id)
    print("handle_issue_comment_event: sent into pachca as parent-reply (fallback), resp:",
          json.dumps(resp, ensure_ascii=False)[:400] if isinstance(resp, dict) else resp)
    if comment_id:
        mark_comment_processed(comment_id)
    return {"statusCode": 200, "body": "ok"}


def get_message_info(message_id):
    print("get_message_info -> message_id:", message_id)
    try:
        r = requests.get(f"{API_BASE_URL}/messages/{message_id}", headers=BOT_HEADERS, timeout=8)
        print("GET /messages -> status:", r.status_code, "body:", (r.text or "")[:1000])
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print("get_message_info error:", e)
    return None


def get_user_info(user_id):
    """Получаем user info из Pachca (возвращаем dict или {})."""
    if not user_id:
        return {}
    print("get_user_info -> user_id:", user_id)
    try:
        r = requests.get(f"{API_BASE_URL}/users/{user_id}", headers=BOT_HEADERS, timeout=6)
        print("GET /users -> status:", r.status_code, "body:", (r.text or "")[:1000])
        if r.status_code == 200:
            j = r.json()
            return j.get("data") if isinstance(j, dict) and "data" in j else j
    except Exception as e:
        print("get_user_info error:", e)
    return {}


def open_view(trigger_id, view_obj, private_metadata=None, callback_id=None):
    payload = {"trigger_id": trigger_id, "type": "modal", "view": view_obj}
    if private_metadata is not None:
        payload["private_metadata"] = json.dumps(private_metadata, ensure_ascii=False)
    if callback_id:
        payload["callback_id"] = callback_id

    print("open_view -> payload (truncated):", json.dumps(payload, ensure_ascii=False)[:1200])
    try:
        r = requests.post(f"{API_BASE_URL}/views/open", headers=BOT_HEADERS, json=payload, timeout=6)
        print("POST /views/open -> status:", r.status_code, "body:", (r.text or "")[:2000])
        return r.status_code >= 200 and r.status_code < 300
    except Exception as e:
        print("open_view error:", e)
        return False


def get_user_department_id(email):
    url = f"https://api360.yandex.net/directory/v1/org/{Y360_ORG_ID}/users?perPage=500"
    headers = {
        "Authorization": f"OAuth {Y360_OAUTH}",
        "X-Org-ID": f"{Y360_ORG_ID}"
    }

    response = requests.get(url, headers=headers)
    print(f"get_user_department_id -> status: {response.status_code}")

    if response.status_code != 200:
        raise Exception(f"Ошибка при получении пользователей: {response.status_code}, {response.text}")

    users = response.json().get("users", [])
    print(f"Всего пользователей в ответе: {len(users)}")

    for user in users:
        if user.get("email", "").lower() == email.lower():
            dept_id = user.get("departmentId")
            print(f"Найден пользователь: {user.get('name', '—')} → departmentId: {dept_id}")
            return dept_id

    print(f"Пользователь не найден по email: {email}")
    return None


def get_departments_mapping():
    url = f"https://api360.yandex.net/directory/v1/org/{Y360_ORG_ID}/departments?perPage=30"
    headers = {
        "Authorization": "OAuth y0__xD79eClqveAAhiikDggsunCsRM-9pN06XrhL-KV5WPNFBmykrw7PQ",
        "X-Org-ID": f"{Y360_ORG_ID}"
    }

    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Ошибка при получении отделов: {response.status_code}, {response.text}")

    data = response.json()
    departments = data.get("departments", [])
    return {dept["id"]: dept["name"] for dept in departments}


# -------------------- Tracker integration --------------------
def create_tracker_issue(queue, summary, description, reporter_name, reporter_login, department_id=None):
    """
    Создаёт issue в Tracker. Добавляет поле department, если указано.
    """
    if not TRACKER_CREATE_URL:
        msg = "TRACKER_CREATE_URL not configured"
        print("create_tracker_issue error:", msg)
        return False, msg, None

    try:
        board_id_int = int(TRACKER_BOARD_ID)
    except Exception:
        board_id_int = 1
    print(f"reporter_name: {reporter_name}")
    payload = {
        "queue": queue,
        "summary": summary,
        "description": description,
        "tags": "Создана в Пачке",
        # "assignee": reporter_login,
        # "followers": reporter_login,
        "author": reporter_login,
        f"{queueField}name": reporter_name,
        # f"{queueField}feedbackInAPachca": reporter_login,
        "boards": [{"id": board_id_int}]
    }

    if department_id:
        payload[f"{queueField}department"] = department_id
        print(f"Добавлено поле department: {department_id}")

    print("create_tracker_issue -> payload:", json.dumps(payload, ensure_ascii=False))

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    auth = None
    if TRACKER_API_TOKEN:
        headers["Authorization"] = f"OAuth {TRACKER_API_TOKEN}"
        print("create_tracker_issue -> using OAuth token")
    elif TRACKER_BASIC_USER and TRACKER_BASIC_PASS:
        auth = HTTPBasicAuth(TRACKER_BASIC_USER, TRACKER_BASIC_PASS)
        print("create_tracker_issue -> using Basic auth")

    if TRACKER_CLOUD_ORG_ID:
        headers["X-Cloud-Org-Id"] = TRACKER_CLOUD_ORG_ID
        print("create_tracker_issue -> set X-Cloud-Org-Id:", TRACKER_CLOUD_ORG_ID)
    elif TRACKER_ORG_ID:
        headers["X-Org-Id"] = TRACKER_ORG_ID
        print("create_tracker_issue -> set X-Org-Id:", TRACKER_ORG_ID)
    else:
        msg = "No TRACKER_ORG_ID or TRACKER_CLOUD_ORG_ID configured"
        print("create_tracker_issue error:", msg)
        return False, msg, None

    try:
        r = requests.post(TRACKER_CREATE_URL, headers=headers, json=payload, auth=auth, timeout=15)
        print("POST tracker -> status:", r.status_code, "body:", (r.text or "")[:4000])
        j = r.json() if r.text else {}

        key = j.get("key") or (j.get("issue") or {}).get("key")
        if r.status_code in range(200, 300) and key:
            print("create_tracker_issue -> created:", key)
            return True, key, j
        print("create_tracker_issue -> failed, status:", r.status_code)
        return False, f"status {r.status_code}", j
    except Exception as e:
        print("create_tracker_issue exception:", e)
        return False, str(e), None


# -------------------- Формирование view (ServiceDesk) --------------------
def build_sd_view():
    return {
        "title": "Обращение в ServiceDesk",
        "submit_text": "Отправить",
        "close_text": "Отменить",
        "blocks": [
            # {
            #    "type": "header",
            #    "text": "Обращение в ServiceDesk"
            # },
            {
                "type": "plain_text",
                "text": "Выбери тему обращения, опиши проблему и прикрепи файлы в задачу."
            },
            {
                "type": "divider"
            },
            {
                "type": "radio",
                "name": "topic_internet",
                "label": "Проблемы с подключением к интернету",
                "options": [
                    {"text": "Проводное подключение", "value": "Проводное подключение"},
                    {"text": "Беспроводное подключение", "value": "Беспроводное подключение"},
                ]
            },
            {
                "type": "radio",
                "name": "topic_mango",
                "label": "Проблемы с телефонией Mango",
                "options": [
                    {"text": "Нет возможности совершать/принимать звонки",
                     "value": "Нет возможности совершать/принимать звонки"},
                    {"text": "Проблемы с качеством связи", "value": "Проблемы с качеством связи"},
                ]
            },
            {
                "type": "radio",
                "name": "topic_yandex",
                "label": "Проблемы с сервисами Яндекс",
                "options": [
                    {"text": "Трекер", "value": "Трекер"},
                    {"text": "Диск", "value": "Диск"},
                    {"text": "Почта", "value": "Почта"},
                    {"text": "Телемост", "value": "Телемост"},
                ]
            },
            {
                "type": "radio",
                "name": "topic_workplace",
                "label": "Проблемы с рабочим местом (оборудование/ПО)",
                "options": [
                    {"text": "Программное обеспечение", "value": "Программное обеспечение"},
                    {"text": "Оборудование", "value": "Оборудование"},
                ]
            },
            {
                "type": "radio",
                "name": "topic_other",
                "label": "Другая проблема",
                "options": [
                    {"text": "Другая проблема", "value": "Другая проблема"},
                ]
            },
            {
                "type": "input",
                "name": "description",
                "label": "Описание проблемы",
                "placeholder": "Опиши, что не работает, шаги воспроизведения, ожидаемый результат...",
                "multiline": True,
                "required": True,
                "min_length": 5,
                "max_length": 3000
            },
            {"type": "plain_text", "text": "Файлы (при необходимости) прикрепи в созданную задачу в Трекере."}
        ]
    }


# -------------------- Обработчики --------------------
def handle_button_webhook(request_json):
    print("handle_button_webhook ->", json.dumps(request_json, ensure_ascii=False))
    trigger_id = request_json.get("trigger_id") or request_json.get("trigger")
    message_id = request_json.get("message_id")
    user_id = request_json.get("user_id")

    try:
        if BOT_USER_ID and user_id and int(user_id) == int(BOT_USER_ID):
            print("Button pressed by bot -> ignoring")
            return {"statusCode": 200, "body": "ok"}
    except Exception:
        pass

    if trigger_id:
        print("trigger_id found -> opening SD view")
        chat_id = request_json.get("chat_id")
        private_meta = {"chat_id": chat_id}
        view_obj = build_sd_view()
        ok = open_view(trigger_id, view_obj, private_metadata=private_meta, callback_id="sd_form")
        if ok:
            print("views.open succeeded")
            return {"statusCode": 200, "body": "ok"}
        else:
            print("views.open failed; will fallback")

    # fallback
    chat_id = request_json.get("chat_id")
    if not chat_id and message_id:
        info = get_message_info(message_id)
        if isinstance(info, dict):
            chat_id = info.get("entity_id") or info.get("chat_id") or (info.get("message") or {}).get("entity_id")
            print("Resolved chat_id:", chat_id)

    if chat_id:
        send_message(chat_id, "Не удалось открыть форму автоматически - нажми кнопку ещё раз.",
                     buttons=[[{"text": "Открыть форму", "data": "open_sd_form"}]])
    else:
        print("Cannot resolve chat_id for fallback; message_id:", message_id)
    return {"statusCode": 200, "body": "ok"}


# -------------------- MAIN handler --------------------
def handler(event, context):
    print("=== WEBHOOK ===")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    raw_body = event.get("body")
    print("Raw body (truncated):", (raw_body or "")[:2000])

    # try quick parse (for issueCommentEvent fast-path)
    request_json = None
    if raw_body:
        try:
            request_json = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
        except Exception:
            request_json = None

    # immediate handle for issueCommentEvent (no signature required)
    if isinstance(request_json, dict) and request_json.get("type") == "issueCommentEvent":
        print("Detected issueCommentEvent — handling without signature check")
        return handle_issue_comment_event(request_json)

    # ---- Обработка thread-событий (обновлённая, предотвращает loop) ----
    if request_json.get("entity_type") == "thread":
        try:
            print("Thread event received ->", json.dumps(request_json, ensure_ascii=False)[:1000])
            thread_obj = request_json.get("thread") or {}
            parent_message_id = thread_obj.get("message_id") or request_json.get("parent_message_id")
            comment_text = (request_json.get("content") or "") or ""
            incoming_user_id = request_json.get("user_id")

            # -- защита от loop: если сообщение отправлено ботом — игнорируем --
            try:
                if incoming_user_id and BOT_USER_ID and str(incoming_user_id) == str(BOT_USER_ID):
                    print("Thread event from configured BOT_USER_ID -> ignoring (avoid loop)")
                    return {"statusCode": 200, "body": "ok"}
            except Exception:
                pass

            # если BOT_USER_ID не настроен или сомнения — проверим флаг 'bot' у пользователя
            try:
                if incoming_user_id:
                    uinfo = get_user_info(incoming_user_id) or {}
                    # если Pachca пометил пользователя как bot — не обрабатываем
                    if uinfo.get("bot") is True:
                        print("Thread event: sender is bot according to get_user_info -> ignoring (avoid loop)",
                              incoming_user_id)
                        return {"statusCode": 200, "body": "ok"}
            except Exception as e:
                print("get_user_info check failed (non-fatal):", e)

            # -- защита по маркеру в тексте: если в тексте уже есть наш шаблон, игнорируем --
            BOT_MARKER = "🔔 Добавлен комментарий к задаче"
            if BOT_MARKER in comment_text:
                print("Thread event: contains bot marker -> ignoring to avoid echo loop")
                return {"statusCode": 200, "body": "ok"}

            # safety: require parent_message_id (т.е. тред привязан к исходному сообщению)
            if not parent_message_id:
                print("Thread event: no parent_message_id found, skipping.")
                return {"statusCode": 200, "body": "ok"}

            # Найдем задачу по parent_message_id
            issue = find_tracker_issue_by_pachca_message_id(parent_message_id)
            if not issue:
                print("Thread event: no tracker issue linked to pachca message", parent_message_id)
                return {"statusCode": 200, "body": "ok"}

            # Подготовим текст комментария: имя автора + содержимое
            author_name = None
            try:
                if incoming_user_id:
                    ui = get_user_info(incoming_user_id) or {}
                    author_name = ((ui.get("first_name") or "") + (
                        " " + (ui.get("last_name") or "") if ui.get("last_name") else "")).strip()
                    author_name = author_name or ui.get("display_name") or ui.get(
                        "nickname") or f"user_{incoming_user_id}"
            except Exception as e:
                print("get_user_info for author failed (non-fatal):", e)
            author_name = author_name or f"user_{incoming_user_id}" if incoming_user_id else "Неизвестный"

            # очистим повторяющиеся вставки (на случай уже начавшегося цикла) — оставим только одно вхождение маркера
            # удаляем все вложенные блоки, содержащие маркер, чтобы не дублировать
            if BOT_MARKER in comment_text:
                # если попали сюда — уже отфильтрованы выше, но дополнительно безопасно сократим
                # удалим всё после первого вхождения маркера (т.к. это, скорее всего, наш echo)
                idx = comment_text.find(BOT_MARKER)
                if idx > 0:
                    comment_text = comment_text[:idx].rstrip()

            # дополнительно обрезаем текст до разумного лимита (например 4000 символов) чтобы избежать ошибок
            MAX_LEN = 4000
            comment_text_short = comment_text.strip()
            if len(comment_text_short) > MAX_LEN:
                comment_text_short = comment_text_short[:MAX_LEN] + "\n…(обрезано)"

            text_for_tracker = f"Комментарий из Пачки от {author_name} (id {incoming_user_id}):\n\n{comment_text_short}"

            # отправляем в трекер (используем вашу функцию add_tracker_comment)
            issue_id = issue.get("id") or issue.get("key")
            print("Adding comment to tracker -> issue_id:", issue_id, "text_len:", len(text_for_tracker))
            try:
                add_resp = add_tracker_comment(issue_id, text_for_tracker)
                add_users_to_tracker_access(issue_id, comment_text)
                print("add_tracker_comment -> ok:", add_resp)
            except Exception as e:
                print("add_tracker_comment failed:", e)

            # окончание обработки треда — не продолжаем обычную логику
            return {"statusCode": 200, "body": "ok"}

        except Exception as e:
            print("Exception while handling thread event:", e)
            # безопасно отдаем ok — чтобы не делать retry со стороны Pachca
            return {"statusCode": 200, "body": "ok"}

    # signature check
    provided_sig = headers.get("pachca-signature") or headers.get("pachca_signature") or headers.get("signature")
    if not provided_sig or not WEBHOOK_SECRET:
        print("Missing signature or WEBHOOK_SECRET -> 403")
        return {"statusCode": 403, "body": "Forbidden"}

    try:
        used_raw = raw_body if isinstance(raw_body, str) else json.dumps(raw_body, separators=(",", ":"),
                                                                         ensure_ascii=False)
        computed_sig = hmac.new(WEBHOOK_SECRET.encode(), msg=used_raw.encode(), digestmod=hashlib.sha256).hexdigest()
        print("Provided sig:", provided_sig, "Computed sig:", computed_sig)
        if not hmac.compare_digest(computed_sig, provided_sig):
            print("Signature mismatch -> 403")
            return {"statusCode": 403, "body": "Forbidden"}
    except Exception as e:
        print("Signature compute error:", e)
        return {"statusCode": 500, "body": "Server Error"}

    # parse again to get full structure
    try:
        request_json = json.loads(raw_body) if isinstance(raw_body, str) else raw_body
    except Exception as e:
        print("JSON parse error:", e)
        return {"statusCode": 400, "body": "Bad Request"}

    print("Parsed request:", json.dumps(request_json, ensure_ascii=False)[:2000])

    # prevent loop
    if request_json.get("entity_type") == "bot":
        print("Ignoring event: entity_type == bot")
        return {"statusCode": 200, "body": "ok"}
    try:
        if BOT_USER_ID and int(request_json.get("user_id") or 0) == BOT_USER_ID:
            print("Ignoring event: user_id == BOT_USER_ID")
            return {"statusCode": 200, "body": "ok"}
    except Exception:
        pass

    if request_json.get("type") == "issueCommentEvent":
        return handle_issue_comment_event(request_json)

    # ---- локальная функция поиска задач в Трекере (обновлённая) ----
    def _search_tracker_for_pachca_user(pachca_user_nickname, closed=False):
        """
        Возвращает список задач в очереди 29 с тегом "Создана в Пачке"
        и локальным полем "createdBy" == pachca_user_nickname.
        При closed=True — ищет по followers и access, объединяя результаты.
        """
        headers_tr = {"Content-Type": "application/json", "Accept": "application/json"}
        auth = None
        if TRACKER_API_TOKEN:
            headers_tr["Authorization"] = f"OAuth {TRACKER_API_TOKEN}"
        elif TRACKER_BASIC_USER and TRACKER_BASIC_PASS:
            auth = HTTPBasicAuth(TRACKER_BASIC_USER, TRACKER_BASIC_PASS)

        if TRACKER_CLOUD_ORG_ID:
            headers_tr["X-Cloud-Org-Id"] = TRACKER_CLOUD_ORG_ID
        elif TRACKER_ORG_ID:
            headers_tr["X-Org-Id"] = TRACKER_ORG_ID

        url_v3 = "https://api.tracker.yandex.net/v3/issues/_search"
        queue_id = "29"

        matched = []
        per_page = 100
        max_pages = 20

        def _fetch_with_filter(base_filter):
            """Вспомогательная функция для пагинации и запроса"""
            local_matched = []
            page = 1
            while page <= max_pages:
                body = {"filter": base_filter, "order": "-updated"}
                params = {"perPage": per_page, "page": page, "expand": "transitions"}

                print(
                    f"_search_tracker_for_pachca_user: requesting page {page} filter={json.dumps(base_filter, ensure_ascii=False)}")
                resp = requests.post(url_v3, headers=headers_tr, json=body, params=params, auth=auth, timeout=20)
                print("Tracker v3 -> status:", resp.status_code)

                if resp.status_code != 200:
                    print("Tracker v3 returned", resp.status_code, resp.text)
                    break

                j = resp.json()
                issues = j if isinstance(j, list) else j.get("issues") or j.get("data") or j.get("items") or []
                print(f"_search_tracker_for_pachca_user: returned {len(issues)} issues on page {page}")

                for it in issues:
                    status_obj = it.get("status") or {}
                    status_key = (status_obj.get("key") or (it.get("statusType") or {}).get("key") or "").lower()

                    if closed:
                        if status_key != "closed":
                            continue
                    else:
                        if status_key == "closed":
                            continue

                    local_matched.append(it)

                if not issues or len(issues) < per_page:
                    break
                page += 1
            return local_matched

        try:
            if closed:
                filters = [
                    {"queue": {"id": queue_id}, "followers": pachca_user_nickname},
                    {"queue": {"id": queue_id}, "access": pachca_user_nickname},
                ]
                for f in filters:
                    matched.extend(_fetch_with_filter(f))
            else:
                base_filter = {"queue": {"id": queue_id}, "createdBy": pachca_user_nickname}
                matched.extend(_fetch_with_filter(base_filter))

        except Exception as e:
            print("Exception during v3 search:", e)
            return None

        # убираем дубли по ключу задачи
        seen = set()
        unique_matched = []
        for it in matched:
            key = it.get("key")
            if key not in seen:
                seen.add(key)
                unique_matched.append(it)

        print(f"_search_tracker_for_pachca_user: matched total {len(unique_matched)} unique issues")
        return unique_matched

    # ---- кнопки (включая "Мои задачи") ----
    if request_json.get("type") == "button":
        print("Button event received")
        btn_raw = request_json.get("data") or request_json.get("payload") or (request_json.get("message") or {}).get(
            "data")
        btn_id = None
        if isinstance(btn_raw, str):
            try:
                parsed = json.loads(btn_raw)
                if isinstance(parsed, dict):
                    btn_id = parsed.get("id") or parsed.get("data") or parsed.get("action")
                else:
                    btn_id = str(parsed)
            except Exception:
                btn_id = btn_raw
        elif isinstance(btn_raw, dict):
            btn_id = btn_raw.get("id") or btn_raw.get("data") or btn_raw.get("action")
        else:
            btn_id = None

        print("Parsed button id:", btn_id, "raw:", btn_raw)

        try:
            if BOT_USER_ID and int(request_json.get("user_id") or 0) == BOT_USER_ID:
                print("Button pressed by bot -> ignoring")
                return {"statusCode": 200, "body": "ok"}
        except Exception:
            pass

        chat_id = request_json.get("chat_id") or (request_json.get("message") or {}).get(
            "entity_id") or request_json.get("chat", {}).get("id")
        user_id = request_json.get("user_id") or request_json.get("actor_id") or (request_json.get("user") or {}).get(
            "id")
        user_nickname = get_user_info(user_id).get("nickname")
        print(f"эээээ{user_id}ааааа{user_nickname}\n")
        print(request_json)
        user_info = {}
        if user_id:
            try:
                user_info = get_user_info(user_id) or {}
            except Exception as e:
                print("get_user_info failed:", e)
                user_info = {}
        user_login = user_info.get("login") or user_info.get("email") or user_info.get("nickname") or user_id or ""

        # show My Tasks menu
        if btn_id in ("my_tasks", "mytasks", "my_tasks_show"):
            buttons = [
                [{"text": "Активные задачи", "data": json.dumps({"id": "active_tasks"})}],
                [{"text": "Задачи, где я наблюдатель", "data": json.dumps({"id": "closed_tasks"})}]
            ]
            send_message(chat_id, "Выберите, какие задачи показать:", buttons=buttons)
            return {"statusCode": 200, "body": "ok"}

        # Active / Closed
        if btn_id in ("active_tasks", "closed_tasks"):
            closed = (btn_id == "closed_tasks")
            if not user_nickname:
                send_message(chat_id, "Не удалось определить никнейм пользователя в Пачке.")
                return {"statusCode": 200, "body": "ok"}

            found_issues = _search_tracker_for_pachca_user(user_nickname, closed=closed)
            if found_issues is None:
                send_message(chat_id, "Ошибка при запросе задач в Трекере.")
                return {"statusCode": 200, "body": "ok"}

            if not found_issues:
                send_message(chat_id, "Закрытых задач не найдено 📁" if closed else "Активных задач не найдено ✅")
                return {"statusCode": 200, "body": "ok"}

            # 🔽 сортировка по номеру задачи (число после SERVICEDESK-...)
            def extract_issue_num(issue):
                key = issue.get("key") or ""
                try:
                    return int(key.split("-")[1])
                except Exception:
                    return 0

            found_issues.sort(key=extract_issue_num, reverse=True)

            # 🔽 ограничиваем количество, если "Где я наблюдатель" — только последние 10
            if closed:
                found_issues = found_issues[:10]

            lines = []
            for it in found_issues:
                key = it.get("key") or str(it.get("id") or "")
                summary = it.get("summary") or ""
                status_obj = it.get("status") or {}
                status_name = status_obj.get("display") or status_obj.get("key") or ""

                assignee = it.get("assignee")
                if isinstance(assignee, dict):
                    assignee_name = assignee.get("display") or assignee.get("id") or "—"
                elif assignee:
                    assignee_name = str(assignee)
                else:
                    assignee_name = "—"

                url = f"https://tracker.yandex.ru/{key}" if key else ""
                link = f"[{key}]({url})" if key else url
                lines.append(f"{link} — {summary} ({status_name})\nИсполнитель: {assignee_name}")

            text = (
                "Задачи, где я наблюдатель (последние 10):\n\n" + "\n\n".join(lines)
                if closed else
                "Открытые задачи:\n\n" + "\n\n".join(lines)
            )
            send_message(chat_id, text)
            return {"statusCode": 200, "body": "ok"}

        # fallback to other button handler
        return handle_button_webhook(request_json)

    # view submit
    if (request_json.get("type") == "view" and request_json.get("event") == "submit") or request_json.get("type") in (
            "view_submission", "view.submit"):
        return handle_view_submission(request_json)

    # text commands -> show menu
    text = (request_json.get("content") or request_json.get("text") or "").strip()
    chat_id = request_json.get("chat_id") or (request_json.get("message") or {}).get("entity_id") or request_json.get(
        "chat", {}).get("id")

    # === Тестовые выгрузки из Трекера (для отладки) ===
    if text.lower() in ("тест", "test", "выгрузка", "tracker test"):
        try:
            headers_tr = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"OAuth {TRACKER_API_TOKEN}",
                "X-Org-Id": TRACKER_ORG_ID or TRACKER_CLOUD_ORG_ID,
            }
            url_v3 = "https://api.tracker.yandex.net/v3/issues/_search"
            per_page = 10

            # --- Используем только 4-й тест: задачи с тегом "Создана в Пачке" ---
            flt = {"queue": {"id": "29"}, "tags": ["Создана в Пачке"]}

            body = {"filter": flt, "order": "-updated"}
            params = {"perPage": per_page, "page": 1, "expand": "transitions"}
            print("\n=== TEST QUERY: Только 'Создана в Пачке' ===")
            print("Filter:", json.dumps(flt, ensure_ascii=False))

            resp = requests.post(url_v3, headers=headers_tr, json=body, params=params, timeout=15)
            print("Status:", resp.status_code)

            if resp.status_code != 200:
                print("Response:", resp.text)
                send_message(chat_id, f"Ошибка {resp.status_code} при запросе к Трекеру")
                return {"statusCode": 200, "body": "ok"}

            j = resp.json()
            if isinstance(j, list):
                issues = j
            elif isinstance(j, dict):
                issues = j.get("issues") or j.get("data") or j.get("items") or []
            else:
                issues = []

            print(f"Returned {len(issues)} issues")

            short_lines = []
            for it in issues[:per_page]:
                key = it.get("key")
                summary = it.get("summary")
                status_obj = it.get("status") or {}
                status = status_obj.get("display") or status_obj.get("key")

                created_by = it.get("createdBy")

                print(f"Issue {key}: createdBy={created_by}")

                short_lines.append(f"{key} — {summary} ({status})")

            summary_text = (
                f"Задач найдено: {len(issues)}\n\n"
                + "\n".join(short_lines)
                if short_lines else "Задачи не найдены."
            )

            send_message(chat_id, summary_text)
            return {"statusCode": 200, "body": "ok"}

        except Exception as e:
            print("Tracker test export error:", e)
            send_message(chat_id, f"Ошибка при выполнении тестового запроса: {e}")
            return {"statusCode": 200, "body": "ok"}

    if text:
        buttons = [
            [{"text": "Создать обращение в ServiceDesk", "data": json.dumps({"id": "open_sd_form"})}],
            [{"text": "Мои задачи", "data": json.dumps({"id": "my_tasks"})}]
        ]
        send_message(chat_id, "Выберите действие:", buttons=buttons)
        return {"statusCode": 200, "body": "ok"}

    print("No matched action -> ok")
    return {"statusCode": 200, "body": "ok"}
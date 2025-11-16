#!/usr/bin/env python3
import json
import threading
import time
import asyncio
import aiohttp
import requests

from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser

# --- Config AES ---
key = b"Yg&tc%DEuh6%Zc^8"
iv = b"6oyZDr22E3ychjM%"

app = Flask(__name__)

# --- Global state ---
accounts_data = {}           # dict: { uid: password }
account_index = 0
accounts_lock = threading.Lock()

tokens = {}                  # dict: { token_str: usage_count }
tokens_lock = threading.Lock()

used_uids = {}               # dict: { uid: date_obj }
uids_lock = threading.Lock()

# removed gringay approach — use tokens pool only

api_keys = {
    "ansoiu": {"exp": "30/07/2095", "remain": 999, "max_remain": 999, "last_reset": None}
}

# --- Helpers / API key check ---
def is_key_valid(key):
    if key not in api_keys:
        return None
    expiration_date = datetime.strptime(api_keys[key]["exp"], "%d/%m/%Y")
    if datetime.utcnow() > expiration_date:
        return False
    current_date = datetime.utcnow().date()
    if api_keys[key]["remain"] <= 0:
        return False
    if api_keys[key].get("last_reset") != current_date:
        api_keys[key]["remain"] = api_keys[key]["max_remain"]
        api_keys[key]["last_reset"] = current_date
    return api_keys[key]["remain"] > 0

# --- Accounts load / iterator ---
def load_accounts():
    global accounts_data
    try:
        with open('account.json', 'r', encoding='utf-8') as f:
            accounts_data = json.load(f)
        print(f"{len(accounts_data)} ACC loaded")
    except (FileNotFoundError, json.JSONDecodeError):
        accounts_data = {}
        print("No account.json or parse error - accounts_data empty")

def get_next_accounts(num=500):
    global account_index, accounts_data
    with accounts_lock:
        if not accounts_data:
            load_accounts()
        if not accounts_data:
            return []

        uids = list(accounts_data.keys())
        selected_accounts = []

        for i in range(min(num, len(uids))):
            if account_index >= len(uids):
                account_index = 0
            uid = uids[account_index]
            password = accounts_data[uid]
            selected_accounts.append((uid, password))
            account_index += 1

        return selected_accounts

# --- Protobuf helpers ---
def Encrypt(number):
    number = int(number)
    if number < 0:
        return False
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes)

def create_varint_field(field_number, value):
    field_header = (field_number << 3) | 0
    return Encrypt(field_header) + Encrypt(value)

def create_length_delimited_field(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return Encrypt(field_header) + Encrypt(len(encoded_value)) + encoded_value

def create_protobuf_packet(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = create_protobuf_packet(value)
            packet.extend(create_length_delimited_field(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(create_varint_field(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(create_length_delimited_field(field, value))
    return packet

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        if result.field not in result_dict:
            result_dict[result.field] = []
        field_data = {}
        if result.wire_type in ["varint", "string", "bytes"]:
            field_data = result.data
        elif result.wire_type == "length_delimited":
            field_data = parse_results(result.data.results)
        result_dict[result.field].append(field_data)
    return {key: value[0] if len(value) == 1 else value for key, value in result_dict.items()}

def protobuf_dec(hex_str):
    try:
        return json.dumps(parse_results(Parser().parse(hex_str)), ensure_ascii=False)
    except Exception:
        return "{}"

def encrypt_api(hex_str):
    try:
        plain_text = bytes.fromhex(hex_str)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception:
        return ""

# --- get_token: call new API and only look for "token" key ---
async def get_token(acc, session):
    """
    acc: either "uid:password" string or (uid, password) tuple/list
    session: aiohttp.ClientSession
    Trả về token (str) hoặc None.
    Chỉ tìm đúng key 'token' (đệ quy trong dict/list)
    """
    try:
        # --- tách uid/password ---
        if isinstance(acc, (list, tuple)):
            uid, password = acc[0], acc[1]
        elif isinstance(acc, str):
            if ":" in acc:
                uid, password = acc.split(":", 1)
            else:
                uid, password = acc, ""
        else:
            return None

        uid = str(uid).strip()
        password = str(password).strip()
        if not uid:
            return None

        url = f"http://103.139.155.35:5000/api/guest_login?uid={uid}&password={password}"
        async with session.get(url) as response:
            text = await response.text()

            # Debug prints (kept minimal in production)
            print(f"[get_token] UID: {uid} STATUS: {response.status}")

            if response.status not in (200, 201):
                return None

            # parse JSON
            try:
                data = json.loads(text)
            except Exception:
                return None

            # --- đệ quy tìm key 'token' trong dict/list ---
            def find_token_only(obj):
                if isinstance(obj, dict):
                    # check direct key first
                    if "token" in obj and isinstance(obj["token"], str) and obj["token"]:
                        return obj["token"]
                    # else recurse
                    for v in obj.values():
                        found = find_token_only(v)
                        if found:
                            return found
                    return None
                elif isinstance(obj, list):
                    for item in obj:
                        found = find_token_only(item)
                        if found:
                            return found
                    return None
                else:
                    return None

            return find_token_only(data)

    except Exception:
        return None

# --- token management tasks ---
async def refresh_tokens():
    global tokens
    try:
        accounts = get_next_accounts(115)
        if accounts:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                tasks = [get_token(f"{uid}:{password}", session) for uid, password in accounts]
                new_tokens = await asyncio.gather(*tasks)
                valid_tokens = [token for token in new_tokens if isinstance(token, str) and token]
                with tokens_lock:
                    tokens = {token: 0 for token in valid_tokens}
    except Exception as e:
        print(f"[refresh_tokens] Exception: {e}")
        with tokens_lock:
            tokens = {}
    # schedule next run
    threading.Timer(12345, lambda: asyncio.run(refresh_tokens())).start()

async def clean_and_replace_tokens():
    global tokens
    tokens_to_remove = []
    with tokens_lock:
        tokens_to_remove = [token for token, count in tokens.items() if count >= 27]
    if not tokens_to_remove:
        return
    accounts = get_next_accounts(len(tokens_to_remove) + 5)
    if accounts:
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                tasks = [get_token(f"{uid}:{password}", session) for uid, password in accounts]
                new_tokens = await asyncio.gather(*tasks, return_exceptions=True)
                valid_new_tokens = [token for token in new_tokens if isinstance(token, str) and token]

                with tokens_lock:
                    for old_token in tokens_to_remove:
                        if old_token in tokens:
                            del tokens[old_token]
                    for new_token in valid_new_tokens:
                        tokens[new_token] = 0
        except Exception as e:
            print(f"[clean_and_replace_tokens] Exception: {e}")
            with tokens_lock:
                for old_token in tokens_to_remove:
                    if old_token in tokens:
                        del tokens[old_token]

async def generate_additional_tokens(needed_tokens):
    try:
        accounts = get_next_accounts(needed_tokens + 10)
        if not accounts:
            return []
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [get_token(f"{uid}:{password}", session) for uid, password in accounts]
            new_tokens = await asyncio.gather(*tasks, return_exceptions=True)
            valid_tokens = [token for token in new_tokens if isinstance(token, str) and token]
            with tokens_lock:
                for token in valid_tokens:
                    tokens[token] = 0
            return valid_tokens
    except Exception as e:
        print(f"[generate_additional_tokens] Exception: {e}")
        return []

# --- API calls to target service ---
async def LikesProfile(payload, session, token):
    try:
        url = "https://clientbp.ggwhitehawk.com/LikeProfile"
        headers = {
            "ReleaseVersion": "OB51",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {token}",
            "Host": "clientbp.ggwhitehawk.com"
        }
        async with session.post(url, headers=headers, data=payload, timeout=10) as res:
            return res.status == 200
    except Exception:
        return False

async def GetPlayerPersonalShow(payload, session):
    try:
        url = "https://clientbp.ggwhitehawk.com/GetPlayerPersonalShow"
        with tokens_lock:
            any_token = next(iter(tokens.keys()), None)
        if not any_token:
            print("[GetPlayerPersonalShow] No available token")
            return None
        headers = {
            "ReleaseVersion": "OB51",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {any_token}",
            "Host": "clientbp.ggwhitehawk.com"
        }
        async with session.post(url, headers=headers, data=payload) as res:
            if res.status == 200:
                r = await res.read()
                return json.loads(protobuf_dec(r.hex()))
            return None
    except Exception:
        return None

def add_token_usage(_tokens):
    with tokens_lock:
        for token in _tokens:
            if token in tokens:
                tokens[token] += 1

# --- Core sendLikes logic ---
async def sendLikes(uid):
    global used_uids, tokens
    today = datetime.now().date()
    with uids_lock:
        if uid in used_uids and used_uids[uid] == today:
            return {"Failed": "Maximum like received"}, 200

    with tokens_lock:
        available_tokens = {k: v for k, v in tokens.items() if v < 27}
        token_list = list(available_tokens.keys())

    if len(token_list) < 115:
        needed_tokens = 115 - len(token_list)
        new_tokens = await generate_additional_tokens(needed_tokens)
        with tokens_lock:
            available_tokens = {k: v for k, v in tokens.items() if v < 27}
            token_list = list(available_tokens.keys())

        if len(token_list) < 1:
            return {"message": "{}".format(len(token_list))}, 200

    _tokens = token_list[:115]
    packet = create_protobuf_packet({1: int(uid), 2: 1}).hex()
    encrypted_packet = encrypt_api(packet)
    if not encrypted_packet:
        return "null", 201
    payload = bytes.fromhex(encrypted_packet)

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        InfoBefore = await GetPlayerPersonalShow(payload, session)
        if not InfoBefore or "1" not in InfoBefore or "21" not in InfoBefore["1"]:
            return {"Failse": "Account does not exist"}, 200

        LikesBefore = int(InfoBefore["1"]["21"])
        start_time = time.time()

        # create tasks using the selected tokens _tokens
        tasks = [LikesProfile(payload, session, token) for token in _tokens]
        await asyncio.gather(*tasks, return_exceptions=True)

        with uids_lock:
            used_uids[uid] = today

        InfoAfter = await GetPlayerPersonalShow(payload, session)
        if not InfoAfter or "1" not in InfoAfter or "21" not in InfoAfter["1"]:
            return "null", 201

        LikesAfter = int(InfoAfter["1"]["21"])
        LikesAdded = LikesAfter - LikesBefore

        add_token_usage(_tokens)
        asyncio.create_task(clean_and_replace_tokens())

        if LikesAdded <= 0:
            return {"Failse": "Account Id '{}' with name '{}' has reached max likes today, try again tomorrow !".format(InfoBefore["1"]["1"], InfoBefore["1"]["3"])}, 200

        end_time = time.time()
        return {
            "result": {
                "User Info": {
                    "Account UID": InfoBefore["1"]["1"],
                    "Account Name": InfoBefore["1"]["3"],
                    "Account Region": InfoBefore["1"]["5"],
                    "Account Level": InfoBefore["1"]["6"],
                    "Account Likes": InfoBefore["1"]["21"]
                },
                "Likes Info": {
                    "Likes Before": LikesBefore,
                    "Likes After": LikesBefore + LikesAdded,
                    "Likes Added": LikesAdded,
                    "Likes start of day": max(0, LikesBefore + LikesAdded - 100),
                },
                "API": {
                    "speeds": "{:.1f}s".format(end_time - start_time),
                    "Success": True,
                }
            }
        }, 200

# --- Reset logic ---
def reset_uids():
    global used_uids, account_index
    with uids_lock:
        used_uids = {}
        account_index = 0

def schedule_reset():
    now = datetime.now(timezone.utc)
    next_reset = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc) + timedelta(days=1)
    delta_seconds = (next_reset - now).total_seconds()
    threading.Timer(delta_seconds, lambda: [reset_uids(), schedule_reset()]).start()

# --- Flask route ---
@app.route("/likes", methods=["GET"])
def FF_LIKES():
    uid = request.args.get("uid")
    key = request.args.get("keys")
    if is_key_valid(key) is None:
        return jsonify({"message": "key not found, To buy key contact tg @boaraoffical"}), 200
    if not uid:
        return 'UID missing!'
    try:
        uid = str(uid).strip()
    except:
        return '?'
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(sendLikes(uid))
        loop.close()
        return jsonify(result[0]), result[1]
    except Exception as e:
        print(f"[FF_LIKES] Exception: {e}")
        return jsonify({"error": str(e)}), 500

# --- Main ---
if __name__ == "__main__":
    load_accounts()

    def background_tasks():
        # start token refreshers in background threads/tasks
        try:
            asyncio.run(refresh_tokens())
        except Exception as e:
            print(f"[background_tasks] refresh_tokens exception: {e}")
        # no gringay refresh here

    threading.Thread(target=background_tasks, daemon=True).start()
    schedule_reset()
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), threaded=True)#  API KEY CHECK
# ------------------------------------------------------------
def is_key_valid(key):
    if key not in api_keys:
        return None
    expiration_date = datetime.strptime(api_keys[key]["exp"], "%d/%m/%Y")
    if datetime.utcnow() > expiration_date:
        return False
    current_date = datetime.utcnow().date()
    if api_keys[key]["remain"] <= 0:
        return False
    if api_keys[key].get("last_reset") != current_date:
        api_keys[key]["remain"] = api_keys[key]["max_remain"]
        api_keys[key]["last_reset"] = current_date
    return api_keys[key]["remain"] > 0

# ------------------------------------------------------------
#  LOAD ACCOUNTS
# ------------------------------------------------------------
def load_accounts():
    global accounts_data
    try:
        with open('account.json', 'r') as f:
            accounts_data = json.load(f)
        print(f"{len(accounts_data)} ACC loaded")
    except:
        accounts_data = {}
        print("accounts_data empty")

def get_next_accounts(num=500):
    global account_index
    with accounts_lock:
        if not accounts_data:
            load_accounts()
        if not accounts_data:
            return []

        uids = list(accounts_data.keys())
        selected = []

        for _ in range(min(num, len(uids))):
            if account_index >= len(uids):
                account_index = 0
            uid = uids[account_index]
            selected.append((uid, accounts_data[uid]))
            account_index += 1

        return selected

# ------------------------------------------------------------
#  PROTOBUF HELPERS
# ------------------------------------------------------------
def Encrypt(number):
    number = int(number)
    encoded = []
    while True:
        b = number & 0x7F
        number >>= 7
        if number:
            b |= 0x80
        encoded.append(b)
        if not number:
            break
    return bytes(encoded)

def create_varint_field(field_number, value):
    header = (field_number << 3) | 0
    return Encrypt(header) + Encrypt(value)

def create_length_delimited_field(field_number, value):
    header = (field_number << 3) | 2
    v = value.encode() if isinstance(value, str) else value
    return Encrypt(header) + Encrypt(len(v)) + v

def create_protobuf_packet(fields):
    pkt = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = create_protobuf_packet(value)
            pkt.extend(create_length_delimited_field(field, nested))
        elif isinstance(value, int):
            pkt.extend(create_varint_field(field, value))
        else:
            pkt.extend(create_length_delimited_field(field, value))
    return pkt

def parse_results(results):
    out = {}
    for r in results:
        if r.field not in out:
            out[r.field] = []
        if r.wire_type == "length_delimited":
            out[r.field].append(parse_results(r.data.results))
        else:
            out[r.field].append(r.data)
    return {k: v[0] if len(v)==1 else v for k,v in out.items()}

def protobuf_dec(hex_str):
    try:
        return json.dumps(parse_results(Parser().parse(hex_str)), ensure_ascii=False)
    except:
        return "{}"

def encrypt_api(hex_str):
    try:
        plain = bytes.fromhex(hex_str)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(plain, AES.block_size)).hex()
    except:
        return ""

# ------------------------------------------------------------
#  GET TOKEN
# ------------------------------------------------------------
async def get_token(acc, session):
    try:
        if isinstance(acc, (list,tuple)):
            uid, password = acc
        else:
            uid, password = acc.split(":",1)

        url = f"http://103.139.155.35:5000/api/guest_login?uid={uid}&password={password}"
        async with session.get(url) as res:
            txt = await res.text()
            if res.status not in (200,201):
                return None
            try:
                data = json.loads(txt)
            except:
                return None

            def find_token(o):
                if isinstance(o, dict):
                    if "token" in o and isinstance(o["token"], str):
                        return o["token"]
                    for v in o.values():
                        r = find_token(v)
                        if r: return r
                if isinstance(o, list):
                    for x in o:
                        r = find_token(x)
                        if r: return r
                return None

            return find_token(data)

    except:
        return None

# ------------------------------------------------------------
#  TOKEN REFRESH THREAD
# ------------------------------------------------------------
async def refresh_tokens():
    global tokens
    try:
        accs = get_next_accounts(115)
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            tasks = [get_token(f"{uid}:{pw}", s) for uid,pw in accs]
            new = await asyncio.gather(*tasks)
            valid = [t for t in new if t]
            with tokens_lock:
                tokens = {t:0 for t in valid}
    except:
        tokens = {}

    threading.Timer(12345, lambda: asyncio.run(refresh_tokens())).start()

async def clean_and_replace_tokens():
    with tokens_lock:
        expired = [t for t,c in tokens.items() if c>=27]

    if not expired:
        return

    accs = get_next_accounts(len(expired)+5)
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        tasks = [get_token(f"{uid}:{pw}", s) for uid,pw in accs]
        new = await asyncio.gather(*tasks)
        valid = [t for t in new if t]

        with tokens_lock:
            for t in expired:
                tokens.pop(t, None)
            for t in valid:
                tokens[t] = 0

async def generate_additional_tokens(n):
    accs = get_next_accounts(n+10)
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        tasks = [get_token(f"{uid}:{pw}", s) for uid,pw in accs]
        new = await asyncio.gather(*tasks)
        valid = [t for t in new if t]
        with tokens_lock:
            for t in valid:
                tokens[t]=0
    return valid

# ------------------------------------------------------------
#  PERSONAL SHOW
# ------------------------------------------------------------
async def GetPlayerPersonalShow(payload, session):
    try:
        with tokens_lock:
            any_token = next(iter(tokens.keys()), None)

        if not any_token:
            return None

        url = "https://clientbp.ggwhitehawk.com/GetPlayerPersonalShow"
        headers = {
            "ReleaseVersion": "OB51",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {any_token}",
            "Host": "clientbp.ggwhitehawk.com"
        }

        async with session.post(url, headers=headers, data=payload) as res:
            if res.status == 200:
                raw = await res.read()
                return json.loads(protobuf_dec(raw.hex()))
            return None

    except:
        return None

# ------------------------------------------------------------
#  LIKE PROFILE
# ------------------------------------------------------------
async def LikesProfile(payload, session, token):
    try:
        url = "https://clientbp.ggwhitehawk.com/LikeProfile"
        headers = {
            "ReleaseVersion": "OB51",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {token}",
            "Host": "clientbp.ggwhitehawk.com"
        }
        async with session.post(url, headers=headers, data=payload, timeout=10) as res:
            return res.status == 200
    except:
        return False

def add_token_usage(_tokens):
    with tokens_lock:
        for t in _tokens:
            if t in tokens:
                tokens[t] += 1

# ------------------------------------------------------------
#  MAIN LIKE LOGIC
# ------------------------------------------------------------
async def sendLikes(uid):
    today = datetime.now().date()
    with uids_lock:
        if uid in used_uids and used_uids[uid] == today:
            return {"Failed": "Maximum like received"}, 200

    with tokens_lock:
        available = [t for t, c in tokens.items() if c < 27]

    if len(available) < 115:
        need = 115 - len(available)
        await generate_additional_tokens(need)
        with tokens_lock:
            available = [t for t, c in tokens.items() if c < 27]
        if len(available) < 1:
            return {"message": str(len(available))}, 200

    use_tokens = available[:115]

    pkt = create_protobuf_packet({1: int(uid), 2: 1}).hex()
    encrypted = encrypt_api(pkt)
    if not encrypted:
        return "null", 201
    payload = bytes.fromhex(encrypted)

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        info1 = await GetPlayerPersonalShow(payload, s)
        if not info1 or "1" not in info1 or "21" not in info1["1"]:
            return {"Failse": "Account does not exist"}, 200

        before = int(info1["1"]["21"])
        t0 = time.time()

        tasks = [LikesProfile(payload, s, tk) for tk in use_tokens]
        await asyncio.gather(*tasks)

        with uids_lock:
            used_uids[uid] = today

        info2 = await GetPlayerPersonalShow(payload, s)
        if not info2:
            return "null", 201

        after = int(info2["1"]["21"])
        added = after - before

        add_token_usage(use_tokens)
        asyncio.create_task(clean_and_replace_tokens())

        if added <= 0:
            return {
                "Failse": f"Account Id '{info1['1']['1']}' with name '{info1['1']['3']}' has reached max likes today"
            }, 200

        t1 = time.time()
        return {
            "result": {
                "User Info": {
                    "Account UID": info1["1"]["1"],
                    "Account Name": info1["1"]["3"],
                    "Account Region": info1["1"]["5"],
                    "Account Level": info1["1"]["6"],
                    "Account Likes": info1["1"]["21"]
                },
                "Likes Info": {
                    "Likes Before": before,
                    "Likes After": before + added,
                    "Likes Added": added
                },
                "API": {
                    "speeds": f"{t1 - t0:.1f}s",
                    "Success": True
                }
            }
        }, 200

# ------------------------------------------------------------
#  RESET DAILY
# ------------------------------------------------------------
def reset_uids():
    global used_uids, account_index
    with uids_lock:
        used_uids = {}
        account_index = 0

def schedule_reset():
    now = datetime.now(timezone.utc)
    nxt = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc) + timedelta(days=1)
    dt = (nxt - now).total_seconds()
    threading.Timer(dt, lambda: [reset_uids(), schedule_reset()]).start()

# ------------------------------------------------------------
#  API ROUTE
# ------------------------------------------------------------
@app.route("/likes", methods=["GET"])
def FF_LIKES():
    uid = request.args.get("uid")
    key = request.args.get("keys")

    if is_key_valid(key) is None:
        return jsonify({"message": "key not found"}), 200

    if not uid:
        return "UID missing!"

    uid = str(uid).strip()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    output = loop.run_until_complete(sendLikes(uid))
    loop.close()
    return jsonify(output[0]), output[1]

# ------------------------------------------------------------
#  MAIN START
# ------------------------------------------------------------
if __name__ == "__main__":
    load_accounts()

    def bg():
        asyncio.run(refresh_tokens())

    threading.Thread(target=bg, daemon=True).start()
    schedule_reset()

    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), threaded=True)#  API KEY CHECK
# ------------------------------------------------------------
def is_key_valid(key):
    if key not in api_keys:
        return None
    expiration_date = datetime.strptime(api_keys[key]["exp"], "%d/%m/%Y")
    if datetime.utcnow() > expiration_date:
        return False
    current_date = datetime.utcnow().date()
    if api_keys[key]["remain"] <= 0:
        return False
    if api_keys[key].get("last_reset") != current_date:
        api_keys[key]["remain"] = api_keys[key]["max_remain"]
        api_keys[key]["last_reset"] = current_date
    return api_keys[key]["remain"] > 0

# ------------------------------------------------------------
#  LOAD ACCOUNTS
# ------------------------------------------------------------
def load_accounts():
    global accounts_data
    try:
        with open('account.json', 'r') as f:
            accounts_data = json.load(f)
        print(f"{len(accounts_data)} ACC loaded")
    except:
        accounts_data = {}
        print("accounts_data empty")

def get_next_accounts(num=500):
    global account_index
    with accounts_lock:
        if not accounts_data:
            load_accounts()
        if not accounts_data:
            return []

        uids = list(accounts_data.keys())
        selected = []

        for _ in range(min(num, len(uids))):
            if account_index >= len(uids):
                account_index = 0
            uid = uids[account_index]
            selected.append((uid, accounts_data[uid]))
            account_index += 1

        return selected

# ------------------------------------------------------------
#  PROTOBUF HELPERS
# ------------------------------------------------------------
def Encrypt(number):
    number = int(number)
    encoded = []
    while True:
        b = number & 0x7F
        number >>= 7
        if number:
            b |= 0x80
        encoded.append(b)
        if not number:
            break
    return bytes(encoded)

def create_varint_field(field_number, value):
    header = (field_number << 3) | 0
    return Encrypt(header) + Encrypt(value)

def create_length_delimited_field(field_number, value):
    header = (field_number << 3) | 2
    v = value.encode() if isinstance(value, str) else value
    return Encrypt(header) + Encrypt(len(v)) + v

def create_protobuf_packet(fields):
    pkt = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = create_protobuf_packet(value)
            pkt.extend(create_length_delimited_field(field, nested))
        elif isinstance(value, int):
            pkt.extend(create_varint_field(field, value))
        else:
            pkt.extend(create_length_delimited_field(field, value))
    return pkt

def parse_results(results):
    out = {}
    for r in results:
        if r.field not in out:
            out[r.field] = []
        if r.wire_type == "length_delimited":
            out[r.field].append(parse_results(r.data.results))
        else:
            out[r.field].append(r.data)
    return {k: v[0] if len(v)==1 else v for k,v in out.items()}

def protobuf_dec(hex_str):
    try:
        return json.dumps(parse_results(Parser().parse(hex_str)), ensure_ascii=False)
    except:
        return "{}"

def encrypt_api(hex_str):
    try:
        plain = bytes.fromhex(hex_str)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(plain, AES.block_size)).hex()
    except:
        return ""
        # ------------------------------------------------------------
#  GET TOKEN
# ------------------------------------------------------------
async def get_token(acc, session):
    try:
        if isinstance(acc, (list,tuple)):
            uid, password = acc
        else:
            uid, password = acc.split(":",1)

        url = f"http://103.139.155.35:5000/api/guest_login?uid={uid}&password={password}"
        async with session.get(url) as res:
            txt = await res.text()
            if res.status not in (200,201):
                return None
            try:
                data = json.loads(txt)
            except:
                return None

            def find_token(o):
                if isinstance(o, dict):
                    if "token" in o and isinstance(o["token"], str):
                        return o["token"]
                    for v in o.values():
                        r = find_token(v)
                        if r: return r
                if isinstance(o, list):
                    for x in o:
                        r = find_token(x)
                        if r: return r
                return None

            return find_token(data)

    except:
        return None

# ------------------------------------------------------------
#  TOKEN REFRESH THREAD
# ------------------------------------------------------------
async def refresh_tokens():
    global tokens
    try:
        accs = get_next_accounts(115)
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            tasks = [get_token(f"{uid}:{pw}", s) for uid,pw in accs]
            new = await asyncio.gather(*tasks)
            valid = [t for t in new if t]
            with tokens_lock:
                tokens = {t:0 for t in valid}
    except:
        tokens = {}

    threading.Timer(12345, lambda: asyncio.run(refresh_tokens())).start()

async def clean_and_replace_tokens():
    with tokens_lock:
        expired = [t for t,c in tokens.items() if c>=27]

    if not expired:
        return

    accs = get_next_accounts(len(expired)+5)
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        tasks = [get_token(f"{uid}:{pw}", s) for uid,pw in accs]
        new = await asyncio.gather(*tasks)
        valid = [t for t in new if t]

        with tokens_lock:
            for t in expired:
                tokens.pop(t, None)
            for t in valid:
                tokens[t] = 0

async def generate_additional_tokens(n):
    accs = get_next_accounts(n+10)
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        tasks = [get_token(f"{uid}:{pw}", s) for uid,pw in accs]
        new = await asyncio.gather(*tasks)
        valid = [t for t in new if t]
        with tokens_lock:
            for t in valid:
                tokens[t]=0
    return valid

# ------------------------------------------------------------
#  FIX A — PERSONAL SHOW DÙNG TOKEN THƯỜNG
# ------------------------------------------------------------
async def GetPlayerPersonalShow(payload, session):
    try:
        with tokens_lock:
            any_token = next(iter(tokens.keys()), None)

        if not any_token:
            print("[PS] no token available")
            return None

        url = "https://clientbp.ggwhitehawk.com/GetPlayerPersonalShow"
        headers = {
            "ReleaseVersion": "OB51",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {any_token}",
            "Host": "clientbp.ggwhitehawk.com"
        }

        async with session.post(url, headers=headers, data=payload) as res:
            if res.status == 200:
                raw = await res.read()
                return json.loads(protobuf_dec(raw.hex()))
            return None

    except Exception as e:
        print("[PS] Exception:", e)
        return None

# ------------------------------------------------------------
#  LIKE PROFILE
# ------------------------------------------------------------
async def LikesProfile(payload, session, token):
    try:
        url = "https://clientbp.ggwhitehawk.com/LikeProfile"
        headers = {
            "ReleaseVersion": "OB51",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {token}",
            "Host": "clientbp.ggwhitehawk.com"
        }
        async with session.post(url, headers=headers, data=payload, timeout=10) as res:
            return res.status == 200
    except:
        return False
        def add_token_usage(_tokens):
    with tokens_lock:
        for t in _tokens:
            if t in tokens:
                tokens[t] += 1

# ------------------------------------------------------------
#  MAIN LIKE LOGIC
# ------------------------------------------------------------
async def sendLikes(uid):
    today = datetime.now().date()
    with uids_lock:
        if uid in used_uids and used_uids[uid] == today:
            return {"Failed": "Maximum like received"}, 200

    with tokens_lock:
        available = [t for t, c in tokens.items() if c < 27]

    if len(available) < 115:
        need = 115 - len(available)
        await generate_additional_tokens(need)
        with tokens_lock:
            available = [t for t, c in tokens.items() if c < 27]
        if len(available) < 1:
            return {"message": str(len(available))}, 200

    use_tokens = available[:115]

    pkt = create_protobuf_packet({1: int(uid), 2: 1}).hex()
    encrypted = encrypt_api(pkt)
    if not encrypted:
        return "null", 201
    payload = bytes.fromhex(encrypted)

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        info1 = await GetPlayerPersonalShow(payload, s)
        if not info1 or "1" not in info1 or "21" not in info1["1"]:
            return {"Failse": "Account does not exist"}, 200

        before = int(info1["1"]["21"])
        t0 = time.time()

        tasks = [LikesProfile(payload, s, tk) for tk in use_tokens]
        await asyncio.gather(*tasks)

        with uids_lock:
            used_uids[uid] = today

        info2 = await GetPlayerPersonalShow(payload, s)
        if not info2:
            return "null", 201

        after = int(info2["1"]["21"])
        added = after - before

        add_token_usage(use_tokens)
        asyncio.create_task(clean_and_replace_tokens())

        if added <= 0:
            return {
                "Failse": f"Account Id '{info1['1']['1']}' with name '{info1['1']['3']}' has reached max likes today"
            }, 200

        t1 = time.time()
        return {
            "result": {
                "User Info": {
                    "Account UID": info1["1"]["1"],
                    "Account Name": info1["1"]["3"],
                    "Account Region": info1["1"]["5"],
                    "Account Level": info1["1"]["6"],
                    "Account Likes": info1["1"]["21"]
                },
                "Likes Info": {
                    "Likes Before": before,
                    "Likes After": before + added,
                    "Likes Added": added
                },
                "API": {
                    "speeds": f"{t1 - t0:.1f}s",
                    "Success": True
                }
            }
        }, 200
        # ------------------------------------------------------------
#  RESET DAILY
# ------------------------------------------------------------
def reset_uids():
    global used_uids, account_index
    with uids_lock:
        used_uids = {}
        account_index = 0

def schedule_reset():
    now = datetime.now(timezone.utc)
    nxt = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc) + timedelta(days=1)
    dt = (nxt - now).total_seconds()
    threading.Timer(dt, lambda: [reset_uids(), schedule_reset()]).start()

# ------------------------------------------------------------
#  API ROUTE
# ------------------------------------------------------------
@app.route("/likes", methods=["GET"])
def FF_LIKES():
    uid = request.args.get("uid")
    key = request.args.get("keys")

    if is_key_valid(key) is None:
        return jsonify({"message": "key not found"}), 200

    if not uid:
        return "UID missing!"

    uid = str(uid).strip()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    output = loop.run_until_complete(sendLikes(uid))
    loop.close()
    return jsonify(output[0]), output[1]

# ------------------------------------------------------------
#  MAIN START (CHẠY LOCAL; RENDER SẼ DÙNG GUNICORN)
# ------------------------------------------------------------
if __name__ == "__main__":
    load_accounts()

    def bg():
        asyncio.run(refresh_tokens())

    threading.Thread(target=bg, daemon=True).start()
    schedule_reset()

    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), threaded=True)

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

api_keys = {
    "anmetmoi": {
        "exp": "18/11/2025",
        "remain": 70,
        "max_remain": 10,
        "last_reset": None
    }
}

# --- API key check ---
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

# --- Load Accounts ---
def load_accounts():
    global accounts_data
    try:
        with open('account.json', 'r', encoding='utf-8') as f:
            accounts_data = json.load(f)
        print(f"{len(accounts_data)} ACC loaded")
    except:
        accounts_data = {}
        print("Failed to load accounts")

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
            pwd = accounts_data[uid]
            selected.append((uid, pwd))
            account_index += 1

        return selected

# --- Protobuf helpers ---
def Encrypt(number):
    number = int(number)
    encoded = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded.append(byte)
        if not number:
            break
    return bytes(encoded)

def create_varint_field(field_number, value):
    header = (field_number << 3) | 0
    return Encrypt(header) + Encrypt(value)

def create_length_delimited_field(field_number, value):
    header = (field_number << 3) | 2
    encoded = value.encode() if isinstance(value, str) else value
    return Encrypt(header) + Encrypt(len(encoded)) + encoded

def create_protobuf_packet(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = create_protobuf_packet(value)
            packet.extend(create_length_delimited_field(field, nested))
        elif isinstance(value, int):
            packet.extend(create_varint_field(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(create_length_delimited_field(field, value))
    return packet

def parse_results(parsed_results):
    result = {}
    for r in parsed_results:
        if r.field not in result:
            result[r.field] = []
        if r.wire_type in ["varint", "string", "bytes"]:
            result[r.field].append(r.data)
        elif r.wire_type == "length_delimited":
            result[r.field].append(parse_results(r.data.results))
    return {k: v[0] if len(v) == 1 else v for k, v in result.items()}

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
# --- get_token: call new API and only look for "token" key ---
async def get_token(acc, session):
    try:
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

        url = f"https://api-jwt-steel.vercel.app/get?uid={uid}&password={password}"
        async with session.get(url) as response:
            txt = await response.text()

            print(f"[get_token] UID={uid} STATUS={response.status}")

            if response.status not in (200, 201):
                return None

            try:
                data = json.loads(txt)
            except:
                return None

            def find_token(obj):
                if isinstance(obj, dict):
                    if "token" in obj and isinstance(obj["token"], str) and obj["token"]:
                        return obj["token"]
                    for v in obj.values():
                        found = find_token(v)
                        if found:
                            return found
                elif isinstance(obj, list):
                    for item in obj:
                        found = find_token(item)
                        if found:
                            return found
                return None

            return find_token(data)

    except Exception:
        return None

# --- token refresh ---
async def refresh_tokens():
    global tokens
    try:
        accounts = get_next_accounts(115)
        if accounts:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                tasks = [
                    get_token(f"{uid}:{pwd}", session)
                    for uid, pwd in accounts
                ]
                results = await asyncio.gather(*tasks)
                valid = [t for t in results if isinstance(t, str) and t]

                with tokens_lock:
                    tokens = {t: 0 for t in valid}

    except Exception as e:
        print(f"[refresh_tokens] ERROR: {e}")
        with tokens_lock:
            tokens = {}

    threading.Timer(12345, lambda: asyncio.run(refresh_tokens())).start()

# --- clean tokens ---
async def clean_and_replace_tokens():
    global tokens
    with tokens_lock:
        expired = [t for t, c in tokens.items() if c >= 27]

    if not expired:
        return

    accounts = get_next_accounts(len(expired) + 5)
    if not accounts:
        return

    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [
                get_token(f"{uid}:{pwd}", session)
                for uid, pwd in accounts
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            valid = [t for t in results if isinstance(t, str) and t]

            with tokens_lock:
                for old in expired:
                    tokens.pop(old, None)
                for new_tk in valid:
                    tokens[new_tk] = 0

    except Exception as e:
        print(f"[clean_and_replace_tokens] ERROR: {e}")
        with tokens_lock:
            for old in expired:
                tokens.pop(old, None)

# --- more tokens if needed ---
async def generate_additional_tokens(need):
    try:
        accounts = get_next_accounts(need + 10)
        if not accounts:
            return []

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [
                get_token(f"{uid}:{pwd}", session)
                for uid, pwd in accounts
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            valid = [t for t in results if isinstance(t, str) and t]

            with tokens_lock:
                for tk in valid:
                    tokens[tk] = 0

            return valid

    except Exception:
        return []
# --- Target API actions ---
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
            tk = next(iter(tokens.keys()), None)

        if not tk:
            print("[GetPlayerPersonalShow] NO TOKEN")
            return None

        headers = {
            "ReleaseVersion": "OB51",
            "X-GA": "v1 1",
            "Authorization": f"Bearer {tk}",
            "Host": "clientbp.ggwhitehawk.com"
        }

        async with session.post(url, headers=headers, data=payload) as res:
            if res.status != 200:
                return None

            r = await res.read()
            return json.loads(protobuf_dec(r.hex()))

    except Exception:
        return None

def add_token_usage(token_list):
    with tokens_lock:
        for tk in token_list:
            if tk in tokens:
                tokens[tk] += 1

# --- MAIN LIKE HANDLER ---
async def sendLikes(uid):
    global used_uids

    today = datetime.now().date()

    # 1) check UID already liked today
    with uids_lock:
        if uid in used_uids and used_uids[uid] == today:
            return {"Failed": "Maximum like received"}, 200

    # 2) filter valid tokens
    with tokens_lock:
        valid_tokens = [tk for tk, count in tokens.items() if count < 15]

    if len(valid_tokens) < 115:
        need = 115 - len(valid_tokens)
        await generate_additional_tokens(need)

        with tokens_lock:
            valid_tokens = [tk for tk, count in tokens.items() if count < 27]

        if len(valid_tokens) < 1:
            return {"message": f"{len(valid_tokens)}"}, 200

    # choose 115 tokens
    use_tokens = valid_tokens[:115]

    # protobuf
    packet = create_protobuf_packet({1: int(uid), 2: 1}).hex()
    encrypted = encrypt_api(packet)
    if not encrypted:
        return "null", 201

    payload = bytes.fromhex(encrypted)

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:

        # GET BEFORE
        info1 = await GetPlayerPersonalShow(payload, session)
        if not info1 or "1" not in info1 or "21" not in info1["1"]:
            return {"Failse": "Account does not exist"}, 200

        before = int(info1["1"]["21"])
        t0 = time.time()

        # LIKE
        tasks = [
            LikesProfile(payload, session, tk)
            for tk in use_tokens
        ]
        await asyncio.gather(*tasks)

        # DONE → mark UID used
        with uids_lock:
            used_uids[uid] = today

        # GET AFTER
        info2 = await GetPlayerPersonalShow(payload, session)
        if not info2 or "1" not in info2 or "21" not in info2["1"]:
            return "null", 201

        after = int(info2["1"]["21"])
        added = after - before

        # token count
        add_token_usage(use_tokens)
        asyncio.create_task(clean_and_replace_tokens())

        if added <= 0:
            return {
                "Failse": f"Account Id '{info1['1']['1']}' with name '{info1['1']['3']}' reached max likes today"
            }, 200

        t1 = time.time()

        return {
            "result": {
                "User Info": {
                    "Account UID": info1["1"]["1"],
                    "Account Name": info1["1"]["3"],
                    "Account Region": info1["1"]["5"],
                    "Account Level": info1["1"]["6"],
                    "Account Likes": info1["1"]["21"],
                },
                "Likes Info": {
                    "Likes Before": before,
                    "Likes After": before + added,
                    "Likes Added": added,
                },
                "API": {
                    "speed": f"{t1 - t0:.1f}s",
                    "Success": True
                }
            }
        }, 200
# --- Daily reset ---
def reset_uids():
    global used_uids, account_index
    with uids_lock:
        used_uids = {}
        account_index = 0

def schedule_reset():
    now = datetime.now(timezone.utc)
    tomorrow = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc) + timedelta(days=1)
    wait_seconds = (tomorrow - now).total_seconds()
    threading.Timer(wait_seconds, lambda: [reset_uids(), schedule_reset()]).start()

# --- Flask API ---
@app.route("/likes", methods=["GET"])
def FF_LIKES():
    uid = request.args.get("uid")
    key = request.args.get("keys")

    if is_key_valid(key) is None:
        return jsonify({"message": "key not found"}), 200

    if not uid:
        return jsonify({"message": "UID missing"}), 200

    uid = str(uid).strip()

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        result = loop.run_until_complete(sendLikes(uid))

        loop.close()

        return jsonify(result[0]), result[1]

    except Exception as e:
        print(f"[FF_LIKES] ERROR: {e}")
        return jsonify({"error": str(e)}), 500

# --- MAIN ---
if __name__ == "__main__":
    load_accounts()

    # Background task for refreshing tokens
    def bg():
        try:
            asyncio.run(refresh_tokens())
        except Exception as e:
            print(f"[bg] refresh_tokens ERROR: {e}")

    threading.Thread(target=bg, daemon=True).start()
    schedule_reset()

    import os
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000)),
        threaded=True
    )

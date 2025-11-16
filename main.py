#!/usr/bin/env python3
import json
import requests
import threading
import time
import asyncio
import aiohttp

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
accounts_data = {}
account_index = 0
accounts_lock = threading.Lock()

tokens = {}
tokens_lock = threading.Lock()

used_uids = {}
uids_lock = threading.Lock()

api_keys = {
    "ansoiu": {"exp": "30/07/2095", "remain": 999, "max_remain": 999, "last_reset": None}
}

# ------------------------------------------------------------
#  API KEY CHECK
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
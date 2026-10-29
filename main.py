from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_count_pb2
import uid_generator_pb2
import time
from collections import defaultdict
from datetime import datetime
import random
import os
import urllib.parse
import jwt
import threading
import pickle

app = Flask(__name__)

# ==================== KEYS ====================
API_KEY = "mm"

# ==================== INFO API ====================
INFO_API_URL = "http://78.154.103.39:11168/info?uid={uid}"

# ==================== 2 JWT TOKEN APIS ====================
JWT_API_URLS = [
    "http://78.154.103.23:12698/token",
    "http://78.154.103.23:12698/token",
]

TOKEN_CACHE = {}
FAILED_TOKENS = {}
TOKEN_EXPIRY_HOURS = 6

# ==================== TRACKING ====================
liked_cache = defaultdict(set)
TRACKER_LOCK = threading.Lock()

# ==================== PERSISTENT STORAGE ====================
def save_data():
    try:
        os.makedirs('/tmp', exist_ok=True)
        with TRACKER_LOCK:
            with open('/tmp/liked_cache.pkl', 'wb') as f:
                pickle.dump(dict(liked_cache), f)
            with open('/tmp/token_cache.pkl', 'wb') as f:
                pickle.dump(dict(TOKEN_CACHE), f)
            with open('/tmp/failed_tokens.pkl', 'wb') as f:
                pickle.dump(dict(FAILED_TOKENS), f)
    except Exception as e:
        print(f"Error saving data: {e}")

def load_data():
    global liked_cache, TOKEN_CACHE, FAILED_TOKENS
    try:
        os.makedirs('/tmp', exist_ok=True)
        if os.path.exists('/tmp/liked_cache.pkl'):
            with open('/tmp/liked_cache.pkl', 'rb') as f:
                loaded_cache = pickle.load(f)
                liked_cache.update(loaded_cache)
        if os.path.exists('/tmp/token_cache.pkl'):
            with open('/tmp/token_cache.pkl', 'rb') as f:
                loaded_token_cache = pickle.load(f)
                TOKEN_CACHE.update(loaded_token_cache)
        if os.path.exists('/tmp/failed_tokens.pkl'):
            with open('/tmp/failed_tokens.pkl', 'rb') as f:
                loaded_failed = pickle.load(f)
                FAILED_TOKENS.update(loaded_failed)
        print(f"✅ Data loaded: {len(TOKEN_CACHE)} tokens, {len(FAILED_TOKENS)} failed")
    except Exception as e:
        print(f"Error loading data: {e}")

def load_accounts(region):
    try:
        region = region.upper().strip()

        if region == "IND":
            filename = "account_ind.json"
        elif region in {"BR", "US", "SAC", "NA"}:
            filename = "account_br.json"
        else:
            filename = "account_bd.json"

        if not os.path.exists(filename):
            print(f"Warning: {filename} not found!")
            return []

        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        accounts = []
        seen_uids = set()

        if isinstance(data, list):
            for item in data:
                uid = None
                password = None

                if isinstance(item, dict):
                    uid = str(item.get("uid", "")).strip()
                    password = str(item.get("password", "")).strip()
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    uid = str(item[0]).strip()
                    password = str(item[1]).strip()

                if uid and password and uid.isdigit() and uid not in seen_uids:
                    seen_uids.add(uid)
                    accounts.append({
                        "uid": uid,
                        "password": password
                    })

        elif isinstance(data, dict):
            for uid, password in data.items():
                uid = str(uid).strip()
                password = str(password).strip()
                if uid and password and uid.isdigit() and uid not in seen_uids:
                    seen_uids.add(uid)
                    accounts.append({
                        "uid": uid,
                        "password": password
                    })

        print(f"Loaded {len(accounts)} accounts from {filename}")
        return accounts

    except Exception as e:
        print(f"Error loading accounts: {e}")
        return []

async def generate_jwt_token_with_api(uid, password, api_url, retry_count=0):
    encoded_password = urllib.parse.quote(password, safe='')
    max_attempts = 3
    
    for attempt in range(retry_count, max_attempts):
        try:
            url = f"{api_url}?uid={uid}&password={encoded_password}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        token = None
                        if isinstance(data, dict):
                            if 'token' in data:
                                token = data['token']
                            elif 'access_token' in data:
                                token = data['access_token']
                            elif 'data' in data and isinstance(data['data'], dict):
                                if 'token' in data['data']:
                                    token = data['data']['token']
                        
                        if token:
                            try:
                                payload = jwt.decode(token, options={"verify_signature": False})
                                exp = payload.get("exp", int(time.time()) + (TOKEN_EXPIRY_HOURS * 3600))
                            except:
                                exp = int(time.time()) + (TOKEN_EXPIRY_HOURS * 3600)
                            
                            TOKEN_CACHE[uid] = {
                                "token": token,
                                "expires_at": datetime.utcfromtimestamp(exp),
                                "api_used": api_url
                            }
                            
                            if uid in FAILED_TOKENS:
                                del FAILED_TOKENS[uid]
                            
                            print(f"✅ Token generated for {uid} from {api_url}")
                            return token
                        else:
                            print(f"⚠️ No token in response for {uid} from {api_url}")
                    else:
                        print(f"❌ API {api_url} returned {response.status} for {uid}")
                            
        except asyncio.TimeoutError:
            print(f"⏰ Timeout for {uid} from {api_url}")
        except Exception as e:
            print(f"❌ Error for {uid} from {api_url}: {e}")
        
        if attempt < max_attempts - 1:
            await asyncio.sleep(2)
    
    FAILED_TOKENS[uid] = {
        'timestamp': time.time(),
        'api_used': api_url
    }
    print(f"❌ Failed to generate token for {uid}")
    return None

async def generate_tokens_batch_parallel(accounts, api_urls):
    if not accounts:
        return {}
    
    total_accounts = len(accounts)
    split_size = total_accounts // len(api_urls)
    
    api1_accounts = accounts[:split_size]
    api2_accounts = accounts[split_size:]
    
    print(f"📊 API1: {len(api1_accounts)} accounts, API2: {len(api2_accounts)} accounts")
    print(f"🚀 API1 এবং API2 একসাথে তাদের ভাগের সব account এর token generate করছে...")
    
    async def generate_for_api1():
        if not api1_accounts:
            return {}
        print(f"🔥 API1 শুরু করলো {len(api1_accounts)} টা account এর token generation (সব একসাথে)...")
        tokens = {}
        semaphore = asyncio.Semaphore(100)
        
        async def generate_for_account(acc):
            token = await generate_jwt_token_with_api(acc['uid'], acc['password'], api_urls[0])
            if token:
                tokens[acc['uid']] = token
            return token
        
        async def limited_generate(acc):
            async with semaphore:
                await generate_for_account(acc)
        
        tasks = [limited_generate(acc) for acc in api1_accounts]
        await asyncio.gather(*tasks, return_exceptions=True)
        print(f"✅ API1 শেষ করলো {len(tokens)} টা token")
        return tokens
    
    async def generate_for_api2():
        if not api2_accounts:
            return {}
        print(f"🔥 API2 শুরু করলো {len(api2_accounts)} টা account এর token generation (সব একসাথে)...")
        tokens = {}
        semaphore = asyncio.Semaphore(100)
        
        async def generate_for_account(acc):
            token = await generate_jwt_token_with_api(acc['uid'], acc['password'], api_urls[1])
            if token:
                tokens[acc['uid']] = token
            return token
        
        async def limited_generate(acc):
            async with semaphore:
                await generate_for_account(acc)
        
        tasks = [limited_generate(acc) for acc in api2_accounts]
        await asyncio.gather(*tasks, return_exceptions=True)
        print(f"✅ API2 শেষ করলো {len(tokens)} টা token")
        return tokens

    start_time = time.time()
    results = await asyncio.gather(
        generate_for_api1(),
        generate_for_api2(),
        return_exceptions=True
    )
    end_time = time.time()
    
    all_tokens = {}
    for result in results:
        if isinstance(result, dict):
            all_tokens.update(result)
    
    print(f"✅ মোট {len(all_tokens)} টা token generate হলো (টাইম: {round(end_time - start_time, 2)} সেকেন্ড)")
    return all_tokens

async def send_like(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB55"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers, timeout=5) as response:
                return response.status
    except:
        return 500

async def send_likes_batch(target_uid, encrypted_uid, accounts_with_tokens, url):
    if not accounts_with_tokens:
        return 0, 0
    
    semaphore = asyncio.Semaphore(100)
    successful = 0
    failed = 0
    
    async def send_for_account(acc, token):
        nonlocal successful, failed
        status = await send_like(encrypted_uid, token, url)
        
        if status == 200:
            with TRACKER_LOCK:
                liked_cache[target_uid].add(acc['uid'])
            successful += 1
        else:
            failed += 1
    
    async def limited_send(acc, token):
        async with semaphore:
            await send_for_account(acc, token)
    
    tasks = []
    for acc, token in accounts_with_tokens:
        tasks.append(limited_send(acc, token))
    
    await asyncio.gather(*tasks, return_exceptions=True)
    
    return successful, failed

async def send_all_likes(target_uid, url, accounts, encrypted_uid):
    if not accounts:
        return {'success': 0, 'failed': 0, 'total': 0, 'already_liked': 0}
    
    with TRACKER_LOCK:
        already_liked = liked_cache.get(target_uid, set())
        fresh_accounts = [acc for acc in accounts if acc['uid'] not in already_liked]
    
    print(f"Total: {len(accounts)}, Fresh: {len(fresh_accounts)}, Already liked: {len(already_liked)}")
    
    if not fresh_accounts:
        return {
            'success': 0, 
            'failed': 0, 
            'total': len(accounts),
            'already_liked': len(already_liked),
            'fresh_used': 0
        }
    
    random.shuffle(fresh_accounts)
    
    accounts_needing_tokens = []
    accounts_with_valid_tokens = []
    
    for acc in fresh_accounts:
        if acc['uid'] in TOKEN_CACHE:
            cached = TOKEN_CACHE[acc['uid']]
            remaining = (cached["expires_at"] - datetime.utcnow()).total_seconds()
            if remaining > 0:
                accounts_with_valid_tokens.append((acc, cached["token"]))
            else:
                accounts_needing_tokens.append(acc)
        else:
            accounts_needing_tokens.append(acc)
    
    print(f"📊 Valid tokens in cache: {len(accounts_with_valid_tokens)}")
    print(f"📊 Need new tokens: {len(accounts_needing_tokens)}")
    
    tokens_dict = {}
    token_gen_time = 0
    if accounts_needing_tokens:
        print(f"🔄 {len(accounts_needing_tokens)} টা account এর জন্য token generation শুরু...")
        start = time.time()
        tokens_dict = await generate_tokens_batch_parallel(accounts_needing_tokens, JWT_API_URLS)
        token_gen_time = time.time() - start
        save_data()
    
    all_accounts_with_tokens = list(accounts_with_valid_tokens)
    for acc in fresh_accounts:
        if acc['uid'] in tokens_dict and tokens_dict[acc['uid']]:
            all_accounts_with_tokens.append((acc, tokens_dict[acc['uid']]))
    
    print(f"✅ {len(all_accounts_with_tokens)} টা account এর token ready")
    
    if not all_accounts_with_tokens:
        return {'success': 0, 'failed': len(fresh_accounts), 'total': len(accounts)}
    
    print(f"🚀 100 concurrent এ {len(all_accounts_with_tokens)} টা like পাঠাচ্ছি...")
    start = time.time()
    successful, failed = await send_likes_batch(target_uid, encrypted_uid, all_accounts_with_tokens, url)
    like_time = time.time() - start
    
    save_data()
    
    return {
        'success': successful,
        'failed': failed,
        'total': len(accounts),
        'already_liked': len(already_liked),
        'fresh_used': len(all_accounts_with_tokens),
        'token_gen_time': round(token_gen_time, 2),
        'like_send_time': round(like_time, 2),
        'total_time': round(token_gen_time + like_time, 2)
    }

def get_valid_token_sync(uid):
    if uid in TOKEN_CACHE:
        cached = TOKEN_CACHE[uid]
        remaining = (cached["expires_at"] - datetime.utcnow()).total_seconds()
        if remaining > 0:
            return cached["token"]
    return None

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded_message)).decode('utf-8')

def enc(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return encrypt_message(message.SerializeToString())

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except:
        return None

def get_player_info(encrypted_uid, region, token):
    if region == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif region in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB55"
    }

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        return decode_protobuf(response.content)
    except:
        return None

def get_player_level_from_info(uid):
    try:
        url = f"{INFO_API_URL}?uid={uid}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'basicInfo' in data and 'level' in data['basicInfo']:
                return data['basicInfo']['level']
        return None
    except Exception as e:
        return None

def process_like_request(uid, region, require_key=True, api_key=None):
    total_start = time.time()
    
    if require_key and api_key != API_KEY:
        return jsonify({"error": "Invalid API Key"}), 403

    if not uid or not region:
        return jsonify({"error": "UID and region are required"}), 400

    valid_servers = ["IND", "BR", "US", "SAC", "NA", "BD", "RU", "ME", "ID"]
    if region not in valid_servers:
        return jsonify({"error": f"Invalid server. Use: {valid_servers}"}), 400

    player_level = get_player_level_from_info(uid)

    accounts = load_accounts(region)
    if not accounts:
        return jsonify({"error": f"No accounts found for {region}"}), 500

    check_token = None
    for account in accounts[:5]:
        check_token = get_valid_token_sync(account['uid'])
        if check_token:
            break
    
    if not check_token:
        for account in accounts[:5]:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                check_token = loop.run_until_complete(
                    generate_jwt_token_with_api(account['uid'], account['password'], JWT_API_URLS[0])
                )
                loop.close()
                if check_token:
                    break
            except:
                continue
    
    if not check_token:
        return jsonify({"error": "Token generation failed"}), 500
    
    encrypted_uid = enc(uid)

    before = get_player_info(encrypted_uid, region, check_token)
    if before is None:
        return jsonify({"error": "Invalid UID or server"}), 200

    try:
        before_data = json.loads(MessageToJson(before))
        before_like = int(before_data['AccountInfo'].get('Likes', 0))
    except:
        return jsonify({"error": "Data parsing failed"}), 200

    if region == "IND":
        like_url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif region in {"BR", "US", "SAC", "NA"}:
        like_url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        like_url = "https://clientbp.ggpolarbear.com/LikeProfile"

    asyncio.run(send_all_likes(uid, like_url, accounts, encrypted_uid))

    after = get_player_info(encrypted_uid, region, check_token)
    if after is None:
        return jsonify({"error": "Could not verify likes"}), 200

    try:
        after_data = json.loads(MessageToJson(after))
        after_like = int(after_data['AccountInfo']['Likes'])
        player_id = int(after_data['AccountInfo']['UID'])
        player_name = str(after_data['AccountInfo']['PlayerNickname'])
        
        like_given = after_like - before_like
        
        if like_given > 0:
            status = 1
        else:
            status = 2
        
        save_data()
        
        total_time = round(time.time() - total_start, 2)

        response_data = {
            "success": True,
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_id,
            "status": status,
        }
        
        if player_level is not None:
            response_data["Level"] = player_level
        
        return jsonify(response_data)
    except Exception as e:
        return jsonify({"error": str(e), "status": 0}), 500

# ==================== API ENDPOINT ====================

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "Sarker Free Fire Free Like API",
        "port": "1001",
        "developer": "M. Sarker",
        "powered_by": "M. Sarker",
        "message": "API active!"
    })

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    region = request.args.get("region", "").upper()
    key = request.args.get("key")
    return process_like_request(uid, region, True, key)

# Load data on startup
load_data()

if __name__ == '__main__':
    print("API Running...!")
    app.run(host='0.0.0.0', port=5000, debug=True)

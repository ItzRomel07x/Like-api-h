from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import os
import random
import string
from datetime import datetime, date, timedelta
from pymongo import MongoClient
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

# -------------------- MongoDB Setup --------------------
MONGODB_URI = os.environ.get('MONGODB_URI')
if not MONGODB_URI:
    raise RuntimeError("❌ MONGODB_URI not set. Add it to your environment variables")

mongo_client = None
db = None

def get_mongo_db():
    """Return cached MongoDB client & database"""
    global mongo_client, db
    if mongo_client is None:
        mongo_client = MongoClient(
            MONGODB_URI,
            tls=True,  # Ensure SSL/TLS for Atlas
            tlsAllowInvalidCertificates=False,
            serverSelectionTimeoutMS=10000
        )
        db = mongo_client.get_database('test')  # Replace with your DB name
    return db

# -------------------- API Key Management --------------------
def generate_api_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def create_api_key_in_db(quota=100):
    try:
        database = get_mongo_db()
        collection = database['api_keys']

        api_key = generate_api_key()
        key_data = {
            'api_key': api_key,
            'quota': quota,
            'used': 0,
            'created_at': datetime.now(),
            'last_reset_date': date.today().isoformat(),
            'active': True
        }
        collection.insert_one(key_data)
        app.logger.info(f"Created API key {api_key} with quota {quota}")
        return api_key
    except Exception as e:
        app.logger.error(f"Error creating API key: {e}")
        return None

def validate_api_key(api_key):
    """Validate API key and return key data"""
    try:
        database = get_mongo_db()
        collection = database['api_keys']

        key_data = collection.find_one({'api_key': api_key, 'active': True})
        if not key_data:
            return None

        # Reset quota daily
        last_reset = key_data.get('last_reset_date')
        today = date.today().isoformat()
        if last_reset != today:
            collection.update_one(
                {'api_key': api_key},
                {'$set': {'used': 0, 'last_reset_date': today}}
            )
            key_data['used'] = 0
            key_data['last_reset_date'] = today

        return key_data
    except Exception as e:
        app.logger.error(f"Error validating API key: {e}")
        return None

def check_and_increment_quota(api_key):
    try:
        database = get_mongo_db()
        collection = database['api_keys']

        key_data = collection.find_one({'api_key': api_key, 'active': True})
        if not key_data:
            return False, "Invalid API key"

        # Reset quota daily
        last_reset = key_data.get('last_reset_date')
        today = date.today().isoformat()
        if last_reset != today:
            collection.update_one(
                {'api_key': api_key},
                {'$set': {'used': 0, 'last_reset_date': today}}
            )
            key_data['used'] = 0

        if key_data['used'] >= key_data['quota']:
            return False, f"Quota exceeded. Used: {key_data['used']}/{key_data['quota']}"

        collection.update_one(
            {'api_key': api_key},
            {'$inc': {'used': 1}}
        )
        return True, f"Requests remaining: {key_data['quota'] - key_data['used'] - 1}/{key_data['quota']}"
    except Exception as e:
        app.logger.error(f"Error checking quota: {e}")
        return False, str(e)

# -------------------- Token Management --------------------
def load_tokens(server_name):
    try:
        database = get_mongo_db()
        if server_name == "IND":
            collection = database['region_IND']
        elif server_name in {"BR", "US", "SAC", "NA"}:
            collection = database['region_BR']
        else:
            collection = database['region_ME']

        docs = list(collection.find({}, {'_id': 0, 'jwt_token': 1}))
        tokens = [{'token': doc['jwt_token']} for doc in docs if doc.get('jwt_token')]
        return tokens if tokens else None
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

# -------------------- Encryption --------------------
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        encrypted = cipher.encrypt(padded)
        return binascii.hexlify(encrypted).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

# -------------------- Protobuf Helpers --------------------
def create_protobuf_message(user_id, region):
    try:
        msg = like_pb2.like()
        msg.uid = int(user_id)
        msg.region = region
        return msg.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

def create_uid_protobuf(uid):
    try:
        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(uid)
        msg.garena = 1
        return msg.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError:
        return None
    except Exception as e:
        app.logger.error(f"Error decoding protobuf: {e}")
        return None

# -------------------- Request Helpers --------------------
async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; Android 14; Pixel 9 Pro Build)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/octet-stream"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed: {response.status}")
                    return None
                content = await response.read()
                binary = bytes.fromhex(content.hex())
                return decode_protobuf(binary)
    except Exception as e:
        app.logger.error(f"Error in send_request: {e}")
        return None

async def send_multiple_requests(uid, server_name, url):
    tokens = load_tokens(server_name)
    if not tokens:
        return None, 0

    encrypted_uid = encrypt_message(create_uid_protobuf(uid))
    if not encrypted_uid:
        return None, 0

    tasks = [send_request(encrypted_uid, t['token'], url) for t in tokens]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results, len(tokens)

# -------------------- API Routes --------------------
@app.route('/create-api-key', methods=['GET', 'POST'])
def create_key():
    try:
        if request.method == 'POST':
            data = request.get_json() or {}
            quota = int(data.get('quota', 100))
        else:
            quota = int(request.args.get('quota', 100))
        if quota < 1:
            return jsonify({"error": "Quota must be positive"}), 400

        api_key = create_api_key_in_db(quota)
        if not api_key:
            return jsonify({"error": "Failed to create API key"}), 500

        return jsonify({"api_key": api_key, "quota": quota, "message": "API key created"}), 201
    except Exception as e:
        app.logger.error(f"Error in create_key: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api-key-status', methods=['GET'])
def api_key_status():
    api_key = request.args.get('api_key')
    if not api_key:
        return jsonify({"error": "api_key required"}), 400
    key_data = validate_api_key(api_key)
    if not key_data:
        return jsonify({"error": "Invalid API key"}), 401
    return jsonify({
        "quota": key_data['quota'],
        "used": key_data['used'],
        "remaining": key_data['quota'] - key_data['used'],
        "active": key_data['active']
    })

@app.route('/like', methods=['GET'])
def handle_like():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    api_key = request.args.get("api_key")

    if not uid or not server_name or not api_key:
        return jsonify({"error": "uid, server_name, and api_key required"}), 400

    key_data = validate_api_key(api_key)
    if not key_data:
        return jsonify({"error": "Invalid API key"}), 401

    quota_ok, quota_msg = check_and_increment_quota(api_key)
    if not quota_ok:
        return jsonify({"error": quota_msg}), 429

    async def process_like():
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        results, tokens_used = await send_multiple_requests(uid, server_name, url)
        return {"status": 1, "tokens_used": tokens_used, "results_count": len(results) if results else 0}

    result = asyncio.run(process_like())
    return jsonify(result)

@app.route('/token-count', methods=['GET'])
def token_count():
    database = get_mongo_db()
    regions = ['region_IND', 'region_BR', 'region_ME']
    summary = {r: database[r].count_documents({}) for r in regions}
    total = sum(summary.values())
    return jsonify({"counts": summary, "total_tokens": total})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

@app.route('/cleanup-tokens', methods=['POST', 'GET'])
def cleanup_tokens():
    try:
        database = get_mongo_db()
        six_hours_ago = datetime.now() - timedelta(hours=6)
        regions = ['region_IND', 'region_BR', 'region_ME']
        summary = {}
        for region in regions:
            result = database[region].delete_many({'created_at': {'$lt': six_hours_ago}})
            summary[region] = result.deleted_count
        return jsonify({"message": "Cleanup completed", "deleted_counts": summary})
    except Exception as e:
        app.logger.error(f"Error cleaning up tokens: {e}")
        return jsonify({"error": str(e)}), 500

# -------------------- Main --------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

#important notice this is not my script i only modify this script to work on telegram 
import logging
import asyncio
import json
import os
import threading
from datetime import datetime
from typing import Dict, List, Optional
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import codecs
import time
import base64
import re
import urllib3
import sys
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters
)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Bot states
SELECTING_REGION, SELECTING_OPTION, ENTERING_COUNT, ENTERING_NAME, ENTERING_PASSWORD, ENTERING_THRESHOLD = range(6)

# Configuration
BOT_TOKEN = "8549665053:AAE-61prZ5lRmMty-twyWaamNZ8onJW6sh0"  # Replace with your bot token
ADMIN_IDS = [7221869317]  # Replace with your Telegram user ID

# Storage folders (same as your original code)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# Change this line:
BASE_FOLDER = os.path.join(CURRENT_DIR, "BLACK-APIS-ERA")
TOKENS_FOLDER = os.path.join(BASE_FOLDER, "TOKENS-JWT")
ACCOUNTS_FOLDER = os.path.join(BASE_FOLDER, "ACCOUNTS")
RARE_ACCOUNTS_FOLDER = os.path.join(BASE_FOLDER, "RARE ACCOUNTS")
COUPLES_ACCOUNTS_FOLDER = os.path.join(BASE_FOLDER, "COUPLES ACCOUNTS")
GHOST_FOLDER = os.path.join(BASE_FOLDER, "GHOST")
GHOST_ACCOUNTS_FOLDER = os.path.join(GHOST_FOLDER, "ACCOUNTS")
GHOST_RARE_FOLDER = os.path.join(GHOST_FOLDER, "RAREACCOUNT")
GHOST_COUPLES_FOLDER = os.path.join(GHOST_FOLDER, "COUPLESACCOUNT")

for folder in [BASE_FOLDER, TOKENS_FOLDER, ACCOUNTS_FOLDER, RARE_ACCOUNTS_FOLDER, COUPLES_ACCOUNTS_FOLDER, GHOST_FOLDER, GHOST_ACCOUNTS_FOLDER, GHOST_RARE_FOLDER, GHOST_COUPLES_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Region data (same as your original code)
REGION_LANG = {"ME": "ar","IND": "hi","ID": "id","VN": "vi","TH": "th","BD": "bn","PK": "ur","TW": "zh","CIS": "ru","SAC": "es","BR": "pt"}
REGION_URLS = {"IND": "https://client.ind.freefiremobile.com/","ID": "https://clientbp.ggblueshark.com/","BR": "https://client.us.freefiremobile.com/","ME": "https://clientbp.common.ggbluefox.com/","VN": "https://clientbp.ggblueshark.com/","TH": "https://clientbp.common.ggbluefox.com/","CIS": "https://clientbp.ggblueshark.com/","BD": "https://clientbp.ggblueshark.com/","PK": "https://clientbp.ggblueshark.com/","SG": "https://clientbp.ggblueshark.com/","SAC": "https://client.us.freefiremobile.com/","TW": "https://clientbp.ggblueshark.com/"}

hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)
hex_data = "8J+agCBCbGFjayBBcGlzIEFjY291bnQgR2VuZXJhdG9yIPCfkqsgQnkgQkxBQ0tfQVBJcyB8IE5vdCBGb3IgU2FsZSDwn5Kr"  # "🔰 Black Apis Account Generator ✅ By BLACK_APIs | Not For Sale ✅"
client_data = base64.b64decode(hex_data).decode('utf-8')
GARENA = "QkxBQ0tfQVBJcw=="  # BLACK_APIs in base64

# Account rarity patterns (same as your original code)
ACCOUNT_RARITY_PATTERNS = {
    "REPEATED_DIGITS_4": [r"(\d)\1{3,}", 3],
    "REPEATED_DIGITS_3": [r"(\d)\1\1(\d)\2\2", 2],
    "SEQUENTIAL_5": [r"(12345|23456|34567|45678|56789)", 4],
    "SEQUENTIAL_4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 3],
    "PALINDROME_6": [r"^(\d)(\d)(\d)\3\2\1$", 5],
    "PALINDROME_4": [r"^(\d)(\d)\2\1$", 3],
    "SPECIAL_COMBINATIONS_HIGH": [r"(69|420|1337|007)", 4],
    "SPECIAL_COMBINATIONS_MED": [r"(100|200|300|400|500|666|777|888|999)", 2],
    "QUADRUPLE_DIGITS": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
    "MIRROR_PATTERN_HIGH": [r"^(\d{2,3})\1$", 3],
    "MIRROR_PATTERN_MED": [r"(\d{2})0\1", 2],
    "GOLDEN_RATIO": [r"1618|0618", 3]
}

ACCOUNT_COUPLES_PATTERNS = {
    "MATCHING_PAIRS": [
        r"(\d{2})01.*\d{2}02",
        r"(\d{2})11.*\d{2}12",
        r"(\d{2})21.*\d{2}22",
    ],
    "COMPLEMENTARY_DIGITS": [
        r".*13.*14$",
        r".*07.*08$",
        r".*51.*52$",
    ],
    "LOVE_NUMBERS": [
        r".*520.*521$",
        r".*1314$",
    ]
}

# Global counters
RARITY_SCORE_THRESHOLD = 3
POTENTIAL_COUPLES = {}
COUPLES_LOCK = threading.Lock()
FILE_LOCKS = {}

# User session data
user_sessions: Dict[int, Dict] = {}
generation_tasks: Dict[int, Dict] = {}

import asyncio
from telegram.error import RetryAfter, TimedOut, NetworkError

# Rate limiting decorator
def rate_limit(max_calls=30, period=1.0):
    """Rate limiting decorator for Telegram API calls."""
    import time
    from functools import wraps
    
    calls = []
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            now = time.time()
            # Remove calls older than period
            calls[:] = [call for call in calls if call > now - period]
            
            if len(calls) >= max_calls:
                sleep_time = calls[0] + period - now
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
            
            calls.append(time.time())
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def get_file_lock(filename):
    if filename not in FILE_LOCKS:
        FILE_LOCKS[filename] = threading.Lock()
    return FILE_LOCKS[filename]

class FreeFireRareAccountGenerator:
    def __init__(self):
        self.lock = threading.Lock()
        self.success_counter = 0
        self.rare_counter = 0
        self.couples_counter = 0
        self.running = False
        
    def check_account_rarity(self, account_data):
        account_id = account_data.get("account_id", "")
        
        if account_id == "N/A" or not account_id:
            return False, None, None, 0
        
        rarity_score = 0
        detected_patterns = []
        
        for rarity_type, pattern_data in ACCOUNT_RARITY_PATTERNS.items():
            pattern = pattern_data[0]
            score = pattern_data[1]
            if re.search(pattern, account_id):
                rarity_score += score
                detected_patterns.append(rarity_type)
        
        account_id_digits = [int(d) for d in account_id if d.isdigit()]
        
        if len(set(account_id_digits)) == 1 and len(account_id_digits) >= 4:
            rarity_score += 5
            detected_patterns.append("UNIFORM_DIGITS")
        
        if len(account_id_digits) >= 4:
            differences = [account_id_digits[i+1] - account_id_digits[i] for i in range(len(account_id_digits)-1)]
            if len(set(differences)) == 1:
                rarity_score += 4
                detected_patterns.append("ARITHMETIC_SEQUENCE")
        
        if len(account_id) <= 8 and account_id.isdigit() and int(account_id) < 1000000:
            rarity_score += 3
            detected_patterns.append("LOW_ACCOUNT_ID")
        
        if rarity_score >= RARITY_SCORE_THRESHOLD:
            reason = f"Account ID {account_id} - Score: {rarity_score} - Patterns: {', '.join(detected_patterns)}"
            return True, "RARE_ACCOUNT", reason, rarity_score
        
        return False, None, None, rarity_score
    
    def check_account_couples(self, account_data, thread_id):
        account_id = account_data.get("account_id", "")
        
        if account_id == "N/A" or not account_id:
            return False, None, None
        
        with COUPLES_LOCK:
            for stored_id, stored_data in POTENTIAL_COUPLES.items():
                stored_account_id = stored_data.get('account_id', '')
                
                couple_found, reason = self.check_account_couple_patterns(account_id, stored_account_id)
                if couple_found:
                    partner_data = stored_data
                    del POTENTIAL_COUPLES[stored_id]
                    return True, reason, partner_data
            
            POTENTIAL_COUPLES[account_id] = {
                'uid': account_data.get('uid', ''),
                'account_id': account_id,
                'name': account_data.get('name', ''),
                'password': account_data.get('password', ''),
                'region': account_data.get('region', ''),
                'thread_id': thread_id,
                'timestamp': datetime.now().isoformat()
            }
        
        return False, None, None
    
    def check_account_couple_patterns(self, account_id1, account_id2):
        if account_id1 and account_id2 and abs(int(account_id1) - int(account_id2)) == 1:
            return True, f"Sequential Account IDs: {account_id1} & {account_id2}"
        
        if account_id1 == account_id2[::-1]:
            return True, f"Mirror Account IDs: {account_id1} & {account_id2}"
        
        if account_id1 and account_id2:
            sum_acc = int(account_id1) + int(account_id2)
            if sum_acc % 1000 == 0 or sum_acc % 10000 == 0:
                return True, f"Complementary sum: {account_id1} + {account_id2} = {sum_acc}"
        
        love_numbers = ['520', '521', '1314', '3344']
        for love_num in love_numbers:
            if love_num in account_id1 and love_num in account_id2:
                return True, f"Both contain love number: {love_num}"
        
        return False, None
    
    def save_rare_account(self, account_data, rarity_type, reason, rarity_score, is_ghost=False):
        try:
            if is_ghost:
                rare_filename = os.path.join(GHOST_RARE_FOLDER, "rare-ghost.json")
            else:
                region = account_data.get('region', 'UNKNOWN')
                rare_filename = os.path.join(RARE_ACCOUNTS_FOLDER, f"rare-{region}.json")
            
            rare_entry = {
                'uid': account_data["uid"],
                'password': account_data["password"],
                'account_id': account_data.get("account_id", "N/A"),
                'name': account_data["name"],
                'region': "BLACK_Apis" if is_ghost else account_data.get('region', 'UNKNOWN'),
                'rarity_type': rarity_type,
                'rarity_score': rarity_score,
                'reason': reason,
                'date_identified': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'jwt_token': account_data.get('jwt_token', ''),
                'thread_id': account_data.get('thread_id', 'N/A')
            }
            
            file_lock = get_file_lock(rare_filename)
            with file_lock:
                rare_list = []
                if os.path.exists(rare_filename):
                    try:
                        with open(rare_filename, 'r', encoding='utf-8') as f:
                            rare_list = json.load(f)
                    except (json.JSONDecodeError, IOError):
                        rare_list = []
                
                existing_ids = [acc.get('account_id') for acc in rare_list]
                if account_data.get("account_id", "N/A") not in existing_ids:
                    rare_list.append(rare_entry)
                    
                    temp_filename = rare_filename + '.tmp'
                    with open(temp_filename, 'w', encoding='utf-8') as f:
                        json.dump(rare_list, f, indent=2, ensure_ascii=False)
                    os.replace(temp_filename, rare_filename)
                    return True
                else:
                    return False
            
        except Exception as e:
            logger.error(f"Error saving rare account: {e}")
            return False
    
    def save_couples_account(self, account1, account2, reason, is_ghost=False):
        try:
            if is_ghost:
                couples_filename = os.path.join(GHOST_COUPLES_FOLDER, "couples-ghost.json")
            else:
                region = account1.get('region', 'UNKNOWN')
                couples_filename = os.path.join(COUPLES_ACCOUNTS_FOLDER, f"couples-{region}.json")
            
            couples_entry = {
                'couple_id': f"{account1.get('account_id', 'N/A')}_{account2.get('account_id', 'N/A')}",
                'account1': {
                    'uid': account1["uid"],
                    'password': account1["password"],
                    'account_id': account1.get("account_id", "N/A"),
                    'name': account1["name"],
                    'thread_id': account1.get('thread_id', 'N/A')
                },
                'account2': {
                    'uid': account2["uid"],
                    'password': account2["password"],
                    'account_id': account2.get("account_id", "N/A"),
                    'name': account2["name"],
                    'thread_id': account2.get('thread_id', 'N/A')
                },
                'reason': reason,
                'region': "BLACK_Apis" if is_ghost else account1.get('region', 'UNKNOWN'),
                'date_matched': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            file_lock = get_file_lock(couples_filename)
            with file_lock:
                couples_list = []
                if os.path.exists(couples_filename):
                    try:
                        with open(couples_filename, 'r', encoding='utf-8') as f:
                            couples_list = json.load(f)
                    except (json.JSONDecodeError, IOError):
                        couples_list = []
                
                existing_couples = [couple.get('couple_id') for couple in couples_list]
                if couples_entry['couple_id'] not in existing_couples:
                    couples_list.append(couples_entry)
                    
                    temp_filename = couples_filename + '.tmp'
                    with open(temp_filename, 'w', encoding='utf-8') as f:
                        json.dump(couples_list, f, indent=2, ensure_ascii=False)
                    os.replace(temp_filename, couples_filename)
                    return True
                else:
                    return False
            
        except Exception as e:
            logger.error(f"Error saving couples account: {e}")
            return False
    
    def generate_random_name(self, base_name):
        exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
        number = random.randint(1, 99999)
        number_str = f"{number:05d}"
        exponent_str = ''.join(exponent_digits[digit] for digit in number_str)
        return f"{base_name[:7]}{exponent_str}"
    
    def generate_custom_password(self, prefix):
        garena_decoded = base64.b64decode(GARENA).decode('utf-8')
        characters = string.ascii_uppercase + string.digits
        random_part1 = ''.join(random.choice(characters) for _ in range(5))
        random_part2 = ''.join(random.choice(characters) for _ in range(5))
        return f"{prefix}_{random_part1}_{garena_decoded}_{random_part2}"
    
    def EnC_Vr(self, N):
        if N < 0: 
            return b''
        H = []
        while True:
            BesTo = N & 0x7F 
            N >>= 7
            if N: 
                BesTo |= 0x80
            H.append(BesTo)
            if not N: 
                break
        return bytes(H)
    
    def CrEaTe_VarianT(self, field_number, value):
        field_header = (field_number << 3) | 0
        return self.EnC_Vr(field_header) + self.EnC_Vr(value)
    
    def CrEaTe_LenGTh(self, field_number, value):
        field_header = (field_number << 3) | 2
        encoded_value = value.encode() if isinstance(value, str) else value
        return self.EnC_Vr(field_header) + self.EnC_Vr(len(encoded_value)) + encoded_value
    
    def CrEaTe_ProTo(self, fields):
        packet = bytearray()    
        for field, value in fields.items():
            if isinstance(value, dict):
                nested_packet = self.CrEaTe_ProTo(value)
                packet.extend(self.CrEaTe_LenGTh(field, nested_packet))
            elif isinstance(value, int):
                packet.extend(self.CrEaTe_VarianT(field, value))           
            elif isinstance(value, str) or isinstance(value, bytes):
                packet.extend(self.CrEaTe_LenGTh(field, value))           
        return packet
    
    def E_AEs(self, Pc):
        Z = bytes.fromhex(Pc)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        K = AES.new(key , AES.MODE_CBC , iv)
        R = K.encrypt(pad(Z , AES.block_size))
        return R
    
    def encrypt_api(self, plain_text):
        plain_text = bytes.fromhex(plain_text)
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    
    def create_acc(self, region, account_name, password_prefix, is_ghost=False):
        if not self.running:
            return None
        try:
            password = self.generate_custom_password(password_prefix)
            data = f"password={password}&client_type=2&source=2&app_id=100067"
            message = data.encode('utf-8')
            signature = hmac.new(key, message, hashlib.sha256).hexdigest()
            
            url = "https://100067.connect.garena.com/oauth/guest/register"
            headers = {
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
                "Authorization": "Signature " + signature,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive"
            }
            
            response = requests.post(url, headers=headers, data=data, timeout=30, verify=False)
            response.raise_for_status()
            
            if 'uid' in response.json():
                uid = response.json()['uid']
                logger.info(f"Guest account created: {uid}")
                time.sleep(random.uniform(1, 2))
                return self.token(uid, password, region, account_name, password_prefix, is_ghost)
            return None
        except Exception as e:
            logger.warning(f"Create account failed: {e}")
            time.sleep(random.uniform(1, 2))
            return None
    
    def token(self, uid, password, region, account_name, password_prefix, is_ghost=False):
        if not self.running:
            return None
        try:
            url = "https://100067.connect.garena.com/oauth/guest/token/grant"
            headers = {
                "Accept-Encoding": "gzip",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "100067.connect.garena.com",
                "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            }
            body = {
                "uid": uid,
                "password": password,
                "response_type": "token",
                "client_type": "2",
                "client_secret": key,
                "client_id": "100067"
            }
            
            response = requests.post(url, headers=headers, data=body, timeout=30, verify=False)
            response.raise_for_status()
            
            if 'open_id' in response.json():
                open_id = response.json()['open_id']
                access_token = response.json()["access_token"]
                refresh_token = response.json()['refresh_token']
                
                result = self.encode_string(open_id)
                field = self.to_unicode_escaped(result['field_14'])
                field = codecs.decode(field, 'unicode_escape').encode('latin1')
                logger.info(f"Token granted for: {uid}")
                time.sleep(random.uniform(1, 2))
                return self.Major_Regsiter(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost)
            return None
        except Exception as e:
            logger.warning(f"Token grant failed: {e}")
            time.sleep(random.uniform(1, 2))
            return None
    
    def encode_string(self, original):
        keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                     0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
        encoded = ""
        for i in range(len(original)):
            orig_byte = ord(original[i])
            key_byte = keystream[i % len(keystream)]
            result_byte = orig_byte ^ key_byte
            encoded += chr(result_byte)
        return {"open_id": original, "field_14": encoded}
    
    def to_unicode_escaped(self, s):
        return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)
    
    def Major_Regsiter(self, access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost=False):
        if not self.running:
            return None
        try:
            if is_ghost:
                url = "https://loginbp.ggblueshark.com/MajorRegister"
            else:
                if region.upper() in ["ME", "TH"]:
                    url = "https://loginbp.common.ggbluefox.com/MajorRegister"
                else:
                    url = "https://loginbp.ggblueshark.com/MajorRegister"
            
            name = self.generate_random_name(account_name)
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",   
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com" if is_ghost or region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
                "ReleaseVersion": "OB51",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4."
            }

            lang_code = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
            payload = {
                1: name,
                2: access_token,
                3: open_id,
                5: 102000007,
                6: 4,
                7: 1,
                13: 1,
                14: field,
                15: lang_code,
                16: 1,
                17: 1
            }

            payload_bytes = self.CrEaTe_ProTo(payload)
            encrypted_payload = self.E_AEs(payload_bytes.hex())
            
            response = requests.post(url, headers=headers, data=encrypted_payload, verify=False, timeout=30)
            
            if response.status_code == 200:
                logger.info(f"MajorRegister successful: {name}")
                
                # Get account ID and JWT from login
                login_result = self.perform_major_login(uid, password, access_token, open_id, region, is_ghost)
                account_id = login_result.get("account_id", "N/A")
                jwt_token = login_result.get("jwt_token", "")
                
                account_data = {
                    "uid": uid, 
                    "password": password, 
                    "name": name, 
                    "region": "GHOST" if is_ghost else region, 
                    "status": "success",
                    "account_id": account_id,
                    "jwt_token": jwt_token
                }
                
                return account_data
            else:
                logger.warning(f"MajorRegister returned status: {response.status_code}")
                return None
        except Exception as e:
            logger.warning(f"Major_Regsiter error: {str(e)}")
            time.sleep(random.uniform(1, 2))
            return None
    
    def perform_major_login(self, uid, password, access_token, open_id, region, is_ghost=False):
        try:
            lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
            
            payload_parts = [
                b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
                lang.encode("ascii"),
                b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
            ]
            
            payload = b''.join(payload_parts)
            
            if is_ghost:
                url = "https://loginbp.ggblueshark.com/MajorLogin"
            elif region.upper() in ["ME", "TH"]:
                url = "https://loginbp.common.ggbluefox.com/MajorLogin"
            else:
                url = "https://loginbp.ggblueshark.com/MajorLogin"
            
            headers = {
                "Accept-Encoding": "gzip",
                "Authorization": "Bearer",
                "Connection": "Keep-Alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Expect": "100-continue",
                "Host": "loginbp.ggblueshark.com" if is_ghost or region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
                "ReleaseVersion": "OB51",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4.11f1"
            }

            data = payload
            data = data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
            data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
            
            d = self.encrypt_api(data.hex())
            final_payload = bytes.fromhex(d)

            response = requests.post(url, headers=headers, data=final_payload, verify=False, timeout=30)
            
            if response.status_code == 200 and len(response.text) > 10:
                jwt_start = response.text.find("eyJ")
                if jwt_start != -1:
                    jwt_token = response.text[jwt_start:]
                    second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                    if second_dot != -1:
                        jwt_token = jwt_token[:second_dot + 44]
                        
                        account_id = self.decode_jwt_token(jwt_token)
                        return {"account_id": account_id, "jwt_token": jwt_token}
            
            return {"account_id": "N/A", "jwt_token": ""}
        except Exception as e:
            logger.warning(f"MajorLogin failed: {e}")
            return {"account_id": "N/A", "jwt_token": ""}
    
    def decode_jwt_token(self, jwt_token):
        try:
            parts = jwt_token.split('.')
            if len(parts) >= 2:
                payload_part = parts[1]
                padding = 4 - len(payload_part) % 4
                if padding != 4:
                    payload_part += '=' * padding
                decoded = base64.urlsafe_b64decode(payload_part)
                data = json.loads(decoded)
                account_id = data.get('account_id') or data.get('external_id')
                if account_id:
                    return str(account_id)
        except Exception as e:
            logger.warning(f"JWT decode failed: {e}")
        return "N/A"
    
    def save_normal_account(self, account_data, region, is_ghost=False):
        try:
            if is_ghost:
                account_filename = os.path.join(GHOST_ACCOUNTS_FOLDER, "ghost.json")
            else:
                account_filename = os.path.join(ACCOUNTS_FOLDER, f"accounts-{region}.json")
            
            account_entry = {
                'uid': account_data["uid"],
                'password': account_data["password"],
                'account_id': account_data.get("account_id", "N/A"),
                'name': account_data["name"],
                'region': "BLACK_Apis" if is_ghost else region,
                'date_created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'thread_id': account_data.get('thread_id', 'N/A')
            }
            
            file_lock = get_file_lock(account_filename)
            with file_lock:
                accounts_list = []
                if os.path.exists(account_filename):
                    try:
                        with open(account_filename, 'r', encoding='utf-8') as f:
                            accounts_list = json.load(f)
                    except (json.JSONDecodeError, IOError):
                        accounts_list = []
                
                existing_account_ids = [acc.get('account_id') for acc in accounts_list]
                if account_data.get("account_id", "N/A") not in existing_account_ids:
                    accounts_list.append(account_entry)
                    
                    temp_filename = account_filename + '.tmp'
                    with open(temp_filename, 'w', encoding='utf-8') as f:
                        json.dump(accounts_list, f, indent=2, ensure_ascii=False)
                    
                    os.replace(temp_filename, account_filename)
                    return True
                else:
                    return False
            
        except Exception as e:
            logger.error(f"Error saving normal account: {e}")
            return False
    
    def save_jwt_token(self, account_data, jwt_token, region, is_ghost=False):
        try:
            if is_ghost:
                token_filename = os.path.join(GHOST_FOLDER, "tokens-ghost.json")
            else:
                token_filename = os.path.join(TOKENS_FOLDER, f"tokens-{region}.json")
            
            token_entry = {
                'uid': account_data["uid"],
                'account_id': account_data.get("account_id", "N/A"),
                'jwt_token': jwt_token,
                'name': account_data["name"],
                'password': account_data["password"],
                'date_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'region': "BLACK_Apis" if is_ghost else region,
                'thread_id': account_data.get('thread_id', 'N/A')
            }
            
            file_lock = get_file_lock(token_filename)
            with file_lock:
                tokens_list = []
                if os.path.exists(token_filename):
                    try:
                        with open(token_filename, 'r', encoding='utf-8') as f:
                            tokens_list = json.load(f)
                    except (json.JSONDecodeError, IOError):
                        tokens_list = []
                
                existing_account_ids = [token.get('account_id') for token in tokens_list]
                if account_data.get("account_id", "N/A") not in existing_account_ids:
                    tokens_list.append(token_entry)
                    
                    temp_filename = token_filename + '.tmp'
                    with open(temp_filename, 'w', encoding='utf-8') as f:
                        json.dump(tokens_list, f, indent=2, ensure_ascii=False)
                    
                    os.replace(temp_filename, token_filename)
                    return True
                else:
                    return False
            
        except Exception as e:
            logger.error(f"Error saving JWT token: {e}")
            return False
    
    def generate_single_account(self, region, account_name, password_prefix, thread_id=1, is_ghost=False):
        if not self.running:
            return None
        
        account_result = self
            
        account_result = self.create_acc(region, account_name, password_prefix, is_ghost)
        if not account_result:
            return None

        account_id = account_result.get("account_id", "N/A")
        jwt_token = account_result.get("jwt_token", "")
        
        account_result['thread_id'] = thread_id

        with self.lock:
            self.success_counter += 1
            current_count = self.success_counter

        # Check for rarity
        is_rare, rarity_type, rarity_reason, rarity_score = self.check_account_rarity(account_result)
        if is_rare:
            with self.lock:
                self.rare_counter += 1
            self.save_rare_account(account_result, rarity_type, rarity_reason, rarity_score, is_ghost)
        
        # Check for couples
        is_couple, couple_reason, partner_data = self.check_account_couples(account_result, thread_id)
        if is_couple and partner_data:
            with self.lock:
                self.couples_counter += 1
            self.save_couples_account(account_result, partner_data, couple_reason, is_ghost)
        
        # Save account
        if is_ghost:
            self.save_normal_account(account_result, "GHOST", is_ghost=True)
            if jwt_token:
                self.save_jwt_token(account_result, jwt_token, "GHOST", is_ghost=True)
        else:
            self.save_normal_account(account_result, region)
            if jwt_token:
                self.save_jwt_token(account_result, jwt_token, region)
        
        return {
            "account": account_result,
            "is_rare": is_rare,
            "rarity_type": rarity_type,
            "rarity_reason": rarity_reason,
            "rarity_score": rarity_score,
            "is_couple": is_couple,
            "couple_reason": couple_reason,
            "count": current_count
        }
    
    def start_generation(self, region, account_name, password_prefix, total_accounts, is_ghost=False):
        self.running = True
        self.success_counter = 0
        self.rare_counter = 0
        self.couples_counter = 0
        
        accounts = []
        rare_accounts = []
        couple_pairs = []
        
        for i in range(total_accounts):
            if not self.running:
                break
                
            result = self.generate_single_account(region, account_name, password_prefix, 1, is_ghost)
            if result:
                accounts.append(result)
                
                if result["is_rare"]:
                    rare_accounts.append(result)
                
                if result["is_couple"]:
                    couple_pairs.append(result)
            
            time.sleep(random.uniform(0.5, 1.5))
        
        return {
            "total_accounts": len(accounts),
            "rare_accounts": len(rare_accounts),
            "couple_pairs": len(couple_pairs),
            "accounts": accounts,
            "rare_accounts_list": rare_accounts,
            "couple_pairs_list": couple_pairs
        }
    
    def stop_generation(self):
        self.running = False

# Initialize generator
generator = FreeFireRareAccountGenerator()

# Bot handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Send welcome message and show region selection."""
    user_id = update.effective_user.id
    
    # Check if user is admin
    if user_id not in ADMIN_IDS:
        await update.message.reply_text(
            "❌ Sorry, this bot is private and only available to authorized users."
        )
        return ConversationHandler.END
    
    # Create keyboard with regions
    keyboard = []
    regions = list(REGION_LANG.keys())
    
    # Create buttons in rows of 3
    for i in range(0, len(regions), 3):
        row = []
        for j in range(3):
            if i + j < len(regions):
                region = regions[i + j]
                row.append(InlineKeyboardButton(
                    f"{region} ({REGION_LANG[region]})",
                    callback_data=f"region_{region}"
                ))
        keyboard.append(row)
    
    # Add GHOST mode and Cancel buttons
    keyboard.append([
        InlineKeyboardButton("👻 GHOST Mode", callback_data="region_GHOST"),
        InlineKeyboardButton("❌ Cancel", callback_data="cancel")
    ])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "🎮 *Free Fire RARE Account Generator*\n\n"
        "*Select a region:*\n"
        "────────────────────\n"
        "✨ *Features:*\n"
        "• Generate rare guest accounts\n"
        "• Find special patterns\n"
        "• Detect couples accounts\n"
        "• Automatic JWT tokens\n"
        "• Multi-threaded\n\n"
        "*Click a region to continue:*",
        parse_mode='Markdown',
        reply_markup=reply_markup
    )
    
    return SELECTING_REGION

async def region_selected(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle region selection."""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    data = query.data
    
    if data == "cancel":
        await query.edit_message_text("❌ Operation cancelled.")
        return ConversationHandler.END
    
    if data.startswith("region_"):
        region = data.replace("region_", "")
        
        # Store region in user session
        if user_id not in user_sessions:
            user_sessions[user_id] = {}
        user_sessions[user_id]['region'] = region
        
        # Ask for account count
        await query.edit_message_text(
            f"✅ *Region Selected:* {region}\n\n"
            f"📝 *How many accounts do you want to generate?*\n"
            f"────────────────────\n"
            f"• Enter a number between 1 and 100\n"
            f"• More accounts = higher chance of finding rare ones\n"
            f"• Recommended: 10-50",
            parse_mode='Markdown'
        )
        
        return ENTERING_COUNT

async def get_account_count(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Get number of accounts to generate."""
    user_id = update.effective_user.id
    text = update.message.text
    
    try:
        count = int(text)
        if 1 <= count <= 1000:
            user_sessions[user_id]['count'] = count
            
            await update.message.reply_text(
                f"✅ *Accounts to generate:* {count}\n\n"
                f"⭐ *Enter rarity threshold (1-10):*\n"
                f"────────────────────\n"
                f"• Higher = more strict rare detection\n"
                f"• Lower = more accounts marked as rare\n"
                f"• Recommended: 3",
                parse_mode='Markdown'
            )
            
            return ENTERING_THRESHOLD
        else:
            await update.message.reply_text(
                "❌ Please enter a number between 1 and 1000."
            )
            return ENTERING_COUNT
    except ValueError:
        await update.message.reply_text("❌ Please enter a valid number.")
        return ENTERING_COUNT

async def get_rarity_threshold(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Get rarity threshold."""
    user_id = update.effective_user.id
    text = update.message.text
    
    try:
        threshold = int(text)
        if 1 <= threshold <= 10:
            global RARITY_SCORE_THRESHOLD
            RARITY_SCORE_THRESHOLD = threshold
            user_sessions[user_id]['threshold'] = threshold
            
            # FIXED: Remove Markdown or simplify the message
            await update.message.reply_text(
                f"✅ Rarity threshold: {threshold}\n\n"
                f"👤 Enter account name prefix:\n"
                f"────────────────────\n"
                f"• This will be the base name\n"
                f"• Random suffix will be added\n"
                f"• Example: BLACK_Apis"
                # Removed parse_mode='Markdown' to avoid parsing errors
            )
            
            return ENTERING_NAME
        else:
            await update.message.reply_text(
                "❌ Please enter a number between 1 and 10."
            )
            return ENTERING_THRESHOLD
    except ValueError:
        await update.message.reply_text("❌ Please enter a valid number.")
        return ENTERING_THRESHOLD

async def get_account_name(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Get account name prefix."""
    user_id = update.effective_user.id
    name = update.message.text.strip()
    
    if name:
        user_sessions[user_id]['name'] = name
        
        # FIXED: Send without Markdown at all
        await update.message.reply_text(
            f"✅ Name prefix: {name}\n\n"
            f"🔑 Enter password prefix:\n"
            f"────────────────────\n"
            f"• This will be the password base\n"
            f"• Random characters will be added\n"
            f"• Example: FF2024"
            # Completely removed parse_mode parameter
        )
        
        return ENTERING_PASSWORD
    else:
        await update.message.reply_text("❌ Please enter a valid name.")
        return ENTERING_NAME

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Get password prefix and start generation."""
    user_id = update.effective_user.id
    password = update.message.text.strip()
    
    if not password:
        await update.message.reply_text("❌ Please enter a valid password prefix.")
        return ENTERING_PASSWORD
    
    user_sessions[user_id]['password'] = password
    
    # Get all user data
    region = user_sessions[user_id].get('region')
    count = user_sessions[user_id].get('count')
    name = user_sessions[user_id].get('name')
    threshold = user_sessions[user_id].get('threshold', 3)
    
    # Send confirmation
    confirm_keyboard = [
        [
            InlineKeyboardButton("✅ Start Generation", callback_data="start_gen"),
            InlineKeyboardButton("❌ Cancel", callback_data="cancel_gen")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(confirm_keyboard)
    
    if region == "GHOST":
        region_display = "👻 GHOST MODE"
    else:
        region_display = f"{region} ({REGION_LANG.get(region, 'en')})"
    
    try:
        await update.message.reply_text(
            f"📋 *Generation Settings*\n"
            f"────────────────────\n"
            f"• *Region:* {region_display}\n"
            f"• *Accounts:* {count}\n"
            f"• *Rarity Threshold:* {threshold}+\n"
            f"• *Name Prefix:* {name}\n"
            f"• *Password Prefix:* {password}\n\n"
            f"*Click 'Start Generation' to begin:*",
            reply_markup=reply_markup
        )
    except Exception as e:
        # If Markdown fails, send without Markdown
        await update.message.reply_text(
            f"📋 Generation Settings\n"
            f"────────────────────\n"
            f"• Region: {region_display}\n"
            f"• Accounts: {count}\n"
            f"• Rarity Threshold: {threshold}+\n"
            f"• Name Prefix: {name}\n"
            f"• Password Prefix: {password}\n\n"
            f"Click 'Start Generation' to begin:",
            reply_markup=reply_markup
        )
    
    return SELECTING_OPTION

async def handle_confirmation(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle confirmation to start generation."""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    
    if query.data == "cancel_gen":
        await query.edit_message_text("❌ Generation cancelled.")
        return ConversationHandler.END
    
    if query.data == "start_gen":
        # Get user session data
        region = user_sessions[user_id].get('region')
        count = user_sessions[user_id].get('count')
        name = user_sessions[user_id].get('name')
        password = user_sessions[user_id].get('password')
        
        is_ghost = (region == "GHOST")
        if is_ghost:
            region = "BR"  # GHOST mode uses BR region
        
        # Store task info
        task_id = f"{user_id}_{int(time.time())}"
        generation_tasks[task_id] = {
            'user_id': user_id,
            'chat_id': query.message.chat_id,
            'message_id': query.message.message_id,
            'region': region,
            'count': count,
            'name': name,
            'password': password,
            'is_ghost': is_ghost,
            'status': 'running',
            'start_time': time.time(),
            'generated': 0,
            'rare_found': 0,
            'couples_found': 0
        }
        
        # Start generation in background
        asyncio.create_task(run_generation(task_id, context))
        
        await query.edit_message_text(
            f"🚀 *Generation Started!*\n\n"
            f"⏳ *Status:* Running\n"
            f"📊 *Progress:* 0/{count}\n"
            f"💎 *Rare Found:* 0\n"
            f"💑 *Couples Found:* 0\n\n"
            f"🔄 Generating accounts..."
        )
        
        return ConversationHandler.END

async def run_generation(task_id: str, context: ContextTypes.DEFAULT_TYPE):
    """Run account generation in background."""
    task = generation_tasks.get(task_id)
    if not task:
        return
    
    user_id = task['user_id']
    chat_id = task['chat_id']
    message_id = task['message_id']
    
    region = task['region']
    count = task['count']
    name = task['name']
    password = task['password']
    is_ghost = task['is_ghost']
    
    try:
        # Start generation
        generator.running = True
        generator.success_counter = 0
        generator.rare_counter = 0
        generator.couples_counter = 0
        
        i = 0
        while i < count and generator.running:
            i += 1
            
            try:
                # Generate account
                result = generator.generate_single_account(region, name, password, 1, is_ghost)
                
                if result:
                    # Update task stats
                    task['generated'] = generator.success_counter
                    task['rare_found'] = generator.rare_counter
                    task['couples_found'] = generator.couples_counter
                    
                    # Update progress message every 5 accounts
                    if generator.success_counter % 5 == 0 or generator.success_counter == 1:
                        progress = (generator.success_counter / count) * 100
                        try:
                            await context.bot.edit_message_text(
                                chat_id=chat_id,
                                message_id=message_id,
                                text=f"🚀 Generation Running\n\n"
                                     f"⏳ Status: Active\n"
                                     f"📊 Progress: {generator.success_counter}/{count} ({progress:.1f}%)\n"
                                     f"💎 Rare Found: {generator.rare_counter}\n"
                                     f"💑 Couples Found: {generator.couples_counter}\n\n"
                                     f"🔄 Generating accounts..."
                            )
                        except:
                            pass
                    
                    # If account is rare, send notification
                    if result["is_rare"]:
                        rare_msg = (
                            f"💎 RARE ACCOUNT FOUND!\n"
                            f"────────────────────\n"
                            f"• Type: {result['rarity_type']}\n"
                            f"• Score: {result['rarity_score']}\n"
                            f"• Name: {result['account']['name']}\n"
                            f"• UID: {result['account']['uid']}\n"
                            f"• Account ID: {result['account'].get('account_id', 'N/A')}\n"
                            f"• Password: {result['account']['password']}\n"
                            f"• Region: {result['account']['region']}\n"
                            f"• Reason: {result['rarity_reason']}\n\n"
                            f"📁 Saved to rare accounts folder"
                        )
                        await context.bot.send_message(chat_id=chat_id, text=rare_msg)
                    
                    # If couple found, send notification
                    if result["is_couple"]:
                        couple_msg = (
                            f"💑 COUPLES ACCOUNT FOUND!\n"
                            f"────────────────────\n"
                            f"• Reason: {result['couple_reason']}\n"
                            f"• Account 1: {result['account']['name']} (ID: {result['account'].get('account_id', 'N/A')})\n"
                            f"• Account 2: Matched with partner\n"
                            f"• UIDs: {result['account']['uid']} & partner\n\n"
                            f"📁 Saved to couples folder"
                        )
                        await context.bot.send_message(chat_id=chat_id, text=couple_msg)
                    
                    # Send EVERY account immediately
                    account_msg = (
                        f"✅ Account #{generator.success_counter}\n"
                        f"────────────────────\n"
                        f"• Name: {result['account']['name']}\n"
                        f"• UID: {result['account']['uid']}\n"
                        f"• Account ID: {result['account'].get('account_id', 'N/A')}\n"
                        f"• Password: {result['account']['password']}\n"
                        f"• Region: {result['account']['region']}\n"
                        f"• Status: {'💎 RARE' if result['is_rare'] else '✅ Normal'}"
                    )
                    await context.bot.send_message(chat_id=chat_id, text=account_msg)
                else:
                    # Account generation failed, retry with same i
                    logger.warning(f"Account generation failed for attempt {i}")
                    i -= 1  # Don't count this attempt
                
            except Exception as e:
                logger.error(f"Error generating account #{i}: {e}")
                # Continue with next account instead of stopping
                continue
            
            # Small delay
            await asyncio.sleep(random.uniform(0.5, 1.5))
        
        # Generation complete
        task['status'] = 'completed'
        generator.stop_generation()
        
        # Send summary
        elapsed_time = time.time() - task['start_time']
        speed = task['generated'] / elapsed_time if elapsed_time > 0 else 0
        
        summary_text = (
            f"🎉 Generation Complete!\n"
            f"────────────────────\n"
            f"• Requested: {count} account(s)\n"
            f"• Generated: {task['generated']} account(s)\n"
            f"• Rare Found: {task['rare_found']}\n"
            f"• Couples Found: {task['couples_found']}\n"
            f"• Rarity Threshold: {RARITY_SCORE_THRESHOLD}+\n"
            f"• Time Taken: {elapsed_time:.2f} seconds\n"
            f"• Speed: {speed:.2f} accounts/second\n\n"
            f"📁 Files Saved:\n"
        )
        
        if is_ghost:
            summary_text += f"• GHOST Accounts: {GHOST_ACCOUNTS_FOLDER}\n"
            summary_text += f"• Rare GHOST: {GHOST_RARE_FOLDER}\n"
            summary_text += f"• Couples GHOST: {GHOST_COUPLES_FOLDER}\n"
        else:
            summary_text += f"• Accounts: {ACCOUNTS_FOLDER}\n"
            summary_text += f"• Rare Accounts: {RARE_ACCOUNTS_FOLDER}\n"
            summary_text += f"• Couples Accounts: {COUPLES_ACCOUNTS_FOLDER}\n"
            summary_text += f"• JWT Tokens: {TOKENS_FOLDER}\n"
        
        # Create summary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(f"Free Fire Account Generation Summary\n")
            f.write(f"=" * 50 + "\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Region: {region}\n")
            f.write(f"Accounts Generated: {task['generated']}/{count}\n")
            f.write(f"Rare Accounts Found: {task['rare_found']}\n")
            f.write(f"Couples Found: {task['couples_found']}\n")
            f.write(f"Time Taken: {elapsed_time:.2f} seconds\n")
            f.write(f"=" * 50 + "\n\n")
            temp_file = f.name
        
        try:
            with open(temp_file, 'rb') as f:
                await context.bot.send_document(
                    chat_id=chat_id,
                    document=f,
                    filename=f"generation_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    caption="📄 Generation summary"
                )
        except:
            pass
        
        # Clean up
        os.unlink(temp_file)
        
        await context.bot.send_message(
            chat_id=chat_id,
            text=summary_text
        )
        
        # Clear user session
        if user_id in user_sessions:
            del user_sessions[user_id]
        
        # Remove task
        if task_id in generation_tasks:
            del generation_tasks[task_id]
            
    except Exception as e:
        logger.error(f"Generation error: {e}")
        task['status'] = 'error'
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"❌ Generation Error:\n{str(e)}"
        )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancel the conversation."""
    user_id = update.effective_user.id
    if user_id in user_sessions:
        del user_sessions[user_id]
    
    # Stop any running generation
    generator.stop_generation()
    
    await update.message.reply_text("❌ Operation cancelled.")
    return ConversationHandler.END

async def stop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stop current generation."""
    user_id = update.effective_user.id
    
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("❌ Sorry, this bot is private.")
        return
    
    generator.stop_generation()
    
    # Find and stop user's task
    for task_id, task in list(generation_tasks.items()):
        if task['user_id'] == user_id and task['status'] == 'running':
            task['status'] = 'stopped'
            await context.bot.send_message(
                chat_id=task['chat_id'],
                text="🛑 Generation stopped by user."
            )
    
    await update.message.reply_text("🛑 Generation stopped.")

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show statistics."""
    user_id = update.effective_user.id
    
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("❌ Sorry, this bot is private.")
        return
    
    # Count total accounts
    total_accounts = 0
    total_rare = 0
    total_couples = 0
    
    # Count normal accounts
    if os.path.exists(ACCOUNTS_FOLDER):
        for file in os.listdir(ACCOUNTS_FOLDER):
            if file.endswith('.json'):
                file_path = os.path.join(ACCOUNTS_FOLDER, file)
                try:
                    with open(file_path, 'r') as f:
                        accounts = json.load(f)
                        total_accounts += len(accounts)
                except:
                    continue
    
    # Count rare accounts
    if os.path.exists(RARE_ACCOUNTS_FOLDER):
        for file in os.listdir(RARE_ACCOUNTS_FOLDER):
            if file.endswith('.json'):
                file_path = os.path.join(RARE_ACCOUNTS_FOLDER, file)
                try:
                    with open(file_path, 'r') as f:
                        accounts = json.load(f)
                        total_rare += len(accounts)
                except:
                    continue
    
    # Count couples
    if os.path.exists(COUPLES_ACCOUNTS_FOLDER):
        for file in os.listdir(COUPLES_ACCOUNTS_FOLDER):
            if file.endswith('.json'):
                file_path = os.path.join(COUPLES_ACCOUNTS_FOLDER, file)
                try:
                    with open(file_path, 'r') as f:
                        couples = json.load(f)
                        total_couples += len(couples)
                except:
                    continue
    
    # Count GHOST accounts
    ghost_file = os.path.join(GHOST_ACCOUNTS_FOLDER, "ghost.json")
    if os.path.exists(ghost_file):
        try:
            with open(ghost_file, 'r') as f:
                accounts = json.load(f)
                total_accounts += len(accounts)
        except:
            pass
    
    stats_text = (
        f"📊 *Bot Statistics*\n"
        f"────────────────────\n"
        f"• *Total Accounts Generated:* {total_accounts}\n"
        f"• *Rare Accounts Found:* {total_rare}\n"
        f"• *Couples Pairs Found:* {total_couples}\n"
        f"• *Available Regions:* {len(REGION_LANG)}\n"
        f"• *Current Rarity Threshold:* {RARITY_SCORE_THRESHOLD}+\n\n"
        f"📁 *Storage Folders:*\n"
        f"• Accounts: `{ACCOUNTS_FOLDER}`\n"
        f"• Rare: `{RARE_ACCOUNTS_FOLDER}`\n"
        f"• Couples: `{COUPLES_ACCOUNTS_FOLDER}`\n"
        f"• Tokens: `{TOKENS_FOLDER}`\n"
        f"• GHOST: `{GHOST_FOLDER}`\n\n"
        f"🤖 *Active Tasks:* {len([t for t in generation_tasks.values() if t['status'] == 'running'])}"
    )
    
    await update.message.reply_text(stats_text, parse_mode='Markdown')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send help message."""
    help_text = (
        "🎮 *Free Fire RARE Account Generator Bot*\n\n"
        "*Commands:*\n"
        "`/start` - Start rare account generation\n"
        "`/stop` - Stop current generation\n"
        "`/stats` - Show generation statistics\n"
        "`/help` - Show this help message\n"
        "`/cancel` - Cancel current operation\n\n"
        "*✨ Features:*\n"
        "• Generate Free Fire guest accounts\n"
        "• Detect rare account patterns\n"
        "• Find couples accounts\n"
        "• Multiple regions + GHOST mode\n"
        "• Automatic JWT token generation\n"
        "• Thread-safe file operations\n\n"
        "*🔍 Rarity Patterns Detected:*\n"
        "• Repeated digits (1111, 2222)\n"
        "• Sequential numbers (12345)\n"
        "• Palindromes (123321)\n"
        "• Special numbers (69, 420, 1337)\n"
        "• Mirror patterns (123123)\n"
        "• Low account IDs\n"
        "• And many more...\n\n"
        "⚠️ *Disclaimer:* For educational purposes only."
    )
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def view_rare_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """View rare accounts."""
    user_id = update.effective_user.id
    
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("❌ Sorry, this bot is private.")
        return
    
    rare_accounts = []
    
    # Get rare accounts from all regions
    if os.path.exists(RARE_ACCOUNTS_FOLDER):
        for file in os.listdir(RARE_ACCOUNTS_FOLDER):
            if file.endswith('.json'):
                file_path = os.path.join(RARE_ACCOUNTS_FOLDER, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        accounts = json.load(f)
                        rare_accounts.extend(accounts)
                except:
                    continue
    
    # Get GHOST rare accounts
    ghost_rare_file = os.path.join(GHOST_RARE_FOLDER, "rare-ghost.json")
    if os.path.exists(ghost_rare_file):
        try:
            with open(ghost_rare_file, 'r', encoding='utf-8') as f:
                accounts = json.load(f)
                rare_accounts.extend(accounts)
        except:
            pass
    
    if not rare_accounts:
        await update.message.reply_text("📭 No rare accounts found yet.")
        return
    
    # Display first 5 rare accounts
    display_text = "💎 *Rare Accounts Found:*\n────────────────────\n\n"
    
    for i, acc in enumerate(rare_accounts[:5], 1):
        display_text += (
            f"*Account #{i}*\n"
            f"• *Name:* `{acc.get('name', 'N/A')}`\n"
            f"• *UID:* `{acc.get('uid', 'N/A')}`\n"
            f"• *Account ID:* `{acc.get('account_id', 'N/A')}`\n"
            f"• *Region:* {acc.get('region', 'N/A')}\n"
            f"• *Rarity Score:* {acc.get('rarity_score', 0)}\n"
            f"• *Type:* {acc.get('rarity_type', 'N/A')}\n"
            f"• *Reason:* {acc.get('reason', 'N/A')[:50]}...\n"
            f"────────────────────\n"
        )
    
    display_text += f"\n*Total Rare Accounts:* {len(rare_accounts)}"
    
    await update.message.reply_text(display_text, parse_mode='Markdown')
    
    # Send rare accounts file if requested
    if context.args and context.args[0] == "file":
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(rare_accounts, f, indent=2, ensure_ascii=False)
            temp_file = f.name
        
        try:
            with open(temp_file, 'rb') as f:
                await update.message.reply_document(
                    document=f,
                    filename="rare_accounts.json",
                    caption="📁 All rare accounts"
                )
        except:
            pass
        
        os.unlink(temp_file)

def main() -> None:
    """Start the bot."""
    # Create Application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Conversation handler for account generation
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            SELECTING_REGION: [CallbackQueryHandler(region_selected)],
            ENTERING_COUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_account_count)],
            ENTERING_THRESHOLD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_rarity_threshold)],
            ENTERING_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_account_name)],
            ENTERING_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
            SELECTING_OPTION: [CallbackQueryHandler(handle_confirmation)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    
    # Add handlers
    application.add_handler(conv_handler)
    application.add_handler(CommandHandler("stop", stop_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("rare", view_rare_command))
    application.add_handler(CommandHandler("cancel", cancel))
    
    # Start the bot
    print("🤖 Free Fire RARE Account Generator Bot")
    print("=======================================")
    print(f"📁 Base Folder: {BASE_FOLDER}")
    print(f"📊 Accounts: {ACCOUNTS_FOLDER}")
    print(f"💎 Rare: {RARE_ACCOUNTS_FOLDER}")
    print(f"💑 Couples: {COUPLES_ACCOUNTS_FOLDER}")
    print(f"🔐 Tokens: {TOKENS_FOLDER}")
    print(f"👻 GHOST: {GHOST_FOLDER}")
    print("🤖 Bot is starting...")
    
    application.run_polling()

if __name__ == '__main__':
    main()
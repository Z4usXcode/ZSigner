
import hashlib
import base64
import time
import random
import string
import urllib.parse

class XBogus:
    STANDARD_B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    CUSTOM_B64_ALPHABET   = 'Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe'
    ENC_TRANS = {s: c for s, c in zip(STANDARD_B64_ALPHABET, CUSTOM_B64_ALPHABET)}
    
    @staticmethod
    def custom_b64_encode(buf: bytes) -> str:
        b64 = base64.b64encode(buf).decode('ascii')
        return ''.join(XBogus.ENC_TRANS.get(ch, ch) for ch in b64)

    @staticmethod
    def std_md5_enc(data: bytes) -> bytes:
        return hashlib.md5(data).digest()

    @staticmethod
    def rc4_enc(key: bytes, plaintext: bytes) -> bytes:
        s = list(range(256))
        j = 0
        key_len = len(key)
        for i in range(256):
            j = (j + s[i] + key[i % key_len]) & 0xFF
            s[i], s[j] = s[j], s[i]

        out = bytearray(len(plaintext))    
        i = j = 0    
        for n in range(len(plaintext)):    
            i = (i + 1) & 0xFF    
            j = (j + s[i]) & 0xFF    
            s[i], s[j] = s[j], s[i]    
            k = s[(s[i] + s[j]) & 0xFF]    
            out[n] = plaintext[n] ^ k    
        return bytes(out)

    @staticmethod
    def xor_key(buf: bytes) -> int:
        acc = 0
        for b in buf:
            acc ^= b
        return acc

    @staticmethod
    def encrypt(params: str, post_data: str, user_agent: str, timestamp: int) -> str:
        ua_key   = bytes([0x00, 0x01, 0x0e])
        list_key = bytes([0xff])
        fixed_val = 0x4a41279f

        md5_params = XBogus.std_md5_enc(XBogus.std_md5_enc(params.encode('utf-8')))    
        md5_post   = XBogus.std_md5_enc(XBogus.std_md5_enc(post_data.encode('utf-8')))    

        ua_rc4 = XBogus.rc4_enc(ua_key, user_agent.encode('utf-8'))    
        ua_b64 = base64.b64encode(ua_rc4)    
        md5_ua = XBogus.std_md5_enc(ua_b64)    

        parts = [    
            bytes([0x40]),        
            ua_key,    
            md5_params[14:16],    
            md5_post[14:16],    
            md5_ua[14:16],    
            timestamp.to_bytes(4, 'big'),    
            fixed_val.to_bytes(4, 'big'),    
        ]    
        buffer = b''.join(parts)  
        checksum = XBogus.xor_key(buffer)    
        buffer += bytes([checksum]) 

        enc = bytes([0x02]) + list_key + XBogus.rc4_enc(list_key, buffer)    
        return XBogus.custom_b64_encode(enc)

class XGnarly:
    aa = [
        0xFFFFFFFF, 138, 1498001188, 211147047, 253, None, 203, 288, 9,
        1196819126, 3212677781, 135, 263, 193, 58, 18, 244, 2931180889, 240, 173,
        268, 2157053261, 261, 175, 14, 5, 171, 270, 156, 258, 13, 15, 3732962506,
        185, 169, 2, 6, 132, 162, 200, 3, 160, 217618912, 62, 2517678443, 44, 164,
        4, 96, 183, 2903579748, 3863347763, 119, 181, 10, 190, 8, 2654435769, 259,
        104, 230, 128, 2633865432, 225, 1, 257, 143, 179, 16, 600974999, 185100057,
        32, 188, 53, 2718276124, 177, 196, 4294967296, 147, 117, 17, 49, 7, 28, 12,
        266, 216, 11, 0, 45, 166, 247, 1451689750,
    ]

    MASK32 = 0xFFFFFFFF

    def init(self):
        self.Ot = [self.aa[9], self.aa[69], self.aa[51], self.aa[92]]
        self.kt = self.init_prng_state()
        self.St = self.aa[88]

    def init_prng_state(self):
        now_ms = int(time.time() * 1000)
        return [
            self.aa[44],
            self.aa[74],
            self.aa[10],
            self.aa[62],
            self.aa[42],
            self.aa[17],
            self.aa[2],
            self.aa[21],
            self.aa[3],
            self.aa[70],
            self.aa[50],
            self.aa[32],
            self.aa[0] & now_ms,
            random.randint(0, 246),
            random.randint(0, 246),
            random.randint(0, 246),
        ]

    def u32(self, x):
        return x & self.MASK32

    def rotl(self, x, n):
        return self.u32((x << n) | (x >> (32 - n)))

    def quarter(self, st, a, b, c, d):
        st[a] = self.u32(st[a] + st[b])
        st[d] = self.rotl(st[d] ^ st[a], 16)
        st[c] = self.u32(st[c] + st[d])
        st[b] = self.rotl(st[b] ^ st[c], 12)
        st[a] = self.u32(st[a] + st[b])
        st[d] = self.rotl(st[d] ^ st[a], 8)
        st[c] = self.u32(st[c] + st[d])
        st[b] = self.rotl(st[b] ^ st[c], 7)

    def chacha_block(self, state, rounds):
        w = state.copy()
        r = 0
        while r < rounds:
            self.quarter(w, 0, 4, 8, 12)
            self.quarter(w, 1, 5, 9, 13)
            self.quarter(w, 2, 6, 10, 14)
            self.quarter(w, 3, 7, 11, 15)
            r += 1
            if r >= rounds:
                break
            self.quarter(w, 0, 5, 10, 15)
            self.quarter(w, 1, 6, 11, 12)
            self.quarter(w, 2, 7, 12, 13)
            self.quarter(w, 3, 4, 13, 14)
            r += 1
        for i in range(16):
            w[i] = self.u32(w[i] + state[i])
        return w

    def bump_counter(self, st):
        st[12] = self.u32(st[12] + 1)

    def rand(self):
        e = self.chacha_block(self.kt, 8)
        t = e[self.St]
        r = (e[self.St + 8] & 0xFFFFFFF0) >> 11
        if self.St == 7:
            self.bump_counter(self.kt)
            self.St = 0
        else:
            self.St += 1
        return (t + 4294967296 * r) / (2 ** 53)

    def num_to_bytes(self, val):
        if val < 255*255:
            return [(val >> 8) & 0xFF, val & 0xFF]
        else:
            return [(val >> 24) & 0xFF, (val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF]

    def be_int_from_str(self, s):
        if not s:
            return 0
        buf = s.encode('utf-8')[:4]
        acc = 0
        for b in buf:
            acc = (acc << 8) | b
        return acc & self.MASK32

    def encrypt_chacha(self, key_words, rounds, data_bytes):
        n_full = len(data_bytes) // 4
        leftover = len(data_bytes) % 4
        words = []
        for i in range(n_full):
            j = i * 4
            word = data_bytes[j] | (data_bytes[j+1]<<8) | (data_bytes[j+2]<<16) | (data_bytes[j+3]<<24)
            words.append(word & self.MASK32)
        if leftover:
            v = 0
            base = 4 * n_full
            for c in range(leftover):
                v |= data_bytes[base+c] << (8*c)
            words.append(v & self.MASK32)

        o = 0    
        state = key_words.copy()    
        while o + 16 < len(words):    
            stream = self.chacha_block(state, rounds)    
            self.bump_counter(state)    
            for k in range(16):    
                words[o+k] ^= stream[k]    
            o += 16    
        remain = len(words) - o    
        if remain > 0:    
            stream = self.chacha_block(state, rounds)    
            for k in range(remain):    
                words[o+k] ^= stream[k]    
        
        result_bytes = bytearray(len(data_bytes))    
        for i in range(n_full):    
            w = words[i]    
            j = 4*i    
            result_bytes[j] = w & 0xFF    
            result_bytes[j+1] = (w >> 8) & 0xFF    
            result_bytes[j+2] = (w >> 16) & 0xFF    
            result_bytes[j+3] = (w >> 24) & 0xFF    
        if leftover:    
            w = words[n_full]    
            base = 4*n_full    
            for c in range(leftover):    
                result_bytes[base+c] = (w >> (8*c)) & 0xFF    
        return result_bytes

    def ab22(self, key12_words, rounds, s):
        state = self.Ot + key12_words
        data = bytearray(s.encode('utf-8'))
        enc = self.encrypt_chacha(state, rounds, data)
        return enc.decode('latin-1')

    def encrypt_auto(self, query_string, payload, user_agent, envcode=0, version='5.1.1', timestamp_ms=None):
        if timestamp_ms is None:
            timestamp_ms = int(time.time() * 1000)
        obj = {}
        obj[1] = 1
        obj[2] = envcode
        obj[3] = hashlib.md5(query_string.encode('utf-8')).hexdigest()
        obj[4] = hashlib.md5(payload.encode('utf-8')).hexdigest()
        obj[5] = hashlib.md5(user_agent.encode('utf-8')).hexdigest()
        obj[6] = timestamp_ms // 1000
        obj[7] = 1508145731
        obj[8] = int((timestamp_ms*1000) % 2147483648)
        obj[9] = version

        if version == '5.1.1':    
            obj[10] = '1.0.0.314'    
            obj[11] = 1    
            v12 = 0    
            for i in range(1, 12):    
                v = obj[i]    
                to_xor = v if isinstance(v, int) else self.be_int_from_str(v)    
                v12 ^= to_xor    
            obj[12] = v12 & self.MASK32    
        elif version != '5.1.0':    
            raise ValueError(f"Unsupported version: {version}")    

        v0 = 0    
        for i in range(1, len(obj)+1):    
            v = obj[i]    
            if isinstance(v, int):    
                v0 ^= v    
        obj[0] = v0 & self.MASK32    

        payload_bytes = bytearray()    
        payload_bytes.append(len(obj))    
        for k in sorted(obj.keys()):    
            payload_bytes.append(k)    
            v = obj[k]    
            if isinstance(v, int):    
                val_bytes = self.num_to_bytes(v)    
            else:    
                val_bytes = list(v.encode('utf-8'))    
            payload_bytes.extend(self.num_to_bytes(len(val_bytes)))    
            payload_bytes.extend(val_bytes)    
        
        base_str = ''.join(chr(b) for b in payload_bytes)    
        
        key_words = []    
        key_bytes = []    
        round_accum = 0    
        for i in range(12):    
            rnd = self.rand()    
            word = int(rnd * 4294967296) & self.MASK32    
            key_words.append(word)    
            round_accum = (round_accum + (word & 15)) & 15    
            key_bytes.extend([word & 0xFF, (word>>8)&0xFF, (word>>16)&0xFF, (word>>24)&0xFF])    
        rounds = round_accum + 5    

        enc = self.ab22(key_words, rounds, base_str)    

        insert_pos = 0    
        for b in key_bytes:    
            insert_pos = (insert_pos + b) % (len(enc)+1)    
        for ch in enc:    
            insert_pos = (insert_pos + ord(ch)) % (len(enc)+1)    

        key_bytes_str = ''.join(chr(b) for b in key_bytes)    
        final_str = chr(((1<<6)^(1<<3)^3)&0xFF) + enc[:insert_pos] + key_bytes_str + enc[insert_pos:]    

        alphabet = 'u09tbS3UvgDEe6r-ZVMXzLpsAohTn7mdINQlW412GqBjfYiyk8JORCF5/xKHwacP='    
        out = []    
        full_len = (len(final_str)//3)*3    
        for i in range(0, full_len, 3):    
            block = (ord(final_str[i])<<16) | (ord(final_str[i+1])<<8) | ord(final_str[i+2])    
            out.append(alphabet[(block>>18)&63])    
            out.append(alphabet[(block>>12)&63])    
            out.append(alphabet[(block>>6)&63])    
            out.append(alphabet[block&63])    
        return ''.join(out)

class Utils:
    @staticmethod
    def get_random_int(a: int, b: int) -> int:
        min_val = min(a, b)
        max_val = max(a, b)
        diff = max_val - min_val + 1
        return min_val + int(random.random() * diff)

    @staticmethod
    def generate_verify_fp() -> str:
        chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        e = len(chars)
        n = int(time.time() * 1000)
        n36 = format(n, 'x')

        r = [''] * 36    
        r[8] = r[13] = r[18] = r[23] = '_'    
        r[14] = '4'    

        for o in range(36):    
            if not r[o]:    
                i = int(random.random() * e)    
                r[o] = chars[(3 & i) | 8 if o == 19 else i]    

        return f"verify_{n36}_{''.join(r)}"

    @staticmethod
    def generate_device_id() -> str:
        timestamp = str(int(time.time() * 1000))
        random_part = str(random.randint(0, 999999999)).zfill(9)
        return '7' + timestamp[-9:] + random_part

    @staticmethod
    def generate_ms_token() -> str:
        chars = string.ascii_letters + string.digits + "-_"
        return ''.join(random.choice(chars) for _ in range(107))

def sign(params, payload=""):
    if isinstance(params, dict):
        params_str = "&".join([f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items()])
    else:
        params_str = params
        
    if isinstance(payload, dict):
        payload_str = "&".join([f"{k}={urllib.parse.quote(str(v))}" for k, v in payload.items()])
    else:
        payload_str = payload

    user_agent = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36"
    timestamp = int(time.time())

    x_gnarly_obj = XGnarly()
    x_gnarly_obj.init()
    verify_fp = Utils.generate_verify_fp()
    device_id = Utils.generate_device_id()
    iid = Utils.generate_device_id()
    ms_token = Utils.generate_ms_token()
    x_bogus = XBogus.encrypt(params_str, payload_str, user_agent, timestamp)
    x_gnarly = x_gnarly_obj.encrypt_auto(params_str, payload_str, user_agent)

    return {
        "verifyFp": verify_fp,
        "device_id": device_id,
        "iid": iid,
        "msToken": ms_token,
        "X-Bogus": x_bogus,
        "X-Gnarly": x_gnarly,
        "timestamp": timestamp,
        "User-Agent": user_agent
      }

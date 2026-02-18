import numpy as np
import math
import time
import io
import struct
from werkzeug.datastructures import FileStorage

def generate_sbox(u_in=3.9985):
    np.random.seed(42) 
    m = 10000
    x = np.zeros(m)
    x[0] = 0.02
    u = u_in
    x_hex = [float.hex(x[0])]
    
    for i in range(1, m):
        x[i] = u * x[i - 1] * (1 - x[i - 1])
        x_hex.append(float.hex(x[i]))
    
    s, s_b = [], []
    for h in x_hex:
        s.append(h[5] + h[6])
    
    for val in s:
        if len(s_b) < 256 and int(val, 16) not in s_b:
            s_b.append(int(val, 16))
    
    return s_b

def get_inverse_sbox(sbox):
    inv = [0] * 256
    for i in range(256):
        inv[sbox[i]] = i
    return inv

Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
        0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
        0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
        0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
        0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
        0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
        0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
        0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
        0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
        0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
        0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
        0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
        0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
        0xe8, 0xcb]

def getRconValue(num):
    return Rcon[num]

def rotate(word):
    return word[1:] + word[:1]

def core(word, iteration, sbox):
    word = rotate(word)
    for i in range(4):
        word[i] = sbox[word[i]]
    word[0] = word[0] ^ getRconValue(iteration)
    return word

def expandKey(key, sbox, size=16, expandedKeySize=176):
    currentSize = 0
    rconIteration = 1
    expandedKey = [0] * expandedKeySize
    
    for j in range(size):
        expandedKey[j] = key[j]
    
    currentSize += size
    
    while currentSize < expandedKeySize:
        t = expandedKey[currentSize-4:currentSize]
        
        if currentSize % size == 0:
            t = core(t, rconIteration, sbox)
            rconIteration += 1
        
        for m in range(4):
            expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[m]
            currentSize += 1
    
    return expandedKey

def gen_cypherkey(inp):
    ck = [ord(i) for i in inp]
    while len(ck) < 17:
        ck = ck + ck
    return ck[-16:], ck[:-16]

def bit_reverse(i, n):
    return int(format(i, '0%db' % n)[::-1], 2)

def bit_reverse_transposition(s):
    return [bit_reverse(i, 8) for i in s]

def rowShift(s):
    r = s.copy()
    r[4:8] = s[5:8] + s[4:5]
    r[8:12] = s[10:12] + s[8:10]
    r[12:16] = s[15:16] + s[12:15]
    return r

def in_shift_rows(s):
    r = s.copy()
    r[4:8] = s[7:8] + s[4:7]
    r[8:12] = s[10:12] + s[8:10]
    r[12:16] = s[13:16] + s[12:13]
    return r

def convertBytes(data_bytes, start, end):
    ar = [0] * 16
    j = 0
    for i in range(start, min(end, len(data_bytes))):
        ar[j] = data_bytes[i]
        j += 1
    return ar

def add_pkcs7_padding(data):
    padding_length = 16 - (len(data) % 16)
    if padding_length == 0:
        padding_length = 16
    return data + bytes([padding_length] * padding_length)

def remove_pkcs7_padding(data):
    padding_length = data[-1]
    if padding_length > 16 or padding_length == 0:
        return data
    for i in range(padding_length):
        if data[-(i+1)] != padding_length:
            return data
    return data[:-padding_length]

def create_file_header(filename, content_type, file_size):
    filename_bytes = filename.encode('utf-8')
    content_type_bytes = content_type.encode('utf-8')
    
    header = struct.pack('>I', len(filename_bytes))
    header += filename_bytes
    header += struct.pack('>I', len(content_type_bytes))
    header += content_type_bytes
    header += struct.pack('>Q', file_size)
    
    return header

def parse_file_header(data):
    offset = 0
    
    filename_len = struct.unpack('>I', bytes(data[offset:offset+4]))[0]
    offset += 4
    filename = bytes(data[offset:offset+filename_len]).decode('utf-8')
    offset += filename_len
    
    content_type_len = struct.unpack('>I', bytes(data[offset:offset+4]))[0]
    offset += 4
    content_type = bytes(data[offset:offset+content_type_len]).decode('utf-8')
    offset += content_type_len
    
    file_size = struct.unpack('>Q', bytes(data[offset:offset+8]))[0]
    offset += 8
    
    return filename, content_type, file_size, offset

def eeaes_encrypt_bytes(data_bytes, key_str):
    cypherkey, sbox_seed = gen_cypherkey(key_str)
    u = float("3.9" + str(sum(sbox_seed)))
    sbox = generate_sbox(u)
    expanded_key = expandKey(cypherkey, sbox)
    
    result = []
    num_blocks = int(math.ceil(float(len(data_bytes)) / 16))
    
    for j in range(num_blocks):
        start = j * 16
        end = min(j * 16 + 16, len(data_bytes))
        plaintext = convertBytes(data_bytes, start, end)
        
        for l in range(10):
            stage_result = []
            for f in range(16):
                stage_result.append(sbox[plaintext[f] ^ expanded_key[f + (l * 16)]])
            stage_result = rowShift(stage_result)
            stage_result = bit_reverse_transposition(stage_result)
            plaintext = stage_result
        
        final_result = []
        for f in range(16):
            final_result.append(sbox[plaintext[f]])
        final_result = rowShift(final_result)
        
        cipher_text_temp = []
        for f in range(16):
            cipher_text_temp.append(final_result[f] ^ expanded_key[f + 160])
        
        result.extend(cipher_text_temp)
    
    return bytes(result)

def eeaes_decrypt_bytes(cipher_bytes, key_str):
    cypherkey, sbox_seed = gen_cypherkey(key_str)
    u = float("3.9" + str(sum(sbox_seed)))
    sbox = generate_sbox(u)
    inv_sbox = get_inverse_sbox(sbox)
    expanded_key = expandKey(cypherkey, sbox)
    
    result = []
    num_blocks = int(math.ceil(float(len(cipher_bytes)) / 16))
    
    for j in range(num_blocks):
        start = j * 16
        end = min(j * 16 + 16, len(cipher_bytes))
        cipher_block = list(cipher_bytes[start:end])
        
        while len(cipher_block) < 16:
            cipher_block.append(0)
        
        stage_result = []
        for f in range(16):
            stage_result.append(cipher_block[f] ^ expanded_key[f + 160])
        stage_result = in_shift_rows(stage_result)
        
        plaintext = []
        for f in range(16):
            plaintext.append(inv_sbox[stage_result[f]])
        
        for l in range(10):
            plaintext = bit_reverse_transposition(plaintext)
            plaintext = in_shift_rows(plaintext)
            
            stage_result = []
            for f in range(16):
                stage_result.append(inv_sbox[plaintext[f]])
            
            stage_result_t = []
            for f in range(16):
                stage_result_t.append(stage_result[f] ^ expanded_key[f + ((9 - l) * 16)])
            
            plaintext = stage_result_t
        
        result.extend(plaintext)
    
    return bytes(result)

def encrypt_file(file_storage, key_str):
    
    file_storage.stream.seek(0)
    
    file_content = file_storage.read()
    
    filename = file_storage.filename or 'unknown_file'
    content_type = file_storage.content_type or 'application/octet-stream'
    file_size = len(file_content)
    
    header = create_file_header(filename, content_type, file_size)
    
    data_to_encrypt = header + file_content
    
    padded_data = add_pkcs7_padding(data_to_encrypt)
    
    encrypted_data = eeaes_encrypt_bytes(padded_data, key_str)
    
    return encrypted_data

def decrypt_file(encrypted_bytes, key_str):

    if isinstance(encrypted_bytes, list):
        encrypted_bytes = bytes(encrypted_bytes)
    
    decrypted_data = eeaes_decrypt_bytes(encrypted_bytes, key_str)
    
    unpadded_data = remove_pkcs7_padding(decrypted_data)
    
    filename, content_type, file_size, content_offset = parse_file_header(unpadded_data)
    
    file_content = bytes(unpadded_data[content_offset:content_offset + file_size])
    
    file_stream = io.BytesIO(file_content)
    
    result_file = FileStorage(
        stream=file_stream,
        filename=filename,
        content_type=content_type
    )
    
    return result_file

def encrypt_file_to_base64(file_storage, key_str):
    import base64
    encrypted_bytes = encrypt_file(file_storage, key_str)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_file_from_base64(base64_string, key_str):

    import base64
    encrypted_bytes = base64.b64decode(base64_string.encode('utf-8'))
    return decrypt_file(encrypted_bytes, key_str)

def save_encrypted_to_file(encrypted_bytes, output_path):
    with open(output_path, 'wb') as f:
        f.write(encrypted_bytes)

def load_encrypted_from_file(input_path):
    with open(input_path, 'rb') as f:
        return f.read()

def save_decrypted_file(file_storage, output_path=None):
   
    if output_path is None:
        output_path = file_storage.filename
    
    file_storage.stream.seek(0)
    with open(output_path, 'wb') as f:
        f.write(file_storage.read())
    
    return output_path

def convertString(string, start, end):
    ar = [0] * 16
    j = 0
    for i in range(start, min(end, len(string))):
        ar[j] = ord(string[i])
        j += 1
    return ar

def eeaes_encrypt(plain_text, key_str):
    
    cypherkey, sbox_seed = gen_cypherkey(key_str)
    u = float("3.9" + str(sum(sbox_seed)))
    sbox = generate_sbox(u)
    expanded_key = expandKey(cypherkey, sbox)
    
    result = []
    
    for j in range(int(math.ceil(float(len(plain_text)) / 16))):
        start = j * 16
        end = min(j * 16 + 16, len(plain_text))
        plaintext = convertString(plain_text, start, end)
        for l in range(10):
            stage_result = []
            for f in range(16):
                stage_result.append(sbox[plaintext[f] ^ expanded_key[f + (l * 16)]])
            stage_result = rowShift(stage_result)
            stage_result = bit_reverse_transposition(stage_result)
            plaintext = stage_result

        final_result = []
        for f in range(16):
            final_result.append(sbox[plaintext[f]])
        final_result = rowShift(final_result)
        
        cipher_text_temp = []
        for f in range(16):
            cipher_text_temp.append(final_result[f] ^ expanded_key[f + 160])
        
        result.extend(cipher_text_temp)
    
    return result

def eeaes_decrypt(cipher_bytes, key_str):

    cypherkey, sbox_seed = gen_cypherkey(key_str)
    u = float("3.9" + str(sum(sbox_seed)))
    sbox = generate_sbox(u)
    inv_sbox = get_inverse_sbox(sbox)
    expanded_key = expandKey(cypherkey, sbox)
    
    result = []
    
    for j in range(int(math.ceil(float(len(cipher_bytes)) / 16))):
        start = j * 16
        end = min(j * 16 + 16, len(cipher_bytes))
        cipher_block = list(cipher_bytes[start:end])
        
        stage_result = []
        for f in range(16):
            stage_result.append(cipher_block[f] ^ expanded_key[f + 160])
        stage_result = in_shift_rows(stage_result)
        
        plaintext = []
        for f in range(16):
            plaintext.append(inv_sbox[stage_result[f]])
 
        for l in range(10):
            plaintext = bit_reverse_transposition(plaintext)
            plaintext = in_shift_rows(plaintext)
            
            stage_result = []
            for f in range(16):
                stage_result.append(inv_sbox[plaintext[f]])
            
            stage_result_t = []
            for f in range(16):
                stage_result_t.append(stage_result[f] ^ expanded_key[f + ((9 - l) * 16)])
            
            plaintext = stage_result_t
        
        result.extend(plaintext)

    text = ''.join(chr(i) for i in result if i != 0)
    return text

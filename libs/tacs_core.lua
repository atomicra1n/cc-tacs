-- TACS CORE CRYPTO LIBRARY 
-- Algorithms: SHA-256, HMAC-SHA256, AES-128-CTR, CSPRNG-Lite
-- optimized for ComputerCraft (Lua 5.1)

local bit = bit or require("bit")
local rshift, lshift, band, bor, bxor, bnot = bit.brshift, bit.blshift, bit.band, bit.bor, bit.bxor, bit.bnot

-- ==========================================
-- 1. UTILITIES
-- ==========================================

local function toHex(str)
    return (str:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function fromHex(str)
    return (str:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end

local function strToTable(str)
    local t = {}
    for i = 1, #str do t[i] = string.byte(str, i) end
    return t
end

local function tableToStr(t)
    local s = {}
    for i = 1, #t do s[i] = string.char(t[i]) end
    return table.concat(s)
end

-- ==========================================
-- 2. SHA-256 IMPLEMENTATION (FIPS 180-4)
-- ==========================================

local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

local function rrotate(x, n) return bor(rshift(x, n), lshift(x, 32 - n)) end

local function sha256(msg)
    local H = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    }
    
    local msgBits = #msg * 8
    msg = msg .. string.char(0x80)
    while (#msg * 8 + 64) % 512 ~= 0 do msg = msg .. string.char(0) end
    
    local high = math.floor(msgBits / 4294967296)
    local low = msgBits % 4294967296
    
    -- Big Endian Length Append
    for i = 1, 4 do msg = msg .. string.char(math.floor(high / 2^((4-i)*8)) % 256) end
    for i = 1, 4 do msg = msg .. string.char(math.floor(low / 2^((4-i)*8)) % 256) end
    
    local W = {}
    for i = 1, #msg / 64 do
        local chunk = string.sub(msg, (i - 1) * 64 + 1, i * 64)
        for j = 1, 16 do
            W[j] = 0
            for k = 1, 4 do W[j] = W[j] * 256 + string.byte(chunk, (j-1)*4 + k) end
        end
        for j = 17, 64 do
            local s0 = bxor(rrotate(W[j-15], 7), rrotate(W[j-15], 18), rshift(W[j-15], 3))
            local s1 = bxor(rrotate(W[j-2], 17), rrotate(W[j-2], 19), rshift(W[j-2], 10))
            W[j] = (W[j-16] + s0 + W[j-7] + s1) % 4294967296
        end
        
        local a, b, c, d, e, f, g, h = unpack(H)
        
        for j = 1, 64 do
            local S1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
            local ch = bxor(band(e, f), band(bnot(e), g))
            local temp1 = (h + S1 + ch + K[j] + W[j]) % 4294967296
            local S0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
            local maj = bxor(band(a, b), band(a, c), band(b, c))
            local temp2 = (S0 + maj) % 4294967296
            
            h, g, f, e = g, f, e, (d + temp1) % 4294967296
            d, c, b, a = c, b, a, (temp1 + temp2) % 4294967296
        end
        
        H[1] = (H[1] + a) % 4294967296; H[2] = (H[2] + b) % 4294967296
        H[3] = (H[3] + c) % 4294967296; H[4] = (H[4] + d) % 4294967296
        H[5] = (H[5] + e) % 4294967296; H[6] = (H[6] + f) % 4294967296
        H[7] = (H[7] + g) % 4294967296; H[8] = (H[8] + h) % 4294967296
    end
    
    local hex = ""
    for i = 1, 8 do hex = hex .. string.format("%08x", H[i]) end
    return hex
end

-- ==========================================
-- 3. HMAC-SHA256 (RFC 2104)
-- ==========================================

local function hmac(key, msg)
    local blockSize = 64
    if #key > blockSize then key = fromHex(sha256(key)) end
    if #key < blockSize then key = key .. string.rep(string.char(0), blockSize - #key) end
    
    local o_key_pad = ""
    local i_key_pad = ""
    
    for i = 1, blockSize do
        local b = string.byte(key, i)
        o_key_pad = o_key_pad .. string.char(bxor(b, 0x5c))
        i_key_pad = i_key_pad .. string.char(bxor(b, 0x36))
    end
    
    return sha256(o_key_pad .. fromHex(sha256(i_key_pad .. msg)))
end

-- ==========================================
-- 4. AES-128 (CTR Mode)
-- ==========================================

local SBox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
}

local Rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }

local function subBytes(s)
    for i = 1, 16 do s[i] = SBox[s[i] + 1] end
end

local function shiftRows(s)
    local function r(t, a, b, c, d) return t[a], t[b], t[c], t[d] end
    s[2], s[6], s[10], s[14] = r(s, 6, 10, 14, 2)
    s[3], s[7], s[11], s[15] = r(s, 11, 15, 3, 7)
    s[4], s[8], s[12], s[16] = r(s, 16, 4, 8, 12)
end

local function mixColumns(s)
    local function gmul(a, b)
        local p = 0
        for i = 0, 7 do
            if band(b, 1) ~= 0 then p = bxor(p, a) end
            local hi = band(a, 0x80)
            a = band(lshift(a, 1), 0xFF)
            if hi ~= 0 then a = bxor(a, 0x1b) end
            b = rshift(b, 1)
        end
        return p
    end
    for i = 0, 3 do
        local c = i * 4 + 1
        local a, b, c1, d = s[c], s[c+1], s[c+2], s[c+3]
        s[c]   = bxor(gmul(a,2), gmul(b,3), c1, d)
        s[c+1] = bxor(a, gmul(b,2), gmul(c1,3), d)
        s[c+2] = bxor(a, b, gmul(c1,2), gmul(d,3))
        s[c+3] = bxor(gmul(a,3), b, c1, gmul(d,2))
    end
end

local function addRoundKey(s, k, round)
    for i = 1, 16 do s[i] = bxor(s[i], k[(round * 16) + i]) end
end

local function keyExpansion(key)
    local k = strToTable(key)
    if #k ~= 16 then 
        -- Fallback: If key is not 16 bytes, hash it and take first 16
        local h = sha256(key)
        local raw = fromHex(h)
        k = strToTable(string.sub(raw, 1, 16))
    end
    
    for i = 16, 175 do
        local temp = {k[i-3], k[i-2], k[i-1], k[i]}
        if i % 16 == 0 then
            temp = {temp[2], temp[3], temp[4], temp[1]} -- RotWord
            for j=1,4 do temp[j] = SBox[temp[j]+1] end -- SubWord
            temp[1] = bxor(temp[1], Rcon[i/16])
        end
        k[i+1] = bxor(k[i-15], temp[(i%4)+1])
    end
    return k
end

local function aesEncryptBlock(input, expKey)
    local state = {}
    for i = 1, 16 do state[i] = input[i] end
    addRoundKey(state, expKey, 0)
    for round = 1, 9 do
        subBytes(state)
        shiftRows(state)
        mixColumns(state)
        addRoundKey(state, expKey, round)
    end
    subBytes(state)
    shiftRows(state)
    addRoundKey(state, expKey, 10)
    return state
end

-- AES-CTR Mode
-- Key: string (hashed to 128-bit)
-- Nonce: number/string
-- Text: string
local function aes_ctr(key, nonce, text)
    local expKey = keyExpansion(key)
    local nonceStr = tostring(nonce)
    -- Pad nonce to 8 bytes, add 8 byte counter
    while #nonceStr < 8 do nonceStr = "0" .. nonceStr end
    nonceStr = string.sub(nonceStr, 1, 8)
    
    local output = {}
    local counter = 0
    local textBytes = strToTable(text)
    
    for i = 1, #textBytes, 16 do
        local counterBlock = strToTable(nonceStr)
        local cStr = string.format("%016x", counter)
        for j=1, 8 do
            counterBlock[8+j] = tonumber(string.sub(cStr, (j-1)*2+1, j*2), 16)
        end
        
        local keystream = aesEncryptBlock(counterBlock, expKey)
        
        for j = 0, 15 do
            if i+j <= #textBytes then
                table.insert(output, bxor(textBytes[i+j], keystream[j+1]))
            end
        end
        counter = counter + 1
    end
    return tableToStr(output)
end

-- ==========================================
-- 5. ENTROPY MIXER (CSPRNG-Lite)
-- ==========================================

local entropy_pool = ""

local function mix_entropy(data)
    entropy_pool = sha256(entropy_pool .. tostring(data))
end

-- Initial Seeding
mix_entropy(os.epoch("utc"))
mix_entropy(os.getComputerID())
mix_entropy(math.random())

local function secure_random()
    -- Mix in current state
    mix_entropy(os.clock())
    
    -- Extract integer from hash
    local h = entropy_pool
    local sub = string.sub(h, 1, 8) -- Take 8 hex chars (32 bits)
    local num = tonumber(sub, 16)
    
    -- Cycle pool for next time
    mix_entropy(num)
    
    return num -- returns 0 to 4294967295
end

local function random_bytes(n)
    local res = ""
    for i=1, n do
        local r = secure_random() % 256
        res = res .. string.char(r)
    end
    return res
end

-- ==========================================
-- 6. PUBLIC API
-- ==========================================

return {
    -- Hashing
    sha256 = sha256,
    hmac = hmac,
    
    -- Encryption
    encrypt = aes_ctr,
    decrypt = aes_ctr,
    
    -- Secure Randomness
    random = secure_random,
    randomBytes = random_bytes,
    
    -- Helpers
    toHex = toHex,
    fromHex = fromHex
}

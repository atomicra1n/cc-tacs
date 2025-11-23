-- TACS SERVER NODE (HIVEMIND)
-- Role: Authentication Authority & Data Replication

os.loadAPI("libs/tacs_core.lua")
local net = require("libs/network_utils")
local db = require("server/database")

-- === STATE ===
local users = db.load()
local CLUSTER_KEY = db.getKey()

-- === INITIALIZATION ===
term.clear()
term.setCursorPos(1,1)
print("--- TACS HIVEMIND NODE ---")
print("ID: " .. os.getComputerID())

if not CLUSTER_KEY then
    print("[!] NO CLUSTER KEY FOUND")
    print("Is this the first server? (Genesis Node)")
    write("Generate Key? (y/n): ")
    local ans = read()
    if ans == "y" then
        CLUSTER_KEY = db.genKey()
        print("Key Generated. Copy '.cluster_key' to other nodes via Disk.")
    else
        print("Please insert Disk with '.cluster_key' and reboot.")
        while true do sleep(1) end
    end
else
    print("[+] Cluster Key Loaded.")
end

-- === LOGIC HANDLERS ===

-- 1. Handle Access Requests (From Turnstiles)
-- Protocol: Cleartext Header, HMAC Signature
local function handleAuth(id, msg)
    if type(msg) ~= "table" or not msg.user or not msg.nonce or not msg.sig then
        return
    end

    local userData = users[msg.user]
    
    -- Does user exist?
    if not userData then
        net.send(id, "PUBLIC", { granted = false, reason = "UNKNOWN_USER" })
        print("Auth Failed: Unknown User " .. msg.user)
        return
    end
    
    -- CHECK HMAC (The Core Security Check)
    -- We reconstruct the signature locally using the Stored Master Key
    -- Expected = HMAC(MasterKey, GateName + Nonce)
    local dataToSign = (msg.gate or "") .. tostring(msg.nonce)
    local expectedSig = tacs_core.hmac(userData.masterKey, dataToSign)
    
    if expectedSig == msg.sig then
        net.send(id, "PUBLIC", { granted = true })
        print("Auth Success: " .. msg.user .. " @ " .. (msg.gate or "Unknown"))
    else
        net.send(id, "PUBLIC", { granted = false, reason = "BAD_SIG" })
        print("Auth Failed: Bad Signature for " .. msg.user)
    end
end

-- 2. Handle Minting Requests (From Minter)
-- Protocol: Encrypted with Cluster Key
local function handleMint(id, msg)
    -- Attempt Decrypt
    -- Msg is expected to be AES encrypted string
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local req = textutils.unserialize(decrypted)
    
    if not req or req.cmd ~= "MINT_USER" then return end
    
    print("Minting Request: " .. req.username)
    
    -- Generate New 256-bit Master Key for this user
    local newMasterKey = tacs_core.randomBytes(32)
    
    -- Save to DB
    users[req.username] = {
        masterKey = newMasterKey,
        level = req.level or 1,
        created = os.epoch("utc")
    }
    db.save(users)
    
    -- Send the new key back to Minter (Encrypted)
    -- Minter needs this to burn it onto the Fob
    local respPayload = textutils.serialize({
        success = true,
        masterKey = newMasterKey
    })
    
    local respNonce = os.epoch("utc")
    local encryptedResp = tacs_core.encrypt(CLUSTER_KEY, respNonce, respPayload)
    
    net.send(id, "MINT", {
        nonce = respNonce,
        payload = encryptedResp
    })
end

-- === MAIN LOOPS ===

local function publicListener()
    while true do
        local id, msg = net.receive("PUBLIC", 9999)
        if msg then handleAuth(id, msg) end
    end
end

local function minterListener()
    while true do
        local id, msg = net.receive("MINT", 9999)
        if msg then handleMint(id, msg) end
    end
end

-- Start services
print("[*] Systems Online. Waiting for requests...")
parallel.waitForAll(publicListener, minterListener)

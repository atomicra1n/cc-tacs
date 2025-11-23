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
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local req = textutils.unserialize(decrypted)
    
    if not req or req.cmd ~= "MINT_USER" then return end
    
    print("Minting Request: " .. req.username)
    
    -- Generate New 256-bit Master Key
    local newMasterKey = tacs_core.randomBytes(32)
    
    -- Update Local State
    local userEntry = {
        masterKey = newMasterKey,
        level = req.level or 1,
        created = os.epoch("utc")
    }
    users[req.username] = userEntry
    db.save(users)
    
    -- === REPLICATION (SYNC TO 30 SERVERS) ===
    -- We broadcast this update to the cluster channel.
    -- All other 29 servers will hear this and update their DBs.
    local replPayload = textutils.serialize({
        cmd = "REPLICATE_USER",
        username = req.username,
        data = userEntry
    })
    
    -- Encrypt with Cluster Key so outsiders can't sniff the keys
    local replNonce = os.epoch("utc")
    local encryptedRepl = tacs_core.encrypt(CLUSTER_KEY, replNonce, replPayload)
    
    net.broadcast("CLUSTER", {
        nonce = replNonce,
        payload = encryptedRepl
    })
    print("Replication sent to swarm.")
    
    -- === REPLY TO MINTER ===
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

-- 3. Handle Cluster Sync (From Other Servers)
-- This keeps the 30 servers in sync
local function handleClusterUpdate(id, msg)
    -- Don't listen to ourselves
    if id == os.getComputerID() then return end
    
    -- Decrypt packet
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local update = textutils.unserialize(decrypted)
    
    if not update then return end
    
    if update.cmd == "REPLICATE_USER" then
        print("Syncing User: " .. update.username .. " (From Node " .. id .. ")")
        users[update.username] = update.data
        db.save(users)
    end
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

local function clusterListener()
    while true do
        local id, msg = net.receive("CLUSTER", 9999)
        if msg then handleClusterUpdate(id, msg) end
    end
end

-- Start services
print("[*] Hivemind Online (" .. os.getComputerID() .. "). Waiting for requests...")
parallel.waitForAll(publicListener, minterListener, clusterListener)

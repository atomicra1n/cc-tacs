-- TACS SERVER NODE (HIVEMIND) v3.2
-- Role: Authentication Authority & Data Replication

-- Use os.loadAPI for compatibility
os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")
os.loadAPI("server/database.lua")

-- === STATE ===
local users = database.loadUsers()
local CLUSTER_KEY = database.getKey()

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
        CLUSTER_KEY = database.genKey()
        print("Key Generated. Copy '.cluster_key' to other nodes via Disk.")
    else
        print("Please insert Disk with '.cluster_key' and reboot.")
        while true do sleep(1) end
    end
else
    print("[+] Cluster Key Loaded.")
end

-- === LOGIC HANDLERS ===

local function handleAuth(id, msg)
    if type(msg) ~= "table" or not msg.user or not msg.nonce or not msg.sig then
        return
    end

    local userData = users[msg.user]
    if not userData then
        network_utils.send(id, "PUBLIC", { granted = false, reason = "UNKNOWN_USER" })
        print("Auth Failed: Unknown User " .. msg.user)
        return
    end
    
    local dataToSign = (msg.gate or "") .. tostring(msg.nonce)
    local expectedSig = tacs_core.hmac(userData.masterKey, dataToSign)
    
    if expectedSig == msg.sig then
        network_utils.send(id, "PUBLIC", { granted = true })
        print("Auth Success: " .. msg.user .. " @ " .. (msg.gate or "Unknown"))
    else
        network_utils.send(id, "PUBLIC", { granted = false, reason = "BAD_SIG" })
        print("Auth Failed: Bad Signature for " .. msg.user)
    end
end

local function handleMint(id, msg)
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local req = textutils.unserialize(decrypted)
    
    if not req or req.cmd ~= "MINT_USER" then return end
    
    print("Minting Request: " .. req.username)
    local newMasterKey = tacs_core.randomBytes(32)
    local userEntry = {
        masterKey = newMasterKey,
        level = req.level or 1,
        created = os.epoch and os.epoch("utc") or os.time()
    }
    users[req.username] = userEntry
    database.saveUsers(users)
    
    local replPayload = textutils.serialize({
        cmd = "REPLICATE_USER",
        username = req.username,
        data = userEntry
    })
    
    local replNonce = os.epoch and os.epoch("utc") or os.time()
    local encryptedRepl = tacs_core.encrypt(CLUSTER_KEY, replNonce, replPayload)
    
    network_utils.broadcast("CLUSTER", {
        nonce = replNonce,
        payload = encryptedRepl
    })
    print("Replication sent to swarm.")
    
    local respPayload = textutils.serialize({
        success = true,
        masterKey = newMasterKey
    })
    
    local respNonce = os.epoch and os.epoch("utc") or os.time()
    local encryptedResp = tacs_core.encrypt(CLUSTER_KEY, respNonce, respPayload)
    
    network_utils.send(id, "MINT", {
        nonce = respNonce,
        payload = encryptedResp
    })
end

local function handleClusterUpdate(id, msg)
    if id == os.getComputerID() then return end
    
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local update = textutils.unserialize(decrypted)
    
    if not update then return end
    
    if update.cmd == "REPLICATE_USER" then
        print("Syncing User: " .. update.username .. " (From Node " .. id .. ")")
        users[update.username] = update.data
        database.saveUsers(users)
    end
end

local function publicListener()
    while true do
        local id, msg = network_utils.receive("PUBLIC", 9999)
        if msg then handleAuth(id, msg) end
    end
end

local function minterListener()
    while true do
        local id, msg = network_utils.receive("MINT", 9999)
        if msg then handleMint(id, msg) end
    end
end

local function clusterListener()
    while true do
        local id, msg = network_utils.receive("CLUSTER", 9999)
        if msg then handleClusterUpdate(id, msg) end
    end
end

print("[*] Hivemind Online (" .. os.getComputerID() .. "). Waiting for requests...")
parallel.waitForAll(publicListener, minterListener, clusterListener)

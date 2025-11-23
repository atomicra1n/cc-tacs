-- TACS SERVER NODE (HIVEMIND) v3.3
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

-- HELPER: Write Key to Disk
local function writeKeyToDisk(key)
    local drive = peripheral.find("drive")
    if not drive then
        print("[!] No Disk Drive found. Cannot create setup disk.")
        return
    end

    print(">> Drive detected.")
    
    -- Wait for disk if missing
    while not drive.isDiskPresent() do
        term.setTextColor(colors.yellow)
        print(">> Please insert a Floppy Disk to create a Setup Disk...")
        term.setTextColor(colors.white)
        os.pullEvent("disk")
    end

    local path = drive.getMountPath()
    if path then
        local f = fs.open(fs.combine(path, ".cluster_key"), "w")
        f.write(key)
        f.close()
        term.setTextColor(colors.lime)
        print("[OK] Cluster Key written to disk!")
        print("    Take this disk to other servers to pair them.")
        term.setTextColor(colors.white)
    else
        print("[!] Error mounting disk.")
    end
end

-- === GENESIS LOGIC ===
if not CLUSTER_KEY then
    print("[!] NO CLUSTER KEY FOUND")
    print("Is this the first server? (Genesis Node)")
    write("Generate Key? (y/n): ")
    local ans = read()
    
    if ans == "y" then
        CLUSTER_KEY = database.genKey()
        print("Key Generated internally.")
        writeKeyToDisk(CLUSTER_KEY)
    else
        -- Follower Node Logic
        local drive = peripheral.find("drive")
        while not CLUSTER_KEY do
             -- Check if key is already on disk
             if drive and drive.isDiskPresent() then
                local path = drive.getMountPath()
                local keyPath = fs.combine(path, ".cluster_key")
                if fs.exists(keyPath) then
                    local f = fs.open(keyPath, "r")
                    local k = f.readAll()
                    f.close()
                    
                    -- Save to local system
                    local localF = fs.open(".cluster_key", "w")
                    localF.write(k)
                    localF.close()
                    CLUSTER_KEY = k
                    term.setTextColor(colors.lime)
                    print("[OK] Key loaded from disk! Rebooting...")
                    term.setTextColor(colors.white)
                    sleep(2)
                    os.reboot()
                end
             end
             
             if not CLUSTER_KEY then
                print("Please insert Disk with '.cluster_key'...")
                os.pullEvent("disk")
             end
        end
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

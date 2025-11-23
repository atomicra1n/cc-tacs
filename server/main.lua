-- TACS SERVER NODE (HIVEMIND) v4.1 (FULL RELEASE)
-- Role: Authentication Authority, Consensus & Replication

os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")
os.loadAPI("server/database.lua")
os.loadAPI("server/consensus.lua")

-- === STATE ===
local users = database.loadUsers()
local CLUSTER_KEY = database.getKey()

-- === INITIALIZATION & GENESIS ===
term.clear()
term.setCursorPos(1,1)
print("--- TACS HIVEMIND NODE ---")
print("ID: " .. os.getComputerID())

-- Helper: Write Cluster Key to Disk for pairing other servers
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

-- Check for Cluster Key (Genesis Logic)
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
        -- Follower Node Logic: Wait for disk
        local drive = peripheral.find("drive")
        while not CLUSTER_KEY do
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

-- 1. Handle Access (READ ONLY - Can be done by anyone)
local function handleAuth(id, msg)
    if not msg.user or not msg.sig then return end
    local userData = users[msg.user]
    
    if not userData then
        network_utils.send(id, "PUBLIC", { granted = false, reason = "UNKNOWN" })
        return 
    end
    
    -- Verify HMAC
    local dataToSign = (msg.gate or "") .. tostring(msg.nonce)
    local expectedSig = tacs_core.hmac(userData.masterKey, dataToSign)
    
    if expectedSig == msg.sig then
        network_utils.send(id, "PUBLIC", { granted = true })
        print("[AUTH] Allowed " .. msg.user)
    else
        network_utils.send(id, "PUBLIC", { granted = false })
        print("[AUTH] Denied " .. msg.user)
    end
end

-- 2. Handle Minting (WRITE - Leader Only)
local function handleMint(id, msg)
    -- RAFT CHECK: Am I the Leader?
    if not consensus.isLeader() then
        local leader = consensus.getLeader()
        -- Redirect Minter to the correct Leader
        network_utils.send(id, "MINT", { retry = true, leader = leader })
        print("[MINT] Redirecting to Leader: " .. tostring(leader))
        return
    end

    -- I AM THE LEADER - PROCEED
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local req = textutils.unserialize(decrypted)
    
    if not req or req.cmd ~= "MINT_USER" then return end
    
    print("[LEADER] Minting User: " .. req.username)
    
    -- Generate Data
    local newMasterKey = tacs_core.randomBytes(32)
    local userEntry = {
        masterKey = newMasterKey,
        level = req.level or 1,
        created = os.epoch and os.epoch("utc") or os.time()
    }
    
    -- Update Local DB
    users[req.username] = userEntry
    database.saveUsers(users)
    
    -- REPLICATION: Broadcast update to Followers (The Swarm)
    -- We use the Cluster Key directly here to secure the replication packet
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
    print("[LEADER] Replication Sent.")
    
    -- Reply to Minter
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

-- 3. Handle Replication (Followers applying updates)
local function handleClusterUpdate(id, msg)
    -- Ignore our own broadcasts
    if id == os.getComputerID() then return end
    
    -- Decrypt
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local update = textutils.unserialize(decrypted)
    
    if not update then return end
    
    -- Apply Replication
    if update.cmd == "REPLICATE_USER" then
        print("[SYNC] User Update: " .. update.username .. " (via " .. id .. ")")
        users[update.username] = update.data
        database.saveUsers(users)
    end
end

-- === MAIN LOOPS ===

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

-- Listens for Replication packets (REPLICATE_USER)
-- Note: Consensus packets (HEARTBEAT/VOTE) are handled by consensus.start
local function clusterListener()
    while true do
        local id, msg = network_utils.receive("CLUSTER", 9999)
        if msg and msg.payload then
            -- We just check if it's a replication packet inside
            -- We have to decrypt to find out, but since consensus.lua also decrypts,
            -- this is a trade-off for simplicity in parallel execution.
            local plain = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
            local packet = textutils.unserialize(plain)
            
            if packet and packet.cmd == "REPLICATE_USER" then
                -- Re-package logically for the handler to keep code clean
                handleClusterUpdate(id, msg)
            end
        end
    end
end

-- Start Everything
print("[*] Node Online. Starting Consensus Engine...")
parallel.waitForAll(
    -- 1. Raft Engine (Handles Heartbeats, Elections, Dead Node Pruning)
    consensus.start,
    
    -- 2. App Listeners
    publicListener,
    minterListener,
    clusterListener
)

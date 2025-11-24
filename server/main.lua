-- TACS SERVER NODE (HIVEMIND) v6.1 (FULL MANAGEMENT)
-- Features: Consensus, User Minting, Zone Management, Replication
-- Includes: Full Genesis Setup Logic

os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")
os.loadAPI("server/database.lua")
os.loadAPI("server/consensus.lua")
-- integrity.lua is loaded inside consensus.lua

local users = database.getAllUsers()
local zones = database.getAllZones()
local CLUSTER_KEY = database.getKey()

-- === INITIALIZATION ===
term.clear()
term.setCursorPos(1,1)
print("--- TACS TEMELIN NODE ---")
print("ID: " .. os.getComputerID())

-- === GENESIS HELPERS ===

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

-- === 1. REPLICATION HANDLER (Followers applying updates) ===
local function handleReplication(id, packet)
    if packet.cmd == "REPLICATE_USER" then
        database.setUser(packet.username, packet.data)
        print("[SYNC] User Updated: " .. packet.username)
        
    elseif packet.cmd == "REPLICATE_ZONE" then
        database.setZone(packet.id, packet.name, packet.parent)
        print("[SYNC] Zone Added: " .. packet.name .. " (Parent: " .. (packet.parent or "ROOT") .. ")")
    end
end

-- === 2. LEADER WRITE HANDLER (From Minter) ===
local function handleWrite(id, msg)
    -- RAFT CHECK: Redirect if not Leader
    if not consensus.isLeader() then 
        local leader = consensus.getLeader()
        network_utils.send(id, "MINT", { retry = true, leader = leader })
        print("[MINT] Redirecting to Leader: " .. tostring(leader))
        return 
    end
    
    -- Decrypt Payload
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local req = textutils.unserialize(decrypted)
    if not req then return end
    
    -- A) MINT USER
    if req.cmd == "MINT_USER" then
        print("[LEADER] Minting User: " .. req.username)
        
        local newKey = tacs_core.randomBytes(32)
        local userEntry = {
            masterKey = newKey,
            level = req.level or 1,
            meta = req.meta, -- { type="BLUE", perms={"NPP"} }
            created = os.epoch("utc")
        }
        database.setUser(req.username, userEntry)
        
        -- Replicate to Swarm
        local repl = textutils.serialize({ cmd="REPLICATE_USER", username=req.username, data=userEntry })
        local nonce = os.epoch("utc")
        local enc = tacs_core.encrypt(CLUSTER_KEY, nonce, repl)
        network_utils.broadcast("CLUSTER", { nonce=nonce, payload=enc })
        
        -- Reply to Minter
        local resp = textutils.serialize({ success=true, masterKey=newKey })
        local encResp = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
        network_utils.send(id, "MINT", { nonce=nonce, payload=encResp })
        
    -- B) ADD ZONE
    elseif req.cmd == "ADD_ZONE" then
        print("[LEADER] Adding Zone: " .. req.name)
        
        database.setZone(req.id, req.name, req.parent)
        
        -- Replicate
        local repl = textutils.serialize({ cmd="REPLICATE_ZONE", id=req.id, name=req.name, parent=req.parent })
        local nonce = os.epoch("utc")
        local enc = tacs_core.encrypt(CLUSTER_KEY, nonce, repl)
        network_utils.broadcast("CLUSTER", { nonce=nonce, payload=enc })
        
        -- Reply Success
        local resp = textutils.serialize({ success=true, msg="Zone Added" })
        local encResp = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
        network_utils.send(id, "MINT", { nonce=nonce, payload=encResp })
    end
end

-- === LISTENERS ===

local function minterListener()
    while true do
        local id, msg = network_utils.receive("MINT", 9999)
        if msg then handleWrite(id, msg) end
    end
end

local function clusterListener()
    while true do
        local id, msg = network_utils.receive("CLUSTER", 9999)
        if msg and msg.payload then
            -- We interpret packet type. 
            -- Consensus packets handled by consensus.start, we only want REPLICATE cmds
            local plain = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
            local packet = textutils.unserialize(plain)
            if packet and (packet.cmd == "REPLICATE_USER" or packet.cmd == "REPLICATE_ZONE") then
                handleReplication(id, packet)
            end
        end
    end
end

print("[*] Temelin Node Online (Management Mode).")
parallel.waitForAll(
    consensus.start, 
    minterListener, 
    clusterListener
)

-- TACS SERVER NODE (HIVEMIND) v7.2 (SECURE GENESIS)
-- Features: Consensus, Management, Replication, Snapshotting
-- Security: Encrypted Key Storage

os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")
os.loadAPI("server/database.lua")

local CLUSTER_KEY = database.getKey()
local PROCESSED_NONCES = {} 

-- === INIT ===
term.clear()
term.setCursorPos(1,1)
print("--- TACS TEMELIN NODE ---")
print("ID: " .. os.getComputerID())

-- Genesis Logic
if not CLUSTER_KEY then
    print("[!] NO CLUSTER KEY")
    local function writeKeyToDisk(key)
        local drive = peripheral.find("drive")
        if not drive then print("No Drive."); return end
        print(">> Drive detected.")
        while not drive.isDiskPresent() do
            term.setTextColor(colors.yellow)
            print(">> Insert Floppy to create Setup Disk...")
            term.setTextColor(colors.white)
            os.pullEvent("disk")
        end
        local path = drive.getMountPath()
        local f = fs.open(fs.combine(path, ".cluster_key"), "w")
        -- Disk always gets Plaintext key so it can be moved
        f.write(key)
        f.close()
        term.setTextColor(colors.lime)
        print("[OK] Key written to disk!")
        term.setTextColor(colors.white)
    end

    print("Is this the first server? (Genesis Node)")
    write("Generate Key? (y/n): ")
    if read() == "y" then
        CLUSTER_KEY = database.genKey()
        writeKeyToDisk(CLUSTER_KEY)
    else
        local drive = peripheral.find("drive")
        while not CLUSTER_KEY do
             if drive and drive.isDiskPresent() then
                local path = drive.getMountPath()
                local keyPath = fs.combine(path, ".cluster_key")
                if fs.exists(keyPath) then
                    local f = fs.open(keyPath, "r")
                    local k = f.readAll()
                    f.close()
                    
                    -- Save to local system using SECURE SAVE
                    database.saveKey(k)
                    CLUSTER_KEY = k
                    
                    term.setTextColor(colors.lime)
                    print("[OK] Key Encrypted & Loaded! Rebooting...")
                    term.setTextColor(colors.white)
                    sleep(2); os.reboot()
                end
             end
             if not CLUSTER_KEY then
                print("Insert Key Disk...")
                os.pullEvent("disk")
             end
        end
    end
else
    print("[+] Cluster Key Loaded.")
end

os.loadAPI("server/consensus.lua")

-- === UTILS ===
local function checkDedup(nonce)
    local now = os.epoch and os.epoch("utc") or os.time()
    for n, t in pairs(PROCESSED_NONCES) do
        if now - t > 10000 then PROCESSED_NONCES[n] = nil end
    end
    
    if PROCESSED_NONCES[nonce] then return true end
    PROCESSED_NONCES[nonce] = now
    return false
end

-- === SYNC REQUESTER ===
local function initialSync()
    sleep(3) 
    if database.isEmpty() and not consensus.isLeader() then
        print("[SYNC] Database empty. Requesting Snapshot...")
        local nonce = os.epoch("utc")
        local req = textutils.serialize({ cmd = "REQUEST_SYNC", id = os.getComputerID() })
        local enc = tacs_core.encrypt(CLUSTER_KEY, nonce, req)
        network_utils.broadcast("CLUSTER", { nonce = nonce, payload = enc })
    end
end

-- === 1. REPLICATION & SYNC HANDLER ===
local function handleClusterMsg(id, packet)
    if packet.cmd == "REPLICATE_USER" then
        database.setUser(packet.username, packet.data)
        print("[SYNC] User Updated: " .. packet.username)
        
    elseif packet.cmd == "REPLICATE_ZONE" then
        database.setZone(packet.id, packet.name, packet.parent)
        print("[SYNC] Zone Added: " .. packet.name)
        
    elseif packet.cmd == "REPLICATE_DEL_ZONE" then
        database.deleteZone(packet.id)
        print("[SYNC] Zone Deleted: " .. packet.id)
    
    elseif packet.cmd == "FULL_SYNC" then
        if packet.target == os.getComputerID() then
            print("[SYNC] Receiving Full Snapshot...")
            if database.restoreState(packet.data) then
                print("[SYNC] Snapshot Applied Successfully.")
            else
                print("[SYNC] Failed to apply snapshot.")
            end
        end
        
    elseif packet.cmd == "REQUEST_SYNC" then
        if consensus.isLeader() then
            print("[LEADER] Sending Snapshot to Node " .. packet.id)
            local dump = database.dumpState()
            local resp = textutils.serialize({ cmd = "FULL_SYNC", target = packet.id, data = dump })
            local nonce = os.epoch("utc")
            local enc = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
            network_utils.send(packet.id, "CLUSTER", { nonce = nonce, payload = enc })
        end
    end
end

-- === 2. LEADER WRITE HANDLER ===
local function handleWrite(id, msg)
    if not consensus.isLeader() then 
        local leader = consensus.getLeader()
        network_utils.send(id, "MINT", { retry = true, leader = leader })
        return 
    end
    
    if checkDedup(msg.nonce) then return end
    
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local req = textutils.unserialize(decrypted)
    if not req then return end
    
    local nonce = os.epoch("utc")
    
    if req.cmd == "MINT_USER" then
        print("[LEADER] Minting User: " .. req.username)
        local newKey = tacs_core.randomBytes(32)
        local userEntry = {
            masterKey = newKey,
            level = req.level or 1,
            meta = req.meta,
            created = nonce
        }
        database.setUser(req.username, userEntry)
        
        local repl = textutils.serialize({ cmd="REPLICATE_USER", username=req.username, data=userEntry })
        local enc = tacs_core.encrypt(CLUSTER_KEY, nonce, repl)
        network_utils.broadcast("CLUSTER", { nonce=nonce, payload=enc })
        
        local resp = textutils.serialize({ success=true, masterKey=newKey })
        local encResp = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
        network_utils.send(id, "MINT", { nonce=nonce, payload=encResp })
        
    elseif req.cmd == "ADD_ZONE" then
        print("[LEADER] Adding Zone: " .. req.name)
        database.setZone(req.id, req.name, req.parent)
        
        local repl = textutils.serialize({ cmd="REPLICATE_ZONE", id=req.id, name=req.name, parent=req.parent })
        local enc = tacs_core.encrypt(CLUSTER_KEY, nonce, repl)
        network_utils.broadcast("CLUSTER", { nonce=nonce, payload=enc })
        
        local resp = textutils.serialize({ success=true, msg="Zone Added" })
        local encResp = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
        network_utils.send(id, "MINT", { nonce=nonce, payload=encResp })
        
    elseif req.cmd == "LIST_ZONES" then
        local zones = database.getAllZones()
        local resp = textutils.serialize({ success=true, zones=zones })
        local encResp = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
        network_utils.send(id, "MINT", { nonce=nonce, payload=encResp })
        
    elseif req.cmd == "DELETE_ZONE" then
        print("[LEADER] Deleting Zone: " .. req.id)
        database.deleteZone(req.id)
        
        local repl = textutils.serialize({ cmd="REPLICATE_DEL_ZONE", id=req.id })
        local enc = tacs_core.encrypt(CLUSTER_KEY, nonce, repl)
        network_utils.broadcast("CLUSTER", { nonce=nonce, payload=enc })
        
        local resp = textutils.serialize({ success=true })
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
            local plain = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
            local packet = textutils.unserialize(plain)
            if packet and (packet.cmd == "REPLICATE_USER" or packet.cmd == "REPLICATE_ZONE" or packet.cmd == "REPLICATE_DEL_ZONE" or packet.cmd == "REQUEST_SYNC" or packet.cmd == "FULL_SYNC") then
                handleClusterMsg(id, packet)
            end
        end
    end
end

print("[*] Temelin Node Online (Management Mode).")

parallel.waitForAll(
    consensus.start, 
    minterListener, 
    clusterListener,
    initialSync
)

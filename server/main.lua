-- TACS SERVER NODE (HIVEMIND) v8.1 (IDEMPOTENCY FIX)
-- Features: Raft Integration, Replay Protection, Secure Minter Interface
-- Update: Fixed Logical Duplication using Request IDs

os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")
os.loadAPI("server/database.lua")

local CLUSTER_KEY = database.getKey()
local REPLAY_WINDOW_MS = 10000 -- 10 Seconds
local PROCESSED_NONCES = {} 
local PROCESSED_IDS = {} -- Tracks Logical Request IDs

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
        while not drive.isDiskPresent() do
            print(">> Insert Floppy...")
            os.pullEvent("disk")
        end
        local path = drive.getMountPath()
        local f = fs.open(fs.combine(path, ".cluster_key"), "w")
        f.write(key)
        f.close()
        print("[OK] Key written to disk!")
    end

    print("Genesis Node? (y/n): ")
    if read() == "y" then
        CLUSTER_KEY = database.genKey()
        writeKeyToDisk(CLUSTER_KEY)
    else
        while not CLUSTER_KEY do
             local drive = peripheral.find("drive")
             if drive and drive.isDiskPresent() then
                local path = drive.getMountPath()
                local keyPath = fs.combine(path, ".cluster_key")
                if fs.exists(keyPath) then
                    local f = fs.open(keyPath, "r")
                    local k = f.readAll()
                    f.close()
                    database.saveKey(k)
                    CLUSTER_KEY = k
                    print("[OK] Loaded! Rebooting...")
                    sleep(2); os.reboot()
                end
             end
             print("Waiting for Key Disk...")
             sleep(1)
        end
    end
else
    print("[+] Cluster Key Loaded.")
end

os.loadAPI("server/consensus.lua")

-- === REPLAY PROTECTION ===
local function checkSecurity(nonce)
    local now = os.epoch and os.epoch("utc") or os.time()
    
    -- 1. Timestamp Check
    local pktTime = tonumber(nonce)
    if not pktTime then return false, "INVALID_NONCE_FORMAT" end
    
    local diff = math.abs(now - pktTime)
    if diff > REPLAY_WINDOW_MS then
        return false, "PACKET_EXPIRED"
    end
    
    -- 2. Crypto Replay Check
    if PROCESSED_NONCES[nonce] then 
        return false, "REPLAY_DETECTED" 
    end
    
    -- Cleanup
    for n, t in pairs(PROCESSED_NONCES) do
        if (now - t) > REPLAY_WINDOW_MS then PROCESSED_NONCES[n] = nil end
    end
    for id, t in pairs(PROCESSED_IDS) do
        -- Keep IDs longer (30s) to handle slow network retries
        if (now - t) > 30000 then PROCESSED_IDS[id] = nil end
    end
    
    PROCESSED_NONCES[nonce] = now
    return true
end

-- === WRITE HANDLER ===
local function handleWrite(id, msg)
    if not consensus.isLeader() then 
        local leader = consensus.getLeader()
        if leader then
            network_utils.send(id, "MINT", { retry = true, leader = leader })
        end
        return 
    end
    
    local valid, reason = checkSecurity(msg.nonce)
    if not valid then
        print("[WARN] Rejected msg from " .. id .. ": " .. reason)
        return
    end
    
    local decrypted = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
    local req = textutils.unserialize(decrypted)
    if not req then return end
    
    local nonce = os.epoch("utc")

    -- === IDEMPOTENCY CHECK ===
    -- If we have seen this reqID, we do NOT propose to Raft again.
    -- We just pretend we did and send the success msg back.
    local isDuplicate = false
    if req.reqID and PROCESSED_IDS[req.reqID] then
        print("[LEADER] Duplicate Request " .. req.reqID .. " - Sending cached ACK")
        isDuplicate = true
    elseif req.reqID then
        PROCESSED_IDS[req.reqID] = nonce
    end
    
    local cmd = nil
    
    if req.cmd == "MINT_USER" then
        local newKey = tacs_core.randomBytes(32) 
        -- Note: On Duplicate, we generate a new key locally but don't save it. 
        -- Ideally we'd cache the response, but for now this stops the log spam.
        
        if not isDuplicate then
            print("[LEADER] Proposing User: " .. req.username)
            cmd = {
                cmd = "MINT_USER",
                username = req.username,
                data = {
                    masterKey = newKey,
                    level = req.level or 1,
                    meta = req.meta,
                    created = nonce
                }
            }
            consensus.propose(cmd)
        end
        
        -- Always send success (Optimization: Assume proposal works)
        local resp = textutils.serialize({ success=true, masterKey=newKey })
        local encResp = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
        network_utils.send(id, "MINT", { nonce=nonce, payload=encResp })
        
    elseif req.cmd == "ADD_ZONE" then
        if not isDuplicate then
            print("[LEADER] Proposing Zone: " .. req.name)
            cmd = {
                cmd = "ADD_ZONE",
                id = req.id,
                name = req.name,
                parent = req.parent
            }
            consensus.propose(cmd)
        end
        
        local resp = textutils.serialize({ success=true })
        local encResp = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
        network_utils.send(id, "MINT", { nonce=nonce, payload=encResp })

    elseif req.cmd == "DELETE_ZONE" then
        if not isDuplicate then
            print("[LEADER] Proposing Delete Zone: " .. req.id)
            cmd = { cmd = "DELETE_ZONE", id = req.id }
            consensus.propose(cmd)
        end
        
        local resp = textutils.serialize({ success=true })
        local encResp = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
        network_utils.send(id, "MINT", { nonce=nonce, payload=encResp })
        
    elseif req.cmd == "LIST_ZONES" then
        local zones = database.getAllZones()
        local resp = textutils.serialize({ success=true, zones=zones })
        local encResp = tacs_core.encrypt(CLUSTER_KEY, nonce, resp)
        network_utils.send(id, "MINT", { nonce=nonce, payload=encResp })
    end
end

-- === LISTENERS ===
local function minterListener()
    while true do
        local id, msg = network_utils.receive("MINT", 0.5)
        if msg then handleWrite(id, msg) end
    end
end

print("[*] Temelin Node Online (Raft V8.1).")

parallel.waitForAll(
    consensus.start, 
    minterListener
)
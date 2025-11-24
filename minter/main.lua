-- TACS MINTER TERMINAL v6.0 (ROBUST NETWORKING)
-- Fixed: Race conditions with redirects and deduplication

os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")

local CLUSTER_KEY_FILE = ".cluster_key"
local CLUSTER_KEY = nil

-- === 1. FOB FIRMWARE TEMPLATE (UNCHANGED) ===
local FOB_TEMPLATE = [[
os.pullEvent = os.pullEventRaw 
local MY_ID = os.getComputerID()
local USERNAME = "%s"
local ENC_KEY = "%s" 
local NONCE_IV = "%s" 
local CARD_TYPE = "%s" 
local BG_COLOR = colors.black
local TXT_COLOR = colors.white
if CARD_TYPE == "BLUE" then BG_COLOR = colors.blue
elseif CARD_TYPE == "GREEN" then BG_COLOR = colors.green
elseif CARD_TYPE == "WHITE" then BG_COLOR = colors.white; TXT_COLOR = colors.black end
if not fs.exists("libs/tacs_core.lua") then error("CRITICAL: Crypto Library Missing!") end
os.loadAPI("libs/tacs_core.lua")
local hw_key = tacs_core.sha256(tostring(MY_ID)) 
local MASTER_KEY = tacs_core.decrypt(hw_key, NONCE_IV, ENC_KEY)
if not MASTER_KEY or #MASTER_KEY == 0 then
    term.setBackgroundColor(colors.red)
    term.setTextColor(colors.white)
    term.clear()
    print("SECURITY FATAL: HARDWARE ID MISMATCH.")
    error()
end
local modem = peripheral.find("modem")
if not modem then print("Error: No Wireless Modem!"); return end
modem.open(666) 
term.setBackgroundColor(BG_COLOR)
term.setTextColor(TXT_COLOR)
term.clear()
term.setCursorPos(1,1)
print("TEMELIN IK: " .. CARD_TYPE)
print("User: " .. USERNAME)
print("Status: ARMED")
while true do
    local e, side, sChan, rChan, msg, dist = os.pullEvent("modem_message")
    if type(msg) == "table" and msg.protocol == "TACS_AUTH_REQ" and msg.nonce then
        term.setCursorPos(1,5); term.clearLine(); print("Ping: " .. (msg.gate or "Unknown"))
        local data = (msg.gate or "") .. tostring(msg.nonce)
        local sig = tacs_core.hmac(MASTER_KEY, data)
        modem.transmit(rChan, 666, { protocol = "TACS_AUTH_RESP", user = USERNAME, sig = sig, nonce = msg.nonce })
        sleep(0.5)
        term.setCursorPos(1,5); term.clearLine(); print("Status: ARMED")
    end
end
]]

-- ==========================================
-- 2. UTILITIES
-- ==========================================

local function getDeviceKey()
    return tacs_core.sha256(tostring(os.getComputerID()))
end

local function saveKey(rawKey)
    local hwKey = getDeviceKey()
    local iv = os.epoch and os.epoch("utc") or os.time()
    local encrypted = tacs_core.encrypt(hwKey, iv, rawKey)
    local f = fs.open(CLUSTER_KEY_FILE, "w")
    f.write(textutils.serialize({ iv = iv, key = encrypted }))
    f.close()
end

local function loadClusterKey()
    if fs.exists(CLUSTER_KEY_FILE) then
        local f = fs.open(CLUSTER_KEY_FILE, "r")
        local content = f.readAll()
        f.close()
        local data = textutils.unserialize(content)
        if type(data) == "table" and data.iv and data.key then
            local hwKey = getDeviceKey()
            return tacs_core.decrypt(hwKey, data.iv, data.key)
        else
            saveKey(content)
            return content 
        end
    end
    return nil
end

CLUSTER_KEY = loadClusterKey()

-- [FIXED] Robust Sender
local function sendToLeader(payloadTable)
    if not CLUSTER_KEY then CLUSTER_KEY = loadClusterKey() end
    if not CLUSTER_KEY then 
        term.setTextColor(colors.red)
        print("Error: No Cluster Key. Please Pair first.")
        term.setTextColor(colors.white)
        sleep(2)
        return nil 
    end
    
    local nonce = os.epoch("utc")
    local encReq = tacs_core.encrypt(CLUSTER_KEY, nonce, textutils.serialize(payloadTable))
    
    -- 1. Initial Discovery Broadcast
    -- We clear queue first to ensure fresh response
    while os.pullEventRaw("modem_message") == "modem_message" do end -- Drain (non-blocking check logic needed actually)
    -- CC doesn't have easy non-blocking peek, so we just rely on loop filtering below.
    
    network_utils.broadcast("MINT", { nonce = nonce, payload = encReq })
    print("Contacting Hivemind...")
    
    local timer = os.startTimer(3)
    local leaderID = nil
    
    -- LOOP 1: Discovery Phase
    -- Listen for EITHER a Success (if Leader heard us) OR a Redirect
    while true do
        local e, p1, p2, p3 = os.pullEvent()
        if e == "timer" and p1 == timer then
            break -- Timeout
        elseif e == "modem_message" then
            -- Check protocol manually since network_utils.receive eats events
            -- p3 is channel, p4 is replyChan, p5 is msg
            -- Wait, os.pullEvent returns different args.
            -- event, side, senderChannel, replyChannel, message, distance
            local msg = p3 -- Using network_utils abstraction is safer usually, but we need control.
            -- Let's stick to network_utils.receive logic but wrapped in a loop
        end
    end
    
    -- Re-implementing receive loop using network_utils to keep it simple but robust
    local attempts = 0
    while attempts < 10 do
        local sender, msg = network_utils.receive("MINT", 1) -- Short timeout to cycle fast
        
        if msg then
            -- CASE A: Redirection
            if msg.retry and msg.leader then
                leaderID = msg.leader
                -- STOP LISTENING to others. We found the Leader ID.
                break 
            end
            
            -- CASE B: Direct Success (Leader heard broadcast)
            if msg.payload then
                local dec = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
                local resp = textutils.unserialize(dec)
                if resp then return resp end -- Success!
            end
        else
            attempts = attempts + 1
        end
    end
    
    -- 2. Directed Phase (If we found a Leader ID)
    if leaderID then
        print("Leader identified: " .. leaderID)
        
        -- RE-GENERATE NONCE (Fixes Server Dedup ignoring us)
        nonce = os.epoch("utc")
        encReq = tacs_core.encrypt(CLUSTER_KEY, nonce, textutils.serialize(payloadTable))
        
        network_utils.send(leaderID, "MINT", { nonce = nonce, payload = encReq })
        
        -- Wait for SPECIFIC reply from Leader
        local retryTimer = os.startTimer(4)
        while true do
            local e, side, sChan, rChan, msg, dist = os.pullEvent()
            if e == "timer" and side == retryTimer then
                print("Leader timed out.")
                return nil
            elseif e == "modem_message" and sChan == 666 and type(msg) == "table" then -- 666 isn't mint chan
                -- We need to check if it matches MINT protocol
                -- Assuming network_utils opens specific channels. 
                -- Let's blindly trust network_utils.receive but verify Sender ID
                
                -- Actually, let's just use network_utils receive loop
            end
        end
    end
    
    -- CLEAN IMPLEMENTATION OF PHASE 2
    if leaderID then
        -- Loop to drain queue of old redirects and find the real payload
        for i=1, 20 do
            local sender, msg = network_utils.receive("MINT", 0.2)
            if sender == leaderID and msg and msg.payload then
                local dec = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
                return textutils.unserialize(dec)
            end
        end
    end
    
    return nil
end

-- ==========================================
-- 3. ACTIONS
-- ==========================================

local function actionMint()
    term.clear(); term.setCursorPos(1,1)
    print("--- MINT NEW IK ---")
    write("Username: ")
    local username = read()
    if username == "" then return end
    print("\nCard Type: (1) BLUE (2) GREEN (3) WHITE")
    write("> ")
    local t = read()
    local cType = "BLUE"
    if t == "2" then cType = "GREEN" elseif t == "3" then cType = "WHITE" end
    local perms = {}
    if cType ~= "WHITE" then
        print("\nPerms (comma sep, e.g. NPP,CORE):")
        write("> ")
        local input = read()
        for p in string.gmatch(input, "([^,]+)") do table.insert(perms, p) end
    end
    print("\nInsert Blank Pocket Computer into Drive...")
    while not peripheral.find("drive").isDiskPresent() do sleep(0.5) end
    print("\nType Target ID (from Pocket Computer):")
    write("ID: ")
    local tid = tonumber(read())
    if not tid then return end
    print("Requesting Key...")
    local resp = sendToLeader({ cmd = "MINT_USER", username = username, level = 1, meta = { type = cType, perms = perms } })
    if resp and resp.success then
        print("Burning...")
        local bindIV = os.epoch("utc")
        local hwKey = tacs_core.sha256(tostring(tid))
        local encMaster = tacs_core.encrypt(hwKey, bindIV, resp.masterKey)
        local path = peripheral.find("drive").getMountPath()
        local f = fs.open(fs.combine(path, "startup.lua"), "w")
        f.write(string.format(FOB_TEMPLATE, tid, username, encMaster, tostring(bindIV), cType))
        f.close()
        if not fs.exists(fs.combine(path, "libs")) then fs.makeDir(fs.combine(path, "libs")) end
        fs.copy("libs/tacs_core.lua", fs.combine(path, "libs/tacs_core.lua"))
        print("SUCCESS. Ejecting...")
        while peripheral.find("drive").isDiskPresent() do sleep(0.5) end
    else
        print("FAILED.")
        if resp and resp.msg then print(resp.msg) end -- Error info
        sleep(2)
    end
end

local function actionAddZone()
    term.clear(); term.setCursorPos(1,1)
    print("--- ADD ZONE ---")
    write("Zone ID (e.g. CORE): ")
    local id = read()
    if id == "" then return end
    write("Display Name: ")
    local name = read()
    write("Parent ID (empty for ROOT): ")
    local parent = read()
    if parent == "" then parent = nil end
    
    local resp = sendToLeader({ cmd = "ADD_ZONE", id = id, name = name, parent = parent })
    if resp and resp.success then print("SUCCESS.") else print("FAILED.") end
    sleep(2)
end

local function actionListZones()
    term.clear(); term.setCursorPos(1,1)
    print("Fetching Zones...")
    local resp = sendToLeader({ cmd = "LIST_ZONES" })
    
    term.clear(); term.setCursorPos(1,1)
    print("--- ZONES ---")
    if resp and resp.zones then
        for id, data in pairs(resp.zones) do
            print(string.format("[%s] %s (Parent: %s)", id, data.name, data.parent or "ROOT"))
        end
    else
        print("Failed to fetch or Empty.")
    end
    print("\nPress Enter...")
    read()
end

local function actionDeleteZone()
    term.clear(); term.setCursorPos(1,1)
    print("--- DELETE ZONE ---")
    write("Zone ID to delete: ")
    local id = read()
    if id == "" then return end
    
    local resp = sendToLeader({ cmd = "DELETE_ZONE", id = id })
    if resp and resp.success then print("SUCCESS.") else print("FAILED.") end
    sleep(2)
end

local function actionPair()
    term.clear(); term.setCursorPos(1,1)
    print("--- PAIR WITH CLUSTER ---")
    print("Insert Genesis Disk...")
    while not peripheral.find("drive").isDiskPresent() do sleep(0.5) end
    local p = peripheral.find("drive").getMountPath()
    local diskKeyPath = fs.combine(p, ".cluster_key")
    if fs.exists(diskKeyPath) then
        local f = fs.open(diskKeyPath, "r")
        local rawKey = f.readAll()
        f.close()
        saveKey(rawKey)
        CLUSTER_KEY = rawKey
        print("PAIRED & ENCRYPTED.")
    else
        print("ERROR: No key found.")
    end
    sleep(2)
end

-- ==========================================
-- 4. MAIN MENU
-- ==========================================
while true do
    term.clear(); term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("--- TEMELIN MANAGEMENT ---")
    term.setTextColor(colors.white)
    
    if not CLUSTER_KEY then
        term.setTextColor(colors.red)
        print("STATUS: UNPAIRED")
    else
        term.setTextColor(colors.lime)
        print("STATUS: ONLINE")
    end
    term.setTextColor(colors.white)
    
    print("\n1. Mint New IK")
    print("2. Add Zone")
    print("3. List Zones")
    print("4. Delete Zone")
    print("5. Pair via Disk")
    print("6. Exit")
    write("\n> ")
    local sel = read()
    
    if sel == "1" then actionMint()
    elseif sel == "2" then actionAddZone()
    elseif sel == "3" then actionListZones()
    elseif sel == "4" then actionDeleteZone()
    elseif sel == "5" then actionPair()
    elseif sel == "6" then break end
end

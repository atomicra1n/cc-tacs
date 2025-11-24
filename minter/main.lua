-- TACS MINTER TERMINAL v7.3 (NON-BLOCKING FIX)
-- Role: Issue Secure Cards & Manage Zones
-- Fixed: Removed blocking drain loop (Causing "Hang on Fetch")
-- Preserved: CEZ UI & Hex Encoding

os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")

local CLUSTER_KEY_FILE = ".cluster_key"
local CLUSTER_KEY = nil

-- ==========================================
-- 1. FOB FIRMWARE TEMPLATE (HEX SAFE + CEZ)
-- ==========================================
local FOB_TEMPLATE = [[
-- TACS SECURE FOB (ID: %d)
os.pullEvent = os.pullEventRaw 
local MY_ID = os.getComputerID()
local USERNAME = "%s"
local ENC_KEY_HEX = "%s" -- Hex Encoded
local NONCE_IV = "%s" 
local CARD_TYPE = "%s" 

-- UI Config
local ROLE_NAME = "NAVSTEVNIK"
local BG_COLOR = colors.white
local TXT_COLOR = colors.black

if CARD_TYPE == "BLUE" then 
    ROLE_NAME = "ZAMESTNANEC"
    BG_COLOR = colors.blue
    TXT_COLOR = colors.white
elseif CARD_TYPE == "GREEN" then 
    ROLE_NAME = "EXTERNISTA"
    BG_COLOR = colors.green
    TXT_COLOR = colors.white
end

if not fs.exists("libs/tacs_core.lua") then error("CRITICAL: Crypto Library Missing!") end
os.loadAPI("libs/tacs_core.lua")

-- Decrypt Key (From Hex)
local hw_key = tacs_core.sha256(tostring(MY_ID)) 
local enc_bytes = tacs_core.fromHex(ENC_KEY_HEX) 
local MASTER_KEY = tacs_core.decrypt(hw_key, NONCE_IV, enc_bytes)

if not MASTER_KEY or #MASTER_KEY == 0 then
    term.setBackgroundColor(colors.red)
    term.setTextColor(colors.white)
    term.clear()
    term.setCursorPos(1,1)
    print("CHYBA HARDWARE ID")
    print("Klonovani detekovano.")
    error()
end

local modem = peripheral.find("modem")
if not modem then print("Chyba: Zadne radio!"); return end
modem.open(666) 

-- === GUI RENDERER ===
local function drawUI(status)
    term.setBackgroundColor(BG_COLOR)
    term.setTextColor(TXT_COLOR)
    term.clear()
    
    local w, h = term.getSize()
    local function cPrint(y, text)
        local x = math.floor((w - #text) / 2) + 1
        term.setCursorPos(x, y)
        term.write(text)
    end

    -- CEZ ASCII ART
    local logoY = 2
    term.setCursorPos(2, logoY);   term.write("  #################")
    term.setCursorPos(2, logoY+1); term.write("  #")
    term.setCursorPos(2, logoY+2); term.write("  #   #############")
    term.setCursorPos(2, logoY+3); term.write("  #   #")
    term.setCursorPos(2, logoY+4); term.write("  #   #   #########")
    term.setCursorPos(2, logoY+5); term.write("  #   #")
    term.setCursorPos(2, logoY+6); term.write("  #   #############")
    term.setCursorPos(2, logoY+7); term.write("  #")
    term.setCursorPos(2, logoY+8); term.write("  #################")

    local y = 11
    cPrint(y, USERNAME)
    cPrint(y+1, "-----------------")
    cPrint(y+2, "Cislo IK: " .. MY_ID)
    cPrint(y+3, "-----------------")
    cPrint(y+4, "Jaderna elektrarna")
    cPrint(y+5, "Temelin")
    cPrint(y+6, "-----------------")
    
    -- Role / Status
    if status then
        term.setTextColor(colors.red)
        cPrint(y+8, status)
    else
        term.setTextColor(TXT_COLOR)
        cPrint(y+8, ROLE_NAME)
    end
end

drawUI()

while true do
    local e, side, sChan, rChan, msg, dist = os.pullEvent("modem_message")
    if type(msg) == "table" and msg.protocol == "TACS_AUTH_REQ" and msg.nonce then
        drawUI("VERIFIKACE...")
        local data = (msg.gate or "") .. tostring(msg.nonce)
        local sig = tacs_core.hmac(MASTER_KEY, data)
        modem.transmit(rChan, 666, { protocol = "TACS_AUTH_RESP", user = USERNAME, sig = sig, nonce = msg.nonce })
        sleep(0.5)
        drawUI("PRISTUP POVOLEN")
        sleep(2)
        drawUI() 
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

-- [FIXED] Robust Sender (Non-Blocking)
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
    
    -- [FIX] Drain queue using 0 timeout (Non-blocking)
    -- This instantly consumes old messages without waiting if empty
    while network_utils.receive("MINT", 0) do end
    
    network_utils.broadcast("MINT", { nonce = nonce, payload = encReq })
    print("Contacting Hivemind...")
    
    local leaderID = nil
    local attempts = 0
    while attempts < 8 do
        local sender, msg = network_utils.receive("MINT", 0.5)
        if msg then
            if msg.retry and msg.leader then
                leaderID = msg.leader
                print("Redirected to Leader: " .. leaderID)
                break 
            end
            if msg.payload then
                local dec = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
                return textutils.unserialize(dec)
            end
        end
        attempts = attempts + 1
    end
    
    if leaderID then
        print("Sending to Leader " .. leaderID .. "...")
        nonce = os.epoch("utc")
        encReq = tacs_core.encrypt(CLUSTER_KEY, nonce, textutils.serialize(payloadTable))
        
        -- Flush again before directed send
        while network_utils.receive("MINT", 0) do end
        
        network_utils.send(leaderID, "MINT", { nonce = nonce, payload = encReq })
        
        for i=1, 10 do
            local sender, msg = network_utils.receive("MINT", 0.5)
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
    
    local resp = sendToLeader({ cmd = "MINT_USER", username = username, level = 1, meta = { type = cType, perms = perms } })
    if resp and resp.success then
        print("Burning...")
        local bindIV = os.epoch("utc")
        local hwKey = tacs_core.sha256(tostring(tid))
        local encMaster = tacs_core.encrypt(hwKey, bindIV, resp.masterKey)
        
        -- HEX ENCODE
        local encHex = tacs_core.toHex(encMaster)
        
        local path = peripheral.find("drive").getMountPath()
        local f = fs.open(fs.combine(path, "startup.lua"), "w")
        f.write(string.format(FOB_TEMPLATE, tid, username, encHex, tostring(bindIV), cType))
        f.close()
        if not fs.exists(fs.combine(path, "libs")) then fs.makeDir(fs.combine(path, "libs")) end
        fs.copy("libs/tacs_core.lua", fs.combine(path, "libs/tacs_core.lua"))
        print("SUCCESS. Ejecting...")
        while peripheral.find("drive").isDiskPresent() do sleep(0.5) end
    else
        print("FAILED.")
        if resp and resp.msg then print(resp.msg) end 
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
        local count = 0
        for id, data in pairs(resp.zones) do
            print(string.format("[%s] %s (Parent: %s)", id, data.name, data.parent or "ROOT"))
            count = count + 1
        end
        if count == 0 then print("(No zones defined)") end
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

while true do
    term.clear(); term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("--- TEMELIN MANAGEMENT ---")
    term.setTextColor(colors.white)
    if not CLUSTER_KEY then term.setTextColor(colors.red); print("STATUS: UNPAIRED") else term.setTextColor(colors.lime); print("STATUS: ONLINE") end
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

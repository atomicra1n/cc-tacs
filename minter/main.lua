-- TACS MINTER TERMINAL v4.1 (TEMELIN FULL)
-- Role: Issue Secure Cards & Manage Zones
-- Dependencies: libs/tacs_core.lua, libs/network_utils.lua

os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")

local CLUSTER_KEY_FILE = ".cluster_key"
local CLUSTER_KEY = nil

-- ==========================================
-- 1. FOB FIRMWARE TEMPLATE
-- This code is written to the Pocket Computer
-- ==========================================
local FOB_TEMPLATE = [[
-- TACS SECURE FOB (ID: %d)
-- Bounded to Hardware ID. Cannot be cloned.

os.pullEvent = os.pullEventRaw -- Disable termination

local MY_ID = os.getComputerID()
local USERNAME = "%s"
local ENC_KEY = "%s" -- AES Encrypted Master Key
local NONCE_IV = "%s" -- IV for decryption
local CARD_TYPE = "%s" 

-- UI Colors
local BG_COLOR = colors.black
local TXT_COLOR = colors.white
if CARD_TYPE == "BLUE" then BG_COLOR = colors.blue
elseif CARD_TYPE == "GREEN" then BG_COLOR = colors.green
elseif CARD_TYPE == "WHITE" then BG_COLOR = colors.white; TXT_COLOR = colors.black end

-- Load Crypto
if not fs.exists("libs/tacs_core.lua") then
    error("CRITICAL: Crypto Library Missing!")
end
os.loadAPI("libs/tacs_core.lua")

-- 1. Decrypt Master Key using Hardware ID
-- This binds the software to THIS SPECIFIC computer.
local hw_key = tacs_core.sha256(tostring(MY_ID)) 
local MASTER_KEY = tacs_core.decrypt(hw_key, NONCE_IV, ENC_KEY)

if not MASTER_KEY or #MASTER_KEY == 0 then
    term.setBackgroundColor(colors.red)
    term.setTextColor(colors.white)
    term.clear()
    term.setCursorPos(1,1)
    print("SECURITY FATAL:")
    print("HARDWARE ID MISMATCH.")
    print("Cloning attempt detected.")
    print("System Halted.")
    error()
end

-- 2. Setup Modem
local modem = peripheral.find("modem")
if not modem then 
    term.clear()
    print("Error: No Wireless Modem!")
    return
end
modem.open(666) -- Public Auth Channel

-- 3. Main UI
term.setBackgroundColor(BG_COLOR)
term.setTextColor(TXT_COLOR)
term.clear()
term.setCursorPos(1,1)
print("TEMELIN IK: " .. CARD_TYPE)
print("User: " .. USERNAME)
print("Status: ARMED")

while true do
    local e, side, sChan, rChan, msg, dist = os.pullEvent("modem_message")
    
    -- Listen for Auth Requests from Turnstiles
    if type(msg) == "table" and msg.protocol == "TACS_AUTH_REQ" and msg.nonce then
        
        -- Visual Feedback
        term.setCursorPos(1,5)
        term.clearLine()
        print("Ping: " .. (msg.gate or "Unknown"))
        
        -- 4. CALCULATE HMAC SIGNATURE
        -- Signature = HMAC(Key, GateName + Nonce)
        local data = (msg.gate or "") .. tostring(msg.nonce)
        local sig = tacs_core.hmac(MASTER_KEY, data)
        
        -- 5. REPLY
        -- We send ONLY the signature. The Key never leaves this device.
        modem.transmit(rChan, 666, {
            protocol = "TACS_AUTH_RESP",
            user = USERNAME,
            sig = sig,
            nonce = msg.nonce -- Echo nonce for tracking
        })
        
        sleep(0.5)
        term.setCursorPos(1,5)
        term.clearLine()
        print("Status: ARMED")
    end
end
]]

-- ==========================================
-- 2. UTILITIES
-- ==========================================

local function loadClusterKey()
    if fs.exists(CLUSTER_KEY_FILE) then
        local f = fs.open(CLUSTER_KEY_FILE, "r")
        local k = f.readAll()
        f.close()
        return k
    end
    return nil
end

-- Handles finding the leader, encrypting requests, and retries
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
    
    -- Broadcast to find leader initially
    network_utils.broadcast("MINT", { nonce = nonce, payload = encReq })
    
    print("Contacting Hivemind...")
    local sender, msg = network_utils.receive("MINT", 5)
    
    if not msg then
        print("[TIMEOUT] No response from Cluster.")
        sleep(2)
        return nil
    end
    
    -- Handle Redirection (If we hit a Follower node)
    if msg.retry and msg.leader then
        print("Redirected to Leader Node: " .. msg.leader)
        network_utils.send(msg.leader, "MINT", { nonce = nonce, payload = encReq })
        sender, msg = network_utils.receive("MINT", 5)
    end
    
    -- Decrypt Response
    if msg and msg.payload then
        local dec = tacs_core.decrypt(CLUSTER_KEY, msg.nonce, msg.payload)
        local resp = textutils.unserialize(dec)
        return resp
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
        for p in string.gmatch(input, "([^,]+)") do 
            table.insert(perms, p) 
        end
    end
    
    print("\nInsert Blank Pocket Computer into Drive...")
    while not peripheral.find("drive").isDiskPresent() do sleep(0.5) end
    
    -- We need the ID to encrypt the key against it
    print("\n[IMPORTANT] Turn on the Pocket Computer.")
    print("Type the ID number displayed on it:")
    write("Target ID: ")
    local tid = tonumber(read())
    if not tid then 
        print("Invalid ID.")
        sleep(1)
        return 
    end
    
    print("Requesting Key from Hivemind...")
    
    -- Send Request to Leader
    local resp = sendToLeader({
        cmd = "MINT_USER",
        username = username,
        level = 1,
        meta = { type = cType, perms = perms }
    })
    
    if resp and resp.success then
        print("Key Received. Burning Fob...")
        
        -- Encrypt the received Master Key using the Fob's Hardware ID
        local bindIV = os.epoch("utc")
        local hwKey = tacs_core.sha256(tostring(tid))
        local encMaster = tacs_core.encrypt(hwKey, bindIV, resp.masterKey)
        
        -- Write Files to Disk
        local drive = peripheral.find("drive")
        local path = drive.getMountPath()
        
        -- 1. Write Startup Script
        local f = fs.open(fs.combine(path, "startup.lua"), "w")
        f.write(string.format(FOB_TEMPLATE, tid, username, encMaster, tostring(bindIV), cType))
        f.close()
        
        -- 2. Install Crypto Library on Fob
        if not fs.exists(fs.combine(path, "libs")) then
            fs.makeDir(fs.combine(path, "libs"))
        end
        fs.copy("libs/tacs_core.lua", fs.combine(path, "libs/tacs_core.lua"))
        
        term.setTextColor(colors.lime)
        print("SUCCESS. Fob Created.")
        term.setTextColor(colors.white)
        print("Please remove the device.")
        
        while drive.isDiskPresent() do sleep(0.5) end
    else
        term.setTextColor(colors.red)
        print("FAILED.")
        if resp and resp.msg then print("Reason: " .. resp.msg) end
        term.setTextColor(colors.white)
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
    
    print("Sending to Hivemind...")
    
    local resp = sendToLeader({
        cmd = "ADD_ZONE",
        id = id,
        name = name,
        parent = parent
    })
    
    if resp and resp.success then
        term.setTextColor(colors.lime)
        print("SUCCESS: Zone Added.")
    else
        term.setTextColor(colors.red)
        print("FAILED.")
    end
    term.setTextColor(colors.white)
    sleep(2)
end

local function actionPair()
    term.clear(); term.setCursorPos(1,1)
    print("--- PAIR WITH CLUSTER ---")
    print("Please insert the Genesis Floppy Disk.")
    print("Waiting for disk...")
    
    while not peripheral.find("drive").isDiskPresent() do sleep(0.5) end
    
    local p = peripheral.find("drive").getMountPath()
    if fs.exists(fs.combine(p, ".cluster_key")) then
        fs.copy(fs.combine(p, ".cluster_key"), ".cluster_key")
        CLUSTER_KEY = loadClusterKey()
        term.setTextColor(colors.lime)
        print("PAIRED SUCCESSFULLY.")
    else
        term.setTextColor(colors.red)
        print("ERROR: .cluster_key not found on disk.")
    end
    term.setTextColor(colors.white)
    sleep(2)
end

-- ==========================================
-- 4. MAIN MENU
-- ==========================================
while true do
    term.clear(); term.setCursorPos(1,1)
    term.setTextColor(colors.yellow)
    print("--- TEMELIN MANAGEMENT TERMINAL ---")
    term.setTextColor(colors.white)
    
    if not CLUSTER_KEY then
        term.setTextColor(colors.red)
        print("STATUS: UNPAIRED")
    else
        term.setTextColor(colors.lime)
        print("STATUS: ONLINE")
    end
    term.setTextColor(colors.white)
    
    print("")
    print("1. Mint New IK")
    print("2. Add/Edit Zone")
    print("3. Pair via Disk")
    print("4. Exit")
    print("")
    write("> ")
    local sel = read()
    
    if sel == "1" then actionMint()
    elseif sel == "2" then actionAddZone()
    elseif sel == "3" then actionPair()
    elseif sel == "4" then break end
end

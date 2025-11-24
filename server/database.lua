-- TACS DATABASE MANAGER v8.0 (STATE MACHINE)
-- Features: Device-Bound Key Storage, State Machine Logic

os.loadAPI("libs/tacs_core.lua")

local DB_FILE = "tacs_users.db"
local NODES_FILE = "tacs_nodes.db"
local ZONES_FILE = "tacs_zones.db"
local TRACK_FILE = "tacs_tracking.db"
local KEY_FILE = ".cluster_key"

-- === CACHES ===
local MEMORY_NODES = {}
local USERS = {}
local ZONES = {} 
local TRACKING = {} 

-- === INIT ===
local function init()
    if fs.exists(NODES_FILE) then
        local f = fs.open(NODES_FILE, "r")
        local data = textutils.unserializeJSON(f.readAll())
        f.close()
        if data then
            for k,v in pairs(data) do 
                local numID = tonumber(k)
                if numID then MEMORY_NODES[numID] = v end
            end
        end
    end
    -- Self-register
    MEMORY_NODES[os.getComputerID()] = os.epoch and os.epoch("utc") or os.time()

    if fs.exists(DB_FILE) then
        local f = fs.open(DB_FILE, "r")
        USERS = textutils.unserializeJSON(f.readAll()) or {}
        f.close()
    end

    if fs.exists(ZONES_FILE) then
        local f = fs.open(ZONES_FILE, "r")
        ZONES = textutils.unserializeJSON(f.readAll()) or {}
        f.close()
    else
        ZONES["NPP"] = { name="Temelin NPP", parent=nil }
    end
end
init()

-- === PERSISTENCE HELPER ===
local function save(file, data)
    local f = fs.open(file, "w")
    f.write(textutils.serializeJSON(data))
    f.close()
end

-- === READ API (Safe to call anytime) ===
function getUser(username) return USERS[username] end
function getAllUsers() return USERS end
function getZone(id) return ZONES[id] end
function getAllZones() return ZONES end

function getNodeCount()
    local count = 0
    for _ in pairs(MEMORY_NODES) do count = count + 1 end
    return count
end

function loadNodes() return MEMORY_NODES end

-- === STATE MACHINE APPLICATION (CRITICAL) ===
-- This is called ONLY by consensus.lua when a log entry is COMMITTED.
function apply(command)
    if not command or type(command) ~= "table" then return false end
    
    if command.cmd == "MINT_USER" then
        USERS[command.username] = command.data
        save(DB_FILE, USERS)
        print("[DB] Applied: User " .. command.username)
        return true
        
    elseif command.cmd == "ADD_ZONE" then
        ZONES[command.id] = { name=command.name, parent=command.parent }
        save(ZONES_FILE, ZONES)
        print("[DB] Applied: Zone " .. command.name)
        return true
        
    elseif command.cmd == "DELETE_ZONE" then
        ZONES[command.id] = nil
        save(ZONES_FILE, ZONES)
        print("[DB] Applied: Delete Zone " .. command.id)
        return true
        
    elseif command.cmd == "TRACK_UPDATE" then
        if not TRACKING[command.user] then TRACKING[command.user] = {} end
        TRACKING[command.user].zone = command.zone
        -- Tracking is volatile, maybe don't save to disk constantly to save I/O
        -- save(TRACK_FILE, TRACKING) 
        return true
    end
    
    return false
end

-- === NODE & TRACKING UTILS ===
function touchNode(id)
    local now = os.epoch and os.epoch("utc") or os.time()
    local numID = tonumber(id)
    if not numID then return end
    if not MEMORY_NODES[numID] then
        MEMORY_NODES[numID] = now
        save(NODES_FILE, MEMORY_NODES)
    else
        MEMORY_NODES[numID] = now
    end
end

function pruneDeadNodes(timeout)
    local now = os.epoch and os.epoch("utc") or os.time()
    local prunedCount = 0
    local saveNeeded = false
    for id, lastSeen in pairs(MEMORY_NODES) do
        if id ~= os.getComputerID() then
            if (now - lastSeen) > timeout then
                MEMORY_NODES[id] = nil
                prunedCount = prunedCount + 1
                saveNeeded = true
            end
        end
    end
    if saveNeeded then save(NODES_FILE, MEMORY_NODES) end
    return prunedCount
end

-- === KEY API (ENCRYPTED) ===
local function getDeviceKey()
    return tacs_core.sha256(tostring(os.getComputerID()))
end

function saveKey(rawKey)
    local hwKey = getDeviceKey()
    local iv = os.epoch and os.epoch("utc") or os.time()
    local encrypted = tacs_core.encrypt(hwKey, iv, rawKey)
    
    local f = fs.open(KEY_FILE, "w")
    f.write(textutils.serialize({ iv = iv, key = encrypted }))
    f.close()
end

function getKey()
    if fs.exists(KEY_FILE) then
        local f = fs.open(KEY_FILE, "r")
        local content = f.readAll()
        f.close()
        
        local data = textutils.unserialize(content)
        if type(data) == "table" and data.iv and data.key then
            local hwKey = getDeviceKey()
            return tacs_core.decrypt(hwKey, data.iv, data.key)
        else
            -- Migration path
            saveKey(content)
            return content 
        end
    end
    return nil
end

function genKey()
    if fs.exists(KEY_FILE) then return getKey() end
    local key = tacs_core.randomBytes(32)
    saveKey(key)
    return key
end
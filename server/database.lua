-- TACS DATABASE MANAGER v5.0 (SNAPSHOT READY)
-- Supports Full State Dump & Restore for new nodes

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

-- === SNAPSHOT API (NEW) ===
function isEmpty()
    local uCount = 0
    for _ in pairs(USERS) do uCount = uCount + 1 end
    -- If only default zone exists and no users, we consider it empty/fresh
    return uCount == 0
end

function dumpState()
    return {
        users = USERS,
        zones = ZONES
    }
end

function restoreState(dumpData)
    if not dumpData then return false end
    
    if dumpData.users then
        USERS = dumpData.users
        save(DB_FILE, USERS)
    end
    
    if dumpData.zones then
        ZONES = dumpData.zones
        save(ZONES_FILE, ZONES)
    end
    
    return true
end

-- === USER API ===
function getUser(username) return USERS[username] end
function setUser(username, data)
    USERS[username] = data
    save(DB_FILE, USERS)
end
function getAllUsers() return USERS end

-- === ZONE API ===
function getZone(id) return ZONES[id] end
function setZone(id, name, parent)
    ZONES[id] = { name=name, parent=parent }
    save(ZONES_FILE, ZONES)
end
function getAllZones() return ZONES end
function getParent(zoneID) 
    if ZONES[zoneID] then return ZONES[zoneID].parent end
    return nil
end

-- === TRACKING API ===
function getLoc(user) 
    if not TRACKING[user] then return nil end
    return TRACKING[user].zone 
end

function updateLoc(user, zoneID)
    if not TRACKING[user] then TRACKING[user] = {} end
    TRACKING[user].zone = zoneID
    save(TRACK_FILE, TRACKING)
end

function linkEscort(visitor, escort)
    if not TRACKING[visitor] then TRACKING[visitor] = {} end
    if not TRACKING[escort] then TRACKING[escort] = {} end
    TRACKING[visitor].escortedBy = escort
    if not TRACKING[escort].escorting then TRACKING[escort].escorting = {} end
    TRACKING[escort].escorting[visitor] = true
    save(TRACK_FILE, TRACKING)
end

function unlinkEscort(visitor, escort)
    if TRACKING[visitor] then TRACKING[visitor].escortedBy = nil end
    if TRACKING[escort] and TRACKING[escort].escorting then
        TRACKING[escort].escorting[visitor] = nil
    end
    save(TRACK_FILE, TRACKING)
end

function getEscortStatus(user)
    return TRACKING[user] or {}
end

-- === NODE API ===
function loadNodes() return MEMORY_NODES end
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
function getNodeCount()
    local count = 0
    for _ in pairs(MEMORY_NODES) do count = count + 1 end
    return count
end

-- === KEY API ===
function getKey()
    if fs.exists(KEY_FILE) then
        local f = fs.open(KEY_FILE, "r")
        local k = f.readAll()
        f.close()
        return k
    end
    return nil
end
function genKey()
    if fs.exists(KEY_FILE) then return getKey() end
    print("GENESIS: Generating new Cluster Key...")
    local key = tacs_core.randomBytes(32)
    local f = fs.open(KEY_FILE, "w")
    f.write(key)
    f.close()
    return key
end

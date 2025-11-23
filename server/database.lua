-- TACS DATABASE MANAGER v3.1 (STRICT NUMBERS)
-- Enforces Number IDs to prevent String/Number duplicates

os.loadAPI("libs/tacs_core.lua")

local DB_FILE = "tacs_users.db"
local NODES_FILE = "tacs_nodes.db"
local KEY_FILE = ".cluster_key"

-- === IN-MEMORY CACHE ===
local MEMORY_NODES = {}

local function initNodeCache()
    -- Always track self
    MEMORY_NODES[os.getComputerID()] = os.epoch and os.epoch("utc") or os.time()
    
    if fs.exists(NODES_FILE) then
        local f = fs.open(NODES_FILE, "r")
        local data = textutils.unserializeJSON(f.readAll())
        f.close()
        if data then
            for k,v in pairs(data) do 
                -- FORCE NUMBER ID
                local numID = tonumber(k)
                if numID then
                    MEMORY_NODES[numID] = os.epoch and os.epoch("utc") or os.time()
                end
            end
        end
    end
end
initNodeCache()

-- === USER MANAGEMENT ===
function loadUsers()
    if not fs.exists(DB_FILE) then return {} end
    local f = fs.open(DB_FILE, "r")
    local data = textutils.unserializeJSON(f.readAll())
    f.close()
    return data
end

function saveUsers(data)
    local f = fs.open(DB_FILE, "w")
    f.write(textutils.serializeJSON(data))
    f.close()
end

-- === CLUSTER NODE MANAGEMENT ===

function loadNodes()
    return MEMORY_NODES
end

function touchNode(id)
    local now = os.epoch and os.epoch("utc") or os.time()
    local numID = tonumber(id) -- Ensure Number
    
    if not numID then return end -- Ignore weird inputs

    if not MEMORY_NODES[numID] then
        MEMORY_NODES[numID] = now
        -- Persist to disk
        local f = fs.open(NODES_FILE, "w")
        f.write(textutils.serializeJSON(MEMORY_NODES))
        f.close()
    else
        MEMORY_NODES[numID] = now
    end
end

function pruneDeadNodes(timeout)
    local now = os.epoch and os.epoch("utc") or os.time()
    local prunedCount = 0
    local saveNeeded = false
    local prunedIDs = ""
    
    for id, lastSeen in pairs(MEMORY_NODES) do
        if id ~= os.getComputerID() then
            if (now - lastSeen) > timeout then
                -- Log the specific ID being killed
                prunedIDs = prunedIDs .. id .. " "
                MEMORY_NODES[id] = nil
                prunedCount = prunedCount + 1
                saveNeeded = true
            end
        end
    end
    
    if saveNeeded then
        print("[DB] Pruning IDs: " .. prunedIDs) -- VISIBLE DEBUGGING
        local f = fs.open(NODES_FILE, "w")
        f.write(textutils.serializeJSON(MEMORY_NODES))
        f.close()
    end
    
    return prunedCount
end

function getNodeCount()
    local count = 0
    for _ in pairs(MEMORY_NODES) do count = count + 1 end
    return count
end

-- === KEY MANAGEMENT ===
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

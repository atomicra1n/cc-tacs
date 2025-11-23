-- TACS DATABASE MANAGER v2.0 (HARDENED)
-- Tracks Node Health & Timestamps

os.loadAPI("libs/tacs_core.lua")

local DB_FILE = "tacs_users.db"
local NODES_FILE = "tacs_nodes.db"
local KEY_FILE = ".cluster_key"

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

-- === CLUSTER NODE MANAGEMENT (ACTIVE HEALTH) ===

-- Loads table: { [id] = timestamp_last_seen }
function loadNodes()
    local nodes = {}
    -- Always include ourselves with current time so we don't prune ourselves
    nodes[os.getComputerID()] = os.epoch and os.epoch("utc") or os.time()
    
    if fs.exists(NODES_FILE) then
        local f = fs.open(NODES_FILE, "r")
        local data = textutils.unserializeJSON(f.readAll())
        f.close()
        -- Merge saved nodes
        for k,v in pairs(data) do nodes[tonumber(k)] = v end
    end
    return nodes
end

-- Updates the "Last Seen" timestamp for a node
function touchNode(id)
    local nodes = loadNodes()
    local now = os.epoch and os.epoch("utc") or os.time()
    
    nodes[id] = now
    
    local f = fs.open(NODES_FILE, "w")
    f.write(textutils.serializeJSON(nodes))
    f.close()
end

-- Removes nodes we haven't heard from in 'timeout' milliseconds/seconds
function pruneDeadNodes(timeout)
    local nodes = loadNodes()
    local now = os.epoch and os.epoch("utc") or os.time()
    local changed = false
    local count = 0
    
    for id, lastSeen in pairs(nodes) do
        -- Skip self
        if id ~= os.getComputerID() then
            if (now - lastSeen) > timeout then
                print("[DB] Pruning Dead Node: " .. id)
                nodes[id] = nil
                changed = true
            else
                count = count + 1
            end
        else
            count = count + 1
        end
    end
    
    if changed then
        local f = fs.open(NODES_FILE, "w")
        f.write(textutils.serializeJSON(nodes))
        f.close()
    end
    
    return count
end

function getNodeCount()
    local nodes = loadNodes()
    local count = 0
    for _ in pairs(nodes) do count = count + 1 end
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

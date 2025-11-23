-- TACS DATABASE MANAGER
-- Handles JSON storage for Users and System Keys

local DB_FILE = "tacs_users.db"
local KEY_FILE = ".cluster_key"
local core = require("libs/tacs_core") -- Crypto dependency

local function loadUsers()
    if not fs.exists(DB_FILE) then return {} end
    local f = fs.open(DB_FILE, "r")
    local data = textutils.unserializeJSON(f.readAll())
    f.close()
    return data
end

local function saveUsers(data)
    local f = fs.open(DB_FILE, "w")
    f.write(textutils.serializeJSON(data))
    f.close()
end

-- === CLUSTER KEY MANAGEMENT ===
-- The Cluster Key allows servers to trust each other and the Minter.
-- It is generated once on the first server ("Genesis") and copied to others via disk.

local function loadClusterKey()
    if fs.exists(KEY_FILE) then
        local f = fs.open(KEY_FILE, "r")
        local k = f.readAll()
        f.close()
        return k
    end
    return nil
end

local function generateClusterKey()
    if fs.exists(KEY_FILE) then return loadClusterKey() end
    
    print("GENESIS: Generating new Cluster Key...")
    local key = core.randomBytes(32) -- 256-bit Key
    
    local f = fs.open(KEY_FILE, "w")
    f.write(key)
    f.close()
    
    return key
end

return {
    load = loadUsers,
    save = saveUsers,
    getKey = loadClusterKey,
    genKey = generateClusterKey
}

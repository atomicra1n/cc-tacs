os.loadAPI("libs/tacs_core.lua")

local DB_FILE = "tacs_users.db"
local KEY_FILE = ".cluster_key"

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

os.loadAPI("libs/tacs_core.lua")

-- Files that define the "Identity" of the system
-- If any of these change, the hash changes.
local CRITICAL_FILES = {
    "startup.lua",
    "server/main.lua",
    "server/database.lua",
    "server/consensus.lua",
    "server/integrity.lua",
    "libs/tacs_core.lua",
    "libs/network_utils.lua"
}

local cached_hash = nil

local function generateSystemHash()
    print("[INTEGRITY] Scanning filesystem...")
    local massive_string = ""
    
    -- We must process files in a deterministic order
    table.sort(CRITICAL_FILES)
    
    for _, path in ipairs(CRITICAL_FILES) do
        if fs.exists(path) then
            local f = fs.open(path, "r")
            local content = f.readAll()
            f.close()
            
            -- We hash the path AND the content
            -- This prevents file swapping attacks
            massive_string = massive_string .. path .. ":" .. content .. "|"
        else
            -- If a file is missing, that is also a unique state
            massive_string = massive_string .. path .. ":MISSING|"
        end
    end
    
    -- Generate final SHA-256 of the entire codebase
    local final_hash = tacs_core.sha256(massive_string)
    print("[INTEGRITY] Checksum: " .. string.sub(final_hash, 1, 8))
    return final_hash
end

function getHash()
    if not cached_hash then
        cached_hash = generateSystemHash()
    end
    return cached_hash
end

-- Force a re-check (useful after an update)
function refresh()
    cached_hash = generateSystemHash()
    return cached_hash
end

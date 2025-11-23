-- TACS AUTO-UPDATER & BOOTSTRAPPER

-- === CONFIGURATION ===
-- Set the role for this specific machine here as per manifest
local ROLE = "turnstile" 

-- GitHub Repository Details
local REPO_USER = "atomicra1n"
local REPO_NAME = "cc-tacs"
local BRANCH = "main"

-- How often to check for updates (in seconds)
local UPDATE_INTERVAL = 300 -- 5 minutes

-- ======================
local BASE_URL = "https://raw.githubusercontent.com/" .. REPO_USER .. "/" .. REPO_NAME .. "/" .. BRANCH .. "/"
local MANIFEST_FILE = ".tacs_manifest" -- Stores local version info

-- UTILITIES
local function download(url, path)
    print("Downloading: " .. path)
    local response = http.get(url)
    if not response then
        print("Error: Failed to download " .. url)
        return false
    end
    
    local content = response.readAll()
    response.close()
    
    local file = fs.open(path, "w")
    file.write(content)
    file.close()
    return true
end

local function loadManifest()
    if not fs.exists(MANIFEST_FILE) then return { version = 0 } end
    local f = fs.open(MANIFEST_FILE, "r")
    local data = textutils.unserialize(f.readAll())
    f.close()
    return data
end

local function saveManifest(data)
    local f = fs.open(MANIFEST_FILE, "w")
    f.write(textutils.serialize(data))
    f.close()
end

-- UPDATE LOGIC
local function performUpdate()
    print("Checking for updates...")
    
    -- Get Remote Manifest
    local response = http.get(BASE_URL .. "manifest.json")
    if not response then
        print("Server unreachable. Skipping update check.")
        return false 
    end
    
    local remoteJson = response.readAll()
    response.close()
    
    local remoteManifest = textutils.unserializeJSON(remoteJson)
    if not remoteManifest then
        print("Error parsing remote manifest.")
        return false
    end

    -- Compare Versions
    local localManifest = loadManifest()
    if remoteManifest.version <= localManifest.version then
        return false -- No update needed
    end

    print("New version found: v" .. remoteManifest.version)
    print("Starting Update Process...")

    -- Download Common Libraries
    for _, file in pairs(remoteManifest.common) do
        download(BASE_URL .. file, file)
    end

    -- Download Role-Specific Files
    local roleFiles = remoteManifest.roles[ROLE]
    if roleFiles then
        for _, file in pairs(roleFiles) do
            download(BASE_URL .. file, file)
        end
    else
        print("Warning: No files defined for role '"..ROLE.."'")
    end

    -- Update Local Version Record
    localManifest.version = remoteManifest.version
    localManifest.entry = remoteManifest.entrypoints[ROLE]
    saveManifest(localManifest)
    
    print("Update Complete. Rebooting...")
    sleep(1)
    os.reboot()
    return true
end

-- APP RUNNER
local function runApplication()
    local data = loadManifest()
    if not data.entry or not fs.exists(data.entry) then
        print("No application installed. Waiting for update...")
        return
    end
    
    -- Run the role's main file
    print("Starting TACS Role: " .. ROLE)
    -- We use dofile to run it in this thread
    dofile(data.entry)
end

local function updateLoop()
    while true do
        performUpdate() -- Check immediately on boot
        sleep(UPDATE_INTERVAL)
    end
end

-- MAIN EXECUTION
term.clear()
term.setCursorPos(1,1)
print("--- TACS BOOTSTRAPPER ---")

-- We run the app and the updater in parallel.
-- If the updater finds a new version, it reboots the whole computer,
-- effectively killing the running app and restarting into the new one.
parallel.waitForAny(
    function() 
        -- Attempt update on first boot before running app
        if not performUpdate() then
            runApplication()
        end
    end,
    function() 
        -- Wait initial interval then loop
        sleep(UPDATE_INTERVAL) 
        updateLoop() 
    end
)

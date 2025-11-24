os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")
os.loadAPI("server/database.lua")
os.loadAPI("server/integrity.lua")

-- === CONFIGURATION ===
local HEARTBEAT_INTERVAL = 2   
local ELECTION_TIMEOUT_MIN = 4 
local ELECTION_TIMEOUT_MAX = 7
local PRUNE_INTERVAL = 15 
local NODE_TIMEOUT = 30000 -- 30s
if not os.epoch then NODE_TIMEOUT = 30 end 

local CLUSTER_KEY = database.getKey()
if not CLUSTER_KEY then error("Consensus failed: No Cluster Key loaded.") end

-- === STATE ===
local state = {
    term = 0,           
    role = "FOLLOWER",  
    votedFor = nil,     
    leaderID = nil,
    
    -- Volatile State
    lastHeartbeat = os.clock(),
    commitIndex = 0,
    lastApplied = 0,
    
    -- Leader State
    nextIndex = {},
    matchIndex = {},
    
    -- Persistent Log
    log = {} -- Array of { term=T, cmd=Command }
}

-- === PERSISTENCE ===
local function saveState()
    local f = fs.open(".raft_state", "w")
    f.write(textutils.serialize({term = state.term, votedFor = state.votedFor}))
    f.close()
end

local function saveLog()
    local f = fs.open(".raft_log", "w")
    f.write(textutils.serialize(state.log))
    f.close()
end

local function loadState()
    if fs.exists(".raft_state") then
        local f = fs.open(".raft_state", "r")
        local data = textutils.unserialize(f.readAll())
        f.close()
        state.term = data.term
        state.votedFor = data.votedFor
    end
    if fs.exists(".raft_log") then
        local f = fs.open(".raft_log", "r")
        local l = textutils.unserialize(f.readAll())
        f.close()
        state.log = l or {}
    end
end
loadState()

-- === UTILITIES ===
local function logMsg(msg)
    print(string.format("[%s|T%d] %s", state.role, state.term, msg))
end

local function getQuorum()
    local total = database.getNodeCount()
    local quorum = math.floor(total / 2) + 1
    return quorum, total
end

local function resetElectionTimer()
    state.lastHeartbeat = os.clock()
    state.timeoutDuration = math.random(ELECTION_TIMEOUT_MIN * 10, ELECTION_TIMEOUT_MAX * 10) / 10
end
resetElectionTimer()

local function getLastLogIndex()
    return #state.log
end

local function getLastLogTerm()
    if #state.log > 0 then return state.log[#state.log].term end
    return 0
end

-- === SECURE COMMS ===
local function sendSecure(targetID, msgTable)
    local nonce = os.epoch and os.epoch("utc") or os.time()
    local payload = textutils.serialize(msgTable)
    local encrypted = tacs_core.encrypt(CLUSTER_KEY, nonce, payload)
    network_utils.send(targetID, "CLUSTER", { nonce = nonce, payload = encrypted })
end

local function broadcastSecure(msgTable)
    local nonce = os.epoch and os.epoch("utc") or os.time()
    local payload = textutils.serialize(msgTable)
    local encrypted = tacs_core.encrypt(CLUSTER_KEY, nonce, payload)
    network_utils.broadcast("CLUSTER", { nonce = nonce, payload = encrypted })
end

-- === STATE MACHINE APPLIER ===
local function applyCommits()
    while state.commitIndex > state.lastApplied do
        state.lastApplied = state.lastApplied + 1
        local entry = state.log[state.lastApplied]
        if entry then
            logMsg("Applying Log #" .. state.lastApplied)
            database.apply(entry.cmd)
        end
    end
end

-- === PUBLIC API ===
function propose(cmd)
    if state.role ~= "LEADER" then return false end
    
    table.insert(state.log, { term = state.term, cmd = cmd })
    saveLog()
    
    local myID = os.getComputerID()
    state.matchIndex[myID] = #state.log
    state.nextIndex[myID] = #state.log + 1
    
    logMsg("Proposing Log #" .. #state.log)
    return true
end

-- === HANDLERS ===

function handleRequestVote(senderID, msg)
    database.touchNode(senderID)
    
    -- SOFT INTEGRITY CHECK
    local myHash = integrity.getHash()
    if msg.codeHash ~= myHash then
        logMsg("WARN: Voter " .. senderID .. " hash mismatch! (Allowing vote)")
    end
    
    if msg.term > state.term then
        state.term = msg.term
        state.role = "FOLLOWER"
        state.votedFor = nil
        saveState()
    end
    
    local lastLogIdx = getLastLogIndex()
    local lastLogTerm = getLastLogTerm()
    
    local logOk = (msg.lastLogTerm > lastLogTerm) or 
                  (msg.lastLogTerm == lastLogTerm and msg.lastLogIndex >= lastLogIdx)
    
    local grant = false
    if msg.term == state.term and logOk and (state.votedFor == nil or state.votedFor == senderID) then
        state.votedFor = senderID
        saveState()
        grant = true
        resetElectionTimer()
    end
    
    sendSecure(senderID, { type="VOTE_RESP", term=state.term, voteGranted=grant })
end

function handleAppendEntries(senderID, msg)
    database.touchNode(senderID)
    
    if msg.term < state.term then
        sendSecure(senderID, { type="APPEND_RESP", term=state.term, success=false })
        return
    end
    
    state.term = msg.term
    state.role = "FOLLOWER"
    state.leaderID = senderID
    resetElectionTimer()
    saveState()
    
    -- Log Consistency Check
    if msg.prevLogIndex > 0 then
        local entry = state.log[msg.prevLogIndex]
        if not entry or entry.term ~= msg.prevLogTerm then
            -- Log mismatch, reject so Leader backs up
            sendSecure(senderID, { type="APPEND_RESP", term=state.term, success=false, index=msg.prevLogIndex })
            return
        end
    end
    
    -- Append New Entries
    if msg.entries then
        for i, entry in ipairs(msg.entries) do
            local idx = msg.prevLogIndex + i
            if state.log[idx] and state.log[idx].term ~= entry.term then
                -- Conflict: Delete existing and all that follow
                for j = idx, #state.log do state.log[j] = nil end
            end
            if not state.log[idx] then
                state.log[idx] = entry
                saveLog()
            end
        end
    end
    
    -- Commit Index Update
    if msg.leaderCommit > state.commitIndex then
        state.commitIndex = math.min(msg.leaderCommit, getLastLogIndex())
        applyCommits()
    end
    
    sendSecure(senderID, { 
        type="APPEND_RESP", 
        term=state.term, 
        success=true, 
        matchIndex = getLastLogIndex() 
    })
end

function handleAppendResponse(senderID, msg)
    database.touchNode(senderID)
    if state.role ~= "LEADER" then return end
    
    if msg.term > state.term then
        state.term = msg.term
        state.role = "FOLLOWER"
        saveState()
        return
    end
    
    if msg.success then
        state.matchIndex[senderID] = msg.matchIndex
        state.nextIndex[senderID] = msg.matchIndex + 1
        
        -- Check if we can commit
        local quorum = getQuorum()
        for N = getLastLogIndex(), state.commitIndex + 1, -1 do
            local count = 1 -- Self
            for id, _ in pairs(database.loadNodes()) do
                if id ~= os.getComputerID() and (state.matchIndex[id] or 0) >= N then
                    count = count + 1
                end
            end
            
            if count >= quorum and state.log[N].term == state.term then
                state.commitIndex = N
                applyCommits()
                break
            end
        end
    else
        -- Backoff optimization
        state.nextIndex[senderID] = math.max(1, state.nextIndex[senderID] - 1)
        -- In production Raft, we would use msg.index to jump back faster
    end
end

-- === LOOPS ===

local function runLeader()
    local myID = os.getComputerID()
    state.nextIndex = {}
    state.matchIndex = {}
    for id, _ in pairs(database.loadNodes()) do
        state.nextIndex[id] = getLastLogIndex() + 1
        state.matchIndex[id] = 0
    end
    
    logMsg("LEADER ELECTED")
    
    while state.role == "LEADER" do
        for id, _ in pairs(database.loadNodes()) do
            if id ~= myID then
                local nextIdx = state.nextIndex[id] or 1
                local prevIdx = nextIdx - 1
                local prevTerm = 0
                if prevIdx > 0 and state.log[prevIdx] then prevTerm = state.log[prevIdx].term end
                
                -- Prepare batch of entries to send
                local entriesToSend = {}
                for i = nextIdx, getLastLogIndex() do
                    table.insert(entriesToSend, state.log[i])
                end
                
                sendSecure(id, {
                    type = "APPEND_ENTRIES",
                    term = state.term,
                    leaderID = myID,
                    prevLogIndex = prevIdx,
                    prevLogTerm = prevTerm,
                    entries = entriesToSend,
                    leaderCommit = state.commitIndex
                })
            end
        end
        sleep(HEARTBEAT_INTERVAL)
    end
end

local function runCandidate()
    state.term = state.term + 1
    state.votedFor = os.getComputerID() 
    saveState()
    
    local myID = os.getComputerID()
    local votes = 1
    logMsg("CANDIDATE (Term " .. state.term .. ")")

    broadcastSecure({
        type = "REQUEST_VOTE",
        term = state.term,
        candidateID = myID,
        lastLogIndex = getLastLogIndex(),
        lastLogTerm = getLastLogTerm(),
        codeHash = integrity.getHash()
    })

    local timer = os.startTimer(state.timeoutDuration)
    while state.role == "CANDIDATE" do
        local e, p1, p2, p3 = os.pullEvent()
        if e == "timer" and p1 == timer then return end
        if e == "modem_message" then
            local msg = p3
            if type(msg) == "table" and msg.type == "VOTE_RESP" and msg.term == state.term and msg.voteGranted then
                votes = votes + 1
                local quorum = getQuorum()
                if votes >= quorum then
                    state.role = "LEADER"
                    return
                end
            end
        end
    end
end

local function runFollower()
    while state.role == "FOLLOWER" do
        if (os.clock() - state.lastHeartbeat) > state.timeoutDuration then
            logMsg("Timeout. Converting to Candidate.")
            state.role = "CANDIDATE"
        end
        sleep(0.5)
    end
end

local function pruneLoop()
    while true do
        sleep(PRUNE_INTERVAL)
        local pruned = database.pruneDeadNodes(NODE_TIMEOUT)
        if pruned > 0 then logMsg("Pruned " .. pruned .. " dead nodes.") end
    end
end

-- === MAIN PROCESS ===
function start()
    integrity.getHash() 
    
    -- Initial Beacon
    broadcastSecure({ type="CLUSTER_JOIN", id=os.getComputerID() })
    
    parallel.waitForAll(
        function()
            while true do
                if state.role == "FOLLOWER" then runFollower()
                elseif state.role == "CANDIDATE" then runCandidate()
                elseif state.role == "LEADER" then runLeader()
                end
            end
        end,
        pruneLoop, 
        function()
            while true do
                local id, packet = network_utils.receive("CLUSTER", 9999)
                if packet and packet.payload and packet.nonce then
                    local plain = tacs_core.decrypt(CLUSTER_KEY, packet.nonce, packet.payload)
                    local status, msg = pcall(textutils.unserialize, plain)
                    if status and type(msg) == "table" and msg.type then
                        if msg.type == "REQUEST_VOTE" then handleRequestVote(id, msg)
                        elseif msg.type == "APPEND_ENTRIES" then handleAppendEntries(id, msg)
                        elseif msg.type == "APPEND_RESP" then handleAppendResponse(id, msg)
                        elseif msg.type == "VOTE_RESP" then
                            os.queueEvent("modem_message", "top", 0, msg, 0)
                        elseif msg.type == "CLUSTER_JOIN" then database.touchNode(id)
                        end
                    end
                end
            end
        end
    )
end

function getRole() return state.role end
function getLeader() return state.leaderID end
function isLeader() return state.role == "LEADER" end
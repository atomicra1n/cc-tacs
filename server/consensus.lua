-- TACS CONSENSUS ENGINE (RAFT PROTOCOL) v4.1 (GOSSIP FIXED)
-- Fixes "Silent Follower" pruning bugs & File Mixup

os.loadAPI("libs/tacs_core.lua")
os.loadAPI("libs/network_utils.lua")
os.loadAPI("server/database.lua")

-- === CONFIGURATION ===
local HEARTBEAT_INTERVAL = 2   
local ELECTION_TIMEOUT_MIN = 4 
local ELECTION_TIMEOUT_MAX = 7
local PRUNE_INTERVAL = 10 
local NODE_TIMEOUT = 15000 

if not os.epoch then NODE_TIMEOUT = 15 end 

local CLUSTER_KEY = database.getKey()
if not CLUSTER_KEY then error("Consensus failed: No Cluster Key loaded.") end

-- === STATE ===
local state = {
    term = 0,           
    role = "FOLLOWER",  
    votedFor = nil,     
    leaderID = nil,     
    lastHeartbeat = os.clock()
}

local function saveState()
    local f = fs.open(".raft_state", "w")
    f.write(textutils.serialize({term = state.term, votedFor = state.votedFor}))
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
end
loadState()

-- === UTILITIES ===
local function log(msg)
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

-- === SECURE COMMS ===

local function broadcastSecure(msgTable)
    local nonce = os.epoch and os.epoch("utc") or os.time()
    local payload = textutils.serialize(msgTable)
    local encrypted = tacs_core.encrypt(CLUSTER_KEY, nonce, payload)
    
    network_utils.broadcast("CLUSTER", {
        nonce = nonce,
        payload = encrypted
    })
end

local function sendSecure(targetID, msgTable)
    local nonce = os.epoch and os.epoch("utc") or os.time()
    local payload = textutils.serialize(msgTable)
    local encrypted = tacs_core.encrypt(CLUSTER_KEY, nonce, payload)
    
    network_utils.send(targetID, "CLUSTER", {
        nonce = nonce,
        payload = encrypted
    })
end

-- === DISCOVERY PROTOCOL ===
local function performDiscovery()
    local myID = os.getComputerID()
    print("Broadcasting Secure Discovery Beacon...")
    broadcastSecure({ type="CLUSTER_JOIN", id=myID })
end

-- === RPC HANDLERS ===

function handleJoin(senderID, msg)
    database.touchNode(senderID)
    log("Discovered Peer: " .. senderID)
    sendSecure(senderID, { type="CLUSTER_WELCOME", id=os.getComputerID() })
end

function handleWelcome(senderID, msg)
    database.touchNode(senderID)
end

function handleRequestVote(senderID, msg)
    database.touchNode(senderID)
    
    local grant = false
    if msg.term < state.term then
        sendSecure(senderID, { type="VOTE_RESP", term=state.term, voteGranted=false })
        return
    end

    if msg.term > state.term then
        state.term = msg.term
        state.role = "FOLLOWER"
        state.votedFor = nil
        saveState()
    end

    if (state.votedFor == nil or state.votedFor == senderID) then
        state.votedFor = senderID
        saveState()
        grant = true
        resetElectionTimer() 
        log("Voted for Node " .. senderID)
    end

    sendSecure(senderID, { type="VOTE_RESP", term=state.term, voteGranted=grant })
end

-- [UPDATED] Heartbeat Handler: GOSSIP SYNC + REPLY
function handleAppendEntries(senderID, msg)
    database.touchNode(senderID) -- Leader is alive
    
    -- GOSSIP: Update our list of peers based on what the Leader sees
    if msg.active_peers then
        for _, peerID in pairs(msg.active_peers) do
            if peerID ~= os.getComputerID() then
                database.touchNode(peerID)
            end
        end
    end
    
    if msg.term >= state.term then
        state.term = msg.term
        state.role = "FOLLOWER"
        state.leaderID = senderID
        resetElectionTimer()
        
        -- REPLY TO LEADER so he knows we are alive
        sendSecure(senderID, { type="HEARTBEAT_RESP", term=state.term, success=true })
        
    elseif msg.term < state.term then
        sendSecure(senderID, { type="HEARTBEAT_RESP", term=state.term, success=false })
    end
end

-- [NEW] Heartbeat Response Handler
function handleHeartbeatResponse(senderID, msg)
    database.touchNode(senderID)
end

-- === LOOPS ===

local function runLeader()
    log("LEADER ACTIVE (Quorum: " .. getQuorum() .. ")")
    while state.role == "LEADER" do
        
        -- GOSSIP: Collect active nodes to share with followers
        local active_list = {}
        local nodes = database.loadNodes()
        for id, _ in pairs(nodes) do table.insert(active_list, id) end
        
        broadcastSecure({
            type = "APPEND_ENTRIES",
            term = state.term,
            leaderID = os.getComputerID(),
            active_peers = active_list -- Tell followers who is alive
        })
        sleep(HEARTBEAT_INTERVAL)
    end
end

local function runCandidate()
    state.term = state.term + 1
    state.votedFor = os.getComputerID() 
    saveState()
    
    local myID = os.getComputerID()
    local votes = 1
    log("Starting Election for Term " .. state.term)

    broadcastSecure({
        type = "REQUEST_VOTE",
        term = state.term,
        candidateID = myID
    })

    local timer = os.startTimer(state.timeoutDuration)
    while state.role == "CANDIDATE" do
        local e, p1, p2, p3 = os.pullEvent()
        
        if e == "timer" and p1 == timer then
            log("Election Timed Out. Retrying...")
            return 
        end

        if e == "modem_message" then
            local msg = p3
            if type(msg) == "table" and msg.type == "VOTE_RESP" and msg.term == state.term and msg.voteGranted then
                votes = votes + 1
                local quorum, total = getQuorum()
                if votes >= quorum then
                    log("Won Election! ("..votes.."/"..total..")")
                    state.role = "LEADER"
                    return
                end
            elseif type(msg) == "table" and msg.term > state.term then
                state.term = msg.term
                state.role = "FOLLOWER"
                saveState()
                return
            end
        end
    end
end

local function runFollower()
    while state.role == "FOLLOWER" do
        if (os.clock() - state.lastHeartbeat) > state.timeoutDuration then
            log("Leader Timeout. Revolting.")
            state.role = "CANDIDATE"
        end
        sleep(0.5)
    end
end

local function pruneLoop()
    while true do
        sleep(PRUNE_INTERVAL)
        local pruned = database.pruneDeadNodes(NODE_TIMEOUT)
        if pruned > 0 then
            local q, t = getQuorum()
            log("Pruned " .. pruned .. " dead nodes. New Total: " .. t .. " (Quorum: " .. q .. ")")
        end
    end
end

-- === MAIN PROCESS ===
function start()
    performDiscovery()
    
    parallel.waitForAny(
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
                    -- Decrypt
                    local plain = tacs_core.decrypt(CLUSTER_KEY, packet.nonce, packet.payload)
                    local status, msg = pcall(textutils.unserialize, plain)
                    
                    if status and type(msg) == "table" and msg.type then
                        if msg.type == "REQUEST_VOTE" then handleRequestVote(id, msg)
                        elseif msg.type == "APPEND_ENTRIES" then handleAppendEntries(id, msg)
                        elseif msg.type == "CLUSTER_JOIN" then handleJoin(id, msg)
                        elseif msg.type == "CLUSTER_WELCOME" then handleWelcome(id, msg)
                        elseif msg.type == "HEARTBEAT_RESP" then handleHeartbeatResponse(id, msg)
                        elseif msg.type == "VOTE_RESP" then
                            os.queueEvent("modem_message", "top", 0, msg, 0) 
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

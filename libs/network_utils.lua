-- TACS NETWORK UTILITIES v1.2
-- FIXED: Modem Side Detection

PROTOCOLS = {
    CLUSTER = "TACS_CLUSTER_V1",
    PUBLIC  = "TACS_PUBLIC_V1",
    MINT    = "TACS_MINT_V1"
}

function openModem()
    -- If already open, just find which one it is to return the object (optional but good for consistency)
    for _, side in ipairs(peripheral.getNames()) do
        if rednet.isOpen(side) then
            return peripheral.wrap(side)
        end
    end

    -- If not open, search for a wireless modem
    for _, side in ipairs(peripheral.getNames()) do
        if peripheral.getType(side) == "modem" then
            local modem = peripheral.wrap(side)
            if modem.isWireless() then
                rednet.open(side)
                return modem
            end
        end
    end
    
    error("No Wireless Modem Found! Please attach one.")
end

function broadcast(protocolKey, msg)
    openModem()
    rednet.broadcast(msg, PROTOCOLS[protocolKey])
end

function send(id, protocolKey, msg)
    openModem()
    rednet.send(id, msg, PROTOCOLS[protocolKey])
end

function receive(protocolKey, timeout)
    openModem()
    local p = PROTOCOLS[protocolKey]
    local id, msg, prot = rednet.receive(p, timeout)
    if id then
        return id, msg
    end
    return nil
end

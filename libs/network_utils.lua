PROTOCOLS = {
    CLUSTER = "TACS_CLUSTER_V1",
    PUBLIC  = "TACS_PUBLIC_V1",
    MINT    = "TACS_MINT_V1"
}

function openModem()
    local modem = peripheral.find("modem")
    if not modem then
        error("No Modem Found! Please attach a Wireless Modem.")
    end
    if not rednet.isOpen(modem.name) then
        rednet.open(modem.name)
    end
    return modem
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

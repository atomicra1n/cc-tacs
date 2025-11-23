print("main of minter")

-- CLI Loop to keep the program running
while true do
    term.setTextColor(colors.yellow)
    write("Minter> ")
    term.setTextColor(colors.white)
    
    local input = read()
    
    if input == "exit" then
        print("Exiting minter...")
        break
    elseif input == "help" then
        print("Available commands:")
        print(" mint <user> - Create a new card")
        print(" help        - Show this menu")
    elseif input ~= "" then
        print("I do not know the command: " .. input)
    end
end

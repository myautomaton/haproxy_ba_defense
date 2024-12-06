-- Function to check the status of a backend server
local function check_backend_status(txn)
    -- Define the backend and server name
    local backend_name = "backend2"   -- Replace with your backend name
    local server_name = "backend2"       -- Replace with your server name

    -- Fetch the status of the backend server
    local server_status = core.backends[backend_name].servers[server_name].status

    txn:log(core.info, "status: " .. server_status)
    -- Check the status and respond accordingly
    if server_status == "UP" then
        -- If server is UP, continue as normal
        txn.http:res_set_status(200)
        txn.http:res_set_body("Server is UP and running.")
        txn:done()
    elseif server_status == "DOWN" then
        -- If server is DOWN, return a custom error message
        txn.http:res_set_status(503)
        txn.http:res_set_body("Server is DOWN. Please try again later.")
        txn:done()
    else
        -- Handle other states (e.g., MAINT, NOLB, DRAIN, etc.)
        txn.http:res_set_status(503)
        txn.http:res_set_body("Server is in an unknown state: " .. server_status)
        txn:done()
    end
end

-- Register the Lua action to run with HTTP requests
core.register_action("check_backend_status", { "http-req" }, check_backend_status)
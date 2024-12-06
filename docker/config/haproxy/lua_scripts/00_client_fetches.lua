-- Function to execute an external script
-- local function execute_external_script()
--     -- Define the command to run
--     local command = "/path/to/external_script.sh"
--     -- Execute the command and capture the result
--     local result = os.execute("/tmp/test.sh")
--     -- Optionally log the result or send a response
--     if result == 0 then
--         core.Info("External script executed successfully.")
--     else
--         core.Alert("Failed to execute external script.")
--     end
-- end


-- local function client_config(txn)
--     local base = txn.sf:base()
--     local host, port, rest = string.match(base, '([^:]+):([^/]+)/?(.+)]?')
--     -- txn.Info(txn, 'Port: ' .. host)
--     -- txn.set_var(txn, 'from_host', host)
--     local from_svc = "asd"
--     txn.set_var(txn, 'from_svc', from_svc)
--     txn.Info(txn, 'From: ' .. from_svc)
--     return from_svc
-- end
-- core.register_fetches("client_config", client_config)

-- core.register_fetches("hello", function(txn)
--     return false
-- end)

-- local function my_lua_service(applet)
--     -- Log a message
--     -- local from_svc = lua.get_var(lua, 'lua.hello')
--     -- txn.Info(txn, string.format("Request from %s took ", hello))

--     local response = "Hello World Lua!"
--     -- Set HTTP response headers and body
--     applet:set_status(200)
--     applet:add_header("content-length", string.len(response))
--     applet:add_header("content-type", "text/plain")
--     applet:start_response()
--     applet:send(response)

-- end
-- core.register_service("my_lua_service", "http", my_lua_service)

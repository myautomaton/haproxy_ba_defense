local function default_service(applet)
    -- Log a message
    -- local from_svc = lua.get_var(lua, 'lua.hello')
    -- txn.Info(txn, string.format("Request from %s took ", hello))

    local response = "Default Backend!"
    -- Set HTTP response headers and body
    applet:set_status(200)
    applet:add_header("content-length", string.len(response))
    applet:add_header("content-type", "text/plain")
    applet:start_response()
    applet:send(response)

end
core.register_service("default_service", "http", default_service)

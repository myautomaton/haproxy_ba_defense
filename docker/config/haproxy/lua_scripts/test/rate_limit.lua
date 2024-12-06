local rate_limits = {}

core.register_action("rate_limit", { "http-req" }, function(txn)
    local client_ip = txn.f:src()
    local current_time = core.now()

    if not rate_limits[client_ip] then
        rate_limits[client_ip] = { last_time = current_time, count = 1 }
    else
        local last_time = rate_limits[client_ip].last_time
        if current_time - last_time > 60 then  -- reset every 60 seconds
            rate_limits[client_ip].last_time = current_time
            rate_limits[client_ip].count = 1
        else
            rate_limits[client_ip].count = rate_limits[client_ip].count + 1
        end
    end

    if rate_limits[client_ip].count > 100 then  -- limit to 100 requests per minute
        txn:set_var("txn.blocked", true)
        txn.http:res_add_header("X-RateLimit-Blocked", "true")
        txn:send_error(429, "Rate limit exceeded")
    end
end)

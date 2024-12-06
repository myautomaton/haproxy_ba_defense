-- Function to detect if the request comes from known bots based on the User-Agent header
local function detect_bots(txn)
    local user_agent = txn.f:req_hdr("user-agent")  -- Retrieve the User-Agent header from the request

    -- Check if User-Agent is present
    if user_agent then
        -- Check against a list of known bots
        if user_agent:find("Googlebot") or 
           user_agent:find("Bingbot") or 
           user_agent:find("Slurp") or 
           user_agent:find("DuckDuckBot") or 
           user_agent:find("Baiduspider") or 
           user_agent:find("YandexBot") or 
           user_agent:find("Sogou") or 
           user_agent:find("Exabot") or 
           user_agent:find("facebot") or 
           user_agent:find("ia_archiver") then
           return true  -- Return true if a known bot is detected
        end
    end
    return false  -- Return false if no bot is detected
end
core.register_fetches("detect_bots", detect_bots)  -- Register the detect_bots function with HAProxy

-- Function to block requests from detected bots by sending a 403 Forbidden response
local function bot_block(applet)
    local response = "Error: Access Denied. No bots allowed."  -- Define the response message
    applet:set_status(403)                                   -- Set the HTTP status to 403 Forbidden
    applet:add_header("content-length", string.len(response)) -- Set the Content-Length header
    applet:add_header("content-type", "text/plain")          -- Set the Content-Type header to plain text
    applet:start_response()                                   -- Start the HTTP response
    applet:send(response)                                     -- Send the response message
end
core.register_service("bot_block", "http", bot_block)     -- Register the bot_block function with HAProxy

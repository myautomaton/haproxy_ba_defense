-- Function to check the type of browser used in the request
local function check_browser(txn)
    local user_agent = txn.f:req_hdr("user-agent")  -- Retrieve the "User-Agent" header from the request

    -- Verify that a User-Agent header exists
    if user_agent then
        -- Check for specific browser types in the User-Agent header string
        if user_agent:find("Chrome") then         -- Check if the browser is Chrome
            return false                          -- Return false to indicate no action is needed
        elseif user_agent:find("Firefox") then    -- Check if the browser is Firefox
            return false                          -- Return false for Firefox as well
        elseif user_agent:find("Safari") and not user_agent:find("Chrome") then  -- Check if Safari (but not Chrome)
            return false                          -- Return false if it is Safari
        elseif user_agent:find("MSIE") or user_agent:find("Trident") then  -- Check for Internet Explorer
            return true                           -- Return true for Internet Explorer
        else
            return true                           -- Return true for any other unlisted browsers
        end
    else
        return true                               -- Return true if no User-Agent is found
    end
end

-- Register the check_browser function as a fetch method in HAProxy
core.register_fetches("check_browser", check_browser)


-- Function to send a custom response for unsupported browsers
local function download_browser(applet)
    local response = "Download proper browser!\n\n"  -- Response message indicating unsupported browser
    applet:set_status(301)                           -- Set HTTP response status to 301 (Moved Permanently)
    applet:add_header("content-length", string.len(response))  -- Set content-length header
    applet:add_header("content-type", "text/plain")  -- Set content-type header to plain text
    applet:start_response()                          -- Start sending the response
    applet:send(response)                            -- Send the response body
end

-- Register download_browser as a custom service for HAProxy to call if unsupported browser detected
core.register_service("download_browser", "http", download_browser)
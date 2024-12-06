-- Table of patterns representing paths that should be restricted or indicate potential exploits
local path_patterns = {
    "wp%-admin",    -- WordPress admin path, % escape is used to handle Lua pattern matching for "-"
    "my%-admin"     -- Custom admin path, with similar escape for "-"
}

-- Function to check if a given path matches any restricted patterns
local function is_path_exploit(input)
    for _, pattern in ipairs(path_patterns) do       -- Loop through each path pattern
        if input:lower():find(pattern) then          -- Convert input to lowercase and search for pattern
            return true                              -- Return true if a match is found
        end
    end
    return false                                     -- Return false if no pattern matches
end

-- Function to log abuse attempts to a file, storing details such as IP, path, body, and headers
function logAbuse(ip, path, body, headers)
    -- Construct a unique filename using the IP and timestamp
    local fileName = string.format(
        "%s.%s.yaml",
        ip,
        os.time(os.date("!*t"))
    )

    -- Attempt to open the file in write mode and handle errors
    local file, err = io.open("/etc/haproxy/abuse/"..fileName, "w+")
    if not file then
        core.Alert("Error opening file: " .. tostring(err)) -- Log alert if the file cannot be opened
        return
    end

    -- Log the detection of an admin path access attempt
    core.log(core.info, string.format("Admin path access from %s ", ip))

    -- Create a structured log entry for the abuse attempt
    local log_entry = string.format(
        "abuser:\n  date: \"%s\"\n  ip: \"%s\"\n  abuse: \"%s\"\n  path: \"%s\"\n  body: \"%s\"\n  headers: %s\n", 
        os.date("%Y-%m-%d %H:%M:%S"),  -- Log current date and time
        ip,
        "admin-path",                  -- Mark abuse type as admin path access attempt
        path,
        body,
        headers
    )    

    file:write(log_entry)  -- Write the log entry to the file
    file:close()            -- Close the file after writing
end

-- Function to combine all request headers into a single formatted string
function squashHeaders(txn)
    local squash = "\n"
    -- Loop through each header name
    for headerName in string.gmatch(txn.f:req_hdr_names(","), '([^,]+)') do
        squash = string.format(
            "%s  - %s: \"%s\"\n",
            squash,
            headerName,
            txn.f:req_hdr(headerName)
        )
    end
    return squash  -- Return the formatted string of headers
end

-- Function to detect attempts to access restricted admin paths
local function detect_admin_path(txn)
    local request_uri = txn.sf:path()          -- Retrieve the request URI path
    local headers = txn.f:req_hdr_names(",")   -- Get names of all HTTP headers
    local body = txn.f:req_body()              -- Get the request body

    -- Get source IP, preferring "x-forwarded-for" header if present
    local x_forwarded_for = txn.f:req_hdr("x-forwarded-for")
    local src_ip = x_forwarded_for or tostring(txn.f:src())

    -- Check if the request URI matches any restricted admin path patterns
    if request_uri and is_path_exploit(request_uri) then
        logAbuse(src_ip, request_uri, body, squashHeaders(txn)) -- Log the attempt if detected
        return true                                      -- Return true to indicate detection
    end

    return false                                         -- Return false if no restricted paths are detected
end
core.register_fetches("detect_admin_path", detect_admin_path)  -- Register detect_admin_path function as a fetch in HAProxy

-- Function to block requests accessing restricted admin paths, returning a 403 Forbidden response
local function admin_path_block(applet)
    local response = "Error: Access Denied. Admin path not allowed\n." -- Define response for blocked admin path
    applet:set_status(403)                                -- Set HTTP response status to 403 (Forbidden)
    applet:add_header("content-length", string.len(response)) -- Set content length header
    applet:add_header("content-type", "text/plain")       -- Set content type to plain text
    applet:start_response()                               -- Start sending the response
    applet:send(response)                                 -- Send the response message
end
core.register_service("admin_path_block", "http", admin_path_block) -- Register admin_path_block as a service in HAProxy

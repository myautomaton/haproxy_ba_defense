-- Set the maximum cookie size in bytes
local MAX_COOKIE_SIZE = 4096

-- Function to log abuse incidents when SQL injection is detected
function logAbuse(ip, path, body, headers)
    -- Generate a unique filename using the IP address and the current timestamp
    local fileName = string.format(
        "%s.%s.yaml",
        ip,
        os.time(os.date("!*t"))
    )

    -- Attempt to open the file for writing; if unsuccessful, log an alert
    local file, err = io.open("/etc/haproxy/abuse/"..fileName, "w+")
    if not file then
        core.Alert("Error opening file: " .. tostring(err)) -- Log error if file can't be opened
        return
    end

    -- Log abuse alert with IP address to HAProxy logs
    core.log(core.info, string.format("Cookie size exceeds maximum limit of %s bytes from %s ", MAX_COOKIE_SIZE, src_ip))

    -- Format the abuse log entry with relevant details in YAML format
    local log_entry = string.format(
        "abuser:\n  date: \"%s\"\n  ip: \"%s\"\n  abuse: \"%s\"\n  path: \"%s\"\n  body: \"%s\"\n  headers: %s\n", 
        os.date("%Y-%m-%d %H:%M:%S"), 
        ip,
        "coockie-size", 
        path,
        body,
        headers
    )    

    -- Write the formatted log entry to the file and close it
    file:write(log_entry)
    file:close()
end

-- Function to format and collect HTTP headers into a structured YAML list
function squashHeaders(txn)
    local squash = "\n"
    -- Iterate through each header name and append it with its value to the list
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

-- Function to validate the size of the "Cookie" header in an HTTP request
local function validate_cookie_size(txn)
    local path = txn.sf:query()               -- Get the URL query string
    local headers = txn.f:req_hdr_names(",")  -- Retrieve all HTTP header names
    local body = txn.f:req_body()             -- Get the HTTP request body

    -- Retrieve the client IP address, prioritizing the "X-Forwarded-For" header if present
    local x_forwarded_for = txn.f:req_hdr("x-forwarded-for")
    local src_ip = x_forwarded_for or tostring(txn.f:src())  -- Use "X-Forwarded-For" IP or fallback to direct IP

    -- Retrieve the "Cookie" header from the HTTP request
    local cookie_header = txn.f:req_hdr("Cookie") 

    -- Check if the "Cookie" header exists
    if cookie_header then
        local cookie_size = #cookie_header    -- Calculate the length of the cookie header in bytes

        -- Check if the cookie size exceeds a predefined maximum limit
        if cookie_size > MAX_COOKIE_SIZE then
            logAbuse(src_ip, path, body, squashHeaders(txn))  -- Log the abuse if the cookie is too large
            return true                                     -- Return true to indicate the oversized cookie
        end
    end
    return false                                            -- Return false if no issues with cookie size
end

-- Register the validate_cookie_size function as a fetch method in HAProxy
core.register_fetches("validate_cookie_size", validate_cookie_size)


-- Function to block requests with oversized cookies by sending an error response
local function coockie_block(applet)
    local response = "Bad Request. Cookie too large!"       -- Define error message for large cookies
    applet:set_status(400)                                  -- Set HTTP response status to 400 (Bad Request)
    applet:add_header("content-length", string.len(response))  -- Add "Content-Length" header to specify response size
    applet:add_header("content-type", "text/plain")         -- Set content type to plain text
    applet:start_response()                                 -- Initiate response
    applet:send(response)                                   -- Send response body with the error message
end

-- Register coockie_block as a custom service in HAProxy to respond when a large cookie is detected
core.register_service("coockie_block", "http", coockie_block)
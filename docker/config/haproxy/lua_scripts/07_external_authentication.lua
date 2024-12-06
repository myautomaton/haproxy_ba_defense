-- Function to authenticate a given username by checking against a list of allowed names
local function authenticate(username)
    names = {                    -- Define a list of valid usernames
        'John', 
        'Joe', 
        'Steve'
    }
    -- Loop through each name in the list
    for i, v in ipairs(names) do
        if v == username then    -- Check if the username matches any name in the list
            return true          -- Return true if the username is valid
        end
    end
    return false                 -- Return false if no match is found
end

-- Main function to intercept HTTP requests and perform authentication
local function user_authenticated(txn)
    local path = txn.sf:path()
    local headers = txn.f:req_hdr_names(",")  -- Get the names of all HTTP headers
    local body = txn.f:req_body()             -- Get the request body

    -- Retrieve the client IP address; prioritize "X-Forwarded-For" header if present
    local x_forwarded_for = txn.f:req_hdr("x-forwarded-for")
    local src_ip = x_forwarded_for or tostring(txn.f:src())

    -- Initialize an empty table to store segments of the path
    local returnTable = {}

    -- Split the path by each '/' and store segments in returnTable
    for k, v in string.gmatch(path, "([^/]+)") do
        returnTable[#returnTable + 1] = k  -- Add each path segment to the table
    end
    
    -- Log the second segment of the path to HAProxy logs, which represents the username
    core.Info("Requested path: " .. returnTable[2])
    
    -- Perform authentication by checking if the second segment of the path is a valid username
    return authenticate(returnTable[2])
end

core.register_fetches("user_authenticated", user_authenticated)

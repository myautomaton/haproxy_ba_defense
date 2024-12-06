-- Configuration for the circuit breaker
local failure_threshold = 5         -- Number of failures before tripping the circuit
local recovery_time = 30            -- Time in seconds to wait before retrying a tripped backend

-- Table to store the failure count and the trip time for each backend
local backends = {}

-- Function to increment failure count and trip the circuit if necessary
local function handle_backend_failure(backend_name)
    local backend = backends[backend_name]
    if not backend then
        backend = { failures = 0, tripped_at = nil }
        backends[backend_name] = backend
    end

    backend.failures = backend.failures + 1

    if backend.failures >= failure_threshold then
        backend.tripped_at = os.time()
        core.Info(string.format("Circuit breaker tripped for backend '%s' at %s", backend_name, os.date()))
    end
end

-- Function to reset the circuit breaker after successful response
local function reset_backend_failure(backend_name)
    local backend = backends[backend_name]
    if backend then
        backend.failures = 0
        backend.tripped_at = nil
    end
end

-- Function to check if a backend is tripped (circuit open)
local function is_backend_tripped(backend_name)
    local backend = backends[backend_name]
    if backend and backend.tripped_at then
        -- Check if recovery time has passed
        if os.time() - backend.tripped_at >= recovery_time then
            core.Info(string.format("Circuit breaker reset for backend '%s' at %s", backend_name, os.date()))
            reset_backend_failure(backend_name)
            return false
        else
            return true
        end
    end
    return false
end

-- Function to check backend status and potentially block traffic
local function circuit_breaker_check(txn)
    local backend_name = txn.sc:backend_name()

    -- Check if the backend circuit is open (tripped)
    if is_backend_tripped(backend_name) then
        txn.http:res_set_status(503)
        txn.http:res_set_body("Service Unavailable: Backend circuit is open (tripped).")
        txn:done()
        return
    end
end

-- Function to monitor the backend responses for failures or success
local function monitor_backend_response(txn)
    local backend_name = txn.sc:backend_name()
    local response_status = txn.http:res_get_status()

    if response_status >= 500 then
        handle_backend_failure(backend_name)
    else
        reset_backend_failure(backend_name)
    end
end

-- Register the Lua functions
core.register_action("circuit_breaker_check", { "http-req" }, circuit_breaker_check)
core.register_action("monitor_backend_response", { "http-res" }, monitor_backend_response)

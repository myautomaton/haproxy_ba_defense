core.register_action("custom_logging", { "http-req" }, function(txn)
    local start_time = core.now()
    txn:set_var("txn.start_time", start_time)
end)

core.register_action("log_response_time", { "http-res" }, function(txn)

    core.log(core.info, string.format("Test log format"))
end)

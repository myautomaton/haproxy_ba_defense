core.register_fetches("greater_than", function(txn, var1, var2)
    local number1 = tonumber(txn:get_var(var1))
    local number2 = tonumber(txn:get_var(var2))
    if number1 > number2 then return true
    else return false end
end)
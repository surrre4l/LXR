
-- LXR Encoder created by surrre4L
-- LXR-Crypt 2.0 | LXR-VM Core
-- Hybrid register + operand-stack VM

local VM = {}

VM.VERSION = "2.0"

local MAX_INSTRUCTIONS = 1000
local MAX_STEPS = 5000
local MAX_STACK = 256
local MAX_REGISTERS = 64

local OPS = {
    PUSH = true, POP = true,
    LOAD = true, STORE = true,
    ADD = true, SUB = true,
    MUL = true, DIV = true,
    EQ = true, LT = true,
    JUMP = true, JUMP_IF = true,
    RETURN = true, HALT = true,
}

local function integer(n, min, max)
    return type(n) == "number"
        and n == n
        and n % 1 == 0
        and n >= min
        and n <= max
end

local function constant(v)
    if type(v) == "number" then
        return v == v
            and v ~= math.huge
            and v ~= -math.huge
    end

    return type(v) == "string"
        or type(v) == "boolean"
end

function VM.Validate(program)
    if type(program) ~= "table" then
        return false, "Program must be a table"
    end

    local n = #program

    if n < 1 or n > MAX_INSTRUCTIONS then
        return false, "Invalid instruction count"
    end

    for key in pairs(program) do
        if not integer(key, 1, n) then
            return false, "Invalid program structure"
        end
    end

    for pc = 1, n do
        local ins = program[pc]

        if type(ins) ~= "table"
            or type(ins.op) ~= "string"
            or not OPS[ins.op] then
            return false, "Invalid opcode at " .. pc
        end

        local op = ins.op

        if op == "PUSH" and not constant(ins.value) then
            return false, "Invalid constant at " .. pc
        end

        if (op == "LOAD" or op == "STORE")
            and not integer(ins.register, 1, MAX_REGISTERS) then
            return false, "Invalid register at " .. pc
        end

        if (op == "JUMP" or op == "JUMP_IF")
            and not integer(ins.target, 1, n) then
            return false, "Invalid jump at " .. pc
        end
    end

    return true
end

function VM.Run(program)
    local valid, reason = VM.Validate(program)

    if not valid then
        return {Success = false, Error = reason}
    end

    local stack, registers = {}, {}
    local pc, steps = 1, 0
    local n = #program

    local function push(value)
        if #stack >= MAX_STACK then
            return false
        end
        stack[#stack + 1] = value
        return true
    end

    local function pop()
        if #stack == 0 then
            return nil, false
        end
        return table.remove(stack), true
    end

    local function result(value)
        return {
            Success = true,
            Value = value,
            Steps = steps,
            Version = VM.VERSION,
        }
    end

    while pc <= n do
        steps += 1

        if steps > MAX_STEPS then
            return {Success = false, Error = "Step limit exceeded"}
        end

        local ins = program[pc]
        local op = ins.op

        if op == "PUSH" then
            if not push(ins.value) then
                return {Success = false, Error = "Stack limit exceeded"}
            end

        elseif op == "POP" then
            local _, found = pop()
            if not found then
                return {Success = false, Error = "Stack underflow"}
            end

        elseif op == "LOAD" then
            local value = registers[ins.register]
            if value == nil then
                return {Success = false, Error = "Empty register"}
            end
            if not push(value) then
                return {Success = false, Error = "Stack limit exceeded"}
            end

        elseif op == "STORE" then
            local value, found = pop()
            if not found then
                return {Success = false, Error = "Stack underflow"}
            end
            registers[ins.register] = value

        elseif op == "ADD" or op == "SUB"
            or op == "MUL" or op == "DIV"
            or op == "EQ" or op == "LT" then

            if #stack < 2 then
                return {Success = false, Error = "Stack underflow"}
            end

            local b = stack[#stack]
            local a = stack[#stack - 1]
            local value

            if op == "EQ" then
                value = a == b
            elseif op == "LT" then
                if type(a) ~= "number" or type(b) ~= "number" then
                    return {Success = false, Error = "LT requires numbers"}
                end
                value = a < b
            else
                if type(a) ~= "number" or type(b) ~= "number" then
                    return {Success = false, Error = "Arithmetic requires numbers"}
                end

                if op == "ADD" then value = a + b
                elseif op == "SUB" then value = a - b
                elseif op == "MUL" then value = a * b
                elseif b == 0 then
                    return {Success = false, Error = "Division by zero"}
                else value = a / b end

                if value ~= value or value == math.huge
                    or value == -math.huge then
                    return {Success = false, Error = "Invalid numeric result"}
                end
            end

            stack[#stack] = nil
            stack[#stack] = nil

            if not push(value) then
                return {Success = false, Error = "Stack limit exceeded"}
            end

        elseif op == "JUMP" then
            pc = ins.target
            continue

        elseif op == "JUMP_IF" then
            local condition, found = pop()
            if not found or type(condition) ~= "boolean" then
                return {Success = false, Error = "JUMP_IF requires a boolean"}
            end
            if condition then
                pc = ins.target
                continue
            end

        elseif op == "RETURN" then
            return result(stack[#stack])

        elseif op == "HALT" then
            return result(stack[#stack])
        end

        pc += 1
    end

    return result(stack[#stack])
end

return VM

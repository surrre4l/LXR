
-- LXR Encoder created by surrre4L
-- LXR-Crypt 2.0 | LXR-VM Test Program

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local VM = require(ReplicatedStorage:WaitForChild("LXRVM"))

local program = {
    {op = "PUSH", value = 12},
    {op = "STORE", register = 1},

    {op = "PUSH", value = 8},
    {op = "LOAD", register = 1},
    {op = "ADD"},

    {op = "HALT"},
}

local result = VM.Run(program)

if result.Success then
    print("LXR-VM:", VM.VERSION)
    print("Execution successful!")
    print("Result:", result.Value)
    print("Steps:", result.Steps)
else
    warn("LXR-VM failed:", result.Error)
end

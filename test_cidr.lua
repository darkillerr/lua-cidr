local cidr = require "cidr"

local tbl = {
	["::1"] = "::1",
	["0.0.0.1"] = "::1",
	["0:0::1"] = "::1",
	["fe90::f8a6:3eff:fa10:a0b3"] = "fe90:0:0:0:f8a6:3eff:fa10:a0b3",
	["127.0.0.1"] = "127.0.0.1",
	["fe90::f8a6:3eff:fa10:a0b3/80"] = "fe90::f8a6:3eab:fa1e:b2",
	["::ffff:0/96"] = "::ffff:10.144.52.38",
	-- add more below
}

for k, v in pairs(tbl) do
	local retval = cidr.cidr_match(k, v)
	if retval == -1 then
		print(string.format("match %s & %s error", k, v))
	elseif retval == 0 then
		print(string.format("match %s & %s failed", k, v))
	elseif retval == 1 then
		print(string.format("match %s & %s success", k, v))
	end
end

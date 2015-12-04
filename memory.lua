local ffi = require("ffi")

local export = {}

ffi.cdef [[
typedef union value_t {
	int8_t int8_value;
	int16_t int16_value;
	int32_t int32_value;
	int64_t int64_value;  
	float float32_value;
	double float64_value;
	uint8_t bytes[8];
};
]]

local function getTypeMaxMin(type)
	local width = 8
	if type == "int16_t" then width = 16 end	
	if type == "int32_t" then width = 32 end
	if type == "int64_t" then width = 64 end	
	local result = math.pow(2, width-1)
	return result-1, -result
end

-- Cache.  Reduces time of calling, thus improve performance when region is large.
local int8_max, int8_min = getTypeMaxMin("int8_t")
local int16_max, int16_min = getTypeMaxMin("int16_t")
local int32_max, int32_min = getTypeMaxMin("int32_t")
local int64_max, int64_min = getTypeMaxMin("int64_t")

------------------------------------------------------------------------------
function assertProcessExists(pid)
	local procFile = io.open("/proc/" .. pid .. "/maps", "r")
	if procFile == nil then
		error("'pid' is not correct, process does not exists")	-- the process should be dead
	end
	io.close(procFile)
end
------------------------------------------------------------------------------
local function filterRegions(line, regionName)
	local startAddr, endAddr, permission, offset, dev1, dev2, length, _, from = string.match(line, "(%x+)-(%x+) (.+) (%x+) (%x+):(%x+) (%d+) (%s*) (.*)")
	if startAddr == nil then -- if the "from" field is nil, all variables will be nil.  Filter again.
		startAddr, endAddr, permission, offset, dev1, dev2, length, from = string.match(line, "(%x+)-(%x+) (.+) (%x+) (%x+):(%x+) (%d+) (%s*)")
	end
	if permission ~= "rw-p" then return nil end
	if from ~= regionName then return nil end
	return startAddr, endAddr
end

local function readMaps(pid, regionName)
	local mapsFile = io.open("/proc/" .. pid .. "/maps", "r")
	if mapsFile == nil then
		error("nil mapsFile with pid: " .. pid)
	end

	local region = {}
	for line in mapsFile:lines() do
		local startAddr, endAddr = filterRegions(line, regionName)
		if startAddr ~= nil and endAddr ~= nil then
			region[#region+1] = {}
			region[#region][0] = tonumber(startAddr,16)
			region[#region][1] = tonumber(endAddr,16)
		end
	end
	mapsFile:close()
	return region
end
------------------------------------------------------------------------------
local function search(pid, value, regionName)
	assertProcessExists(pid) -- Checks if process exists
	local regions = readMaps(pid, regionName) -- Read the valid maps regions

	local memFile = io.open("/proc/" .. pid .. "/mem", "r")
	if memFile == nil then
		error("nil memFile with pid: " .. pid)
	end

	if value == math.floor(value) then -- int value
		local paramValue = ffi.new("union value_t", { int64_value = value })
		local paramValueFirstByte = paramValue.bytes[0]	-- MUST cache!!!
		local scannedValue = ffi.new("union value_t", {})

		for mapsIndex=1,#regions do
			local startAddr = regions[mapsIndex][0]
			local endAddr = regions[mapsIndex][1]
			local length = endAddr-startAddr
			memFile:seek("set", startAddr)
			local data = memFile:read(length)
			if data ~= nil then
				for offset=1,length,4 do
					if paramValueFirstByte == data:byte(offset) then
						scannedValue.bytes = data:sub(offset, offset+ffi.sizeof("int64_t"))
						if not (value < int8_min or value > int8_max) then
							if value == scannedValue.int8_value then
								print("found at " .. string.format("%x", startAddr+offset-1) .. " type: int8")
							end
						end
						if not (value < int16_min or value > int16_max) then
							if value == scannedValue.int16_value then
								print("found at " .. string.format("%x", startAddr+offset-1) .. " type: int16")
							end
						end
						if not (value < int32_min or value > int32_max) then
							if value == scannedValue.int32_value then
								print("found at " .. string.format("%x", startAddr+offset-1) .. " type: int32")
							end
						end
						if not (value < int64_min or value > int64_max) then
							if value == scannedValue.int64_value then
								print("found at " .. string.format("%x", startAddr+offset-1) .. " type: int64")
							end
						end
					end
				end
			end
		end
	else -- float value
		local paramFloat32Value = ffi.new("union value_t", { float32_value = value })
		local paramFloat64Value = ffi.new("union value_t", { float64_value = value })
		local paramFloat32ValueFirstByte = paramFloat32Value.bytes[0]		-- MUST cache!!!
		local paramFloat32ValueAccurate = paramFloat32Value.float32_value	-- MUST cache!!!
		local paramFloat64ValueFirstByte = paramFloat64Value.bytes[0]		-- MUST cache!!!
		local scannedValue = ffi.new("union value_t", {})

		for mapsIndex=1,#regions do
			local startAddr = regions[mapsIndex][0]
			local endAddr = regions[mapsIndex][1]
			local length = endAddr-startAddr
			memFile:seek("set", startAddr)
			local data = memFile:read(length)
			if data ~= nil then
				for offset=1,length,ffi.sizeof("float") do
					local byte = data:byte(offset)
					if byte == paramFloat32ValueFirstByte then
						scannedValue.bytes = data:sub(offset, offset+ffi.sizeof("float"))
						if paramFloat32ValueAccurate == scannedValue.float32_value then
							print("found at " .. string.format("%x", startAddr+offset-1) .. " type: float32")
						end
					end
					if byte == paramFloat64ValueFirstByte then
						scannedValue.bytes = data:sub(offset, offset+ffi.sizeof("double"))
						if value == scannedValue.float64_value then
							print("found at " .. string.format("%x", startAddr+offset-1) .. " type: float64")
						end
					end
				end
			end
		end
	end
	
	memFile:close()
	return regions
end

function export.search(pid, value, regionName)
  search(pid, value, regionName)
end

return export

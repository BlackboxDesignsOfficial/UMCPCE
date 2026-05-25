-- ============================================================================
-- CHEATENGINE MCP BRIDGE v11.4 - FORTIFIED EDITION
-- ============================================================================
-- Combines timer-based pipe communication (v10) with complete command set (v8)
-- This is the PRODUCTION version with all tools for AI-powered reverse engineering
-- v11.4.0: Added robust cleanup on start/stop to prevent zombie breakpoints/watches
--          Ensures clean state on script reload even if resources are active
-- v11.3.1: Universal 32/64-bit handling, improved breakpoint capture, robust analysis
--          Fixed analyze_function, readPointer for pointer chains
-- ============================================================================

local PIPE_NAME = "CE_MCP_Bridge_v99"
local VERSION = "11.8.0"

-- Global State
local serverState = {
    running = false,
    timer = nil,
    pipe = nil,
    connected = false,
    scan_memscan = nil,
    scan_foundlist = nil,
    breakpoints = {},
    breakpoint_hits = {},
    hw_bp_slots = {},      -- Hardware breakpoint slots (max 4)
    active_watches = {},   -- DBVM watch IDs for hypervisor-level tracing

    -- Emulator guest-address translation (multi-region, v11.6+).
    -- guestRegions is an array of { guestStart, guestEnd, hostBase, kind }, all
    -- numeric. Each maps a contiguous guest VA range to a host VA range. Empty
    -- table = no translation (pass-through). Multi-region is required for
    -- consoles like the Wii (MEM1 at 0x80000000 + MEM2 at 0x90000000) and any
    -- emulator with split RAM. Backward compat: cmd_set_guest_base still accepts
    -- the single range_start/range_end shape and just installs one region.
    guestRegions = {},
    guestKind = nil        -- last-set kind for informational reporting only
}

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

local function toHex(num)
    if not num then return "nil" end
    -- Handle both 32-bit and 64-bit addresses correctly
    -- Lua numbers are doubles, so we need to handle large integers carefully
    if num < 0 then
        -- Handle negative numbers (signed interpretation)
        return string.format("-0x%X", -num)
    elseif num > 0xFFFFFFFF then
        -- 64-bit address: use proper formatting
        local high = math.floor(num / 0x100000000)
        local low = num % 0x100000000
        return string.format("0x%X%08X", high, low)
    else
        -- 32-bit address
        return string.format("0x%08X", num)
    end
end

-- ============================================================================
-- ADDRESS RESOLUTION (with optional guest->host translation for emulators)
-- ============================================================================

-- Numeric coercion helper. Accepts numbers, hex strings ("0x...", with or
-- without prefix when unambiguous), and decimal strings. Returns nil on
-- failure. Used to defend against any code path where a JSON param leaks
-- through as a string (which is what caused the v11.5 "compare string with
-- number" error inside translateGuest when range_start was supplied as a hex
-- string to set_guest_base and never coerced).
local function _num(v)
    if v == nil then return nil end
    local t = type(v)
    if t == "number" then return v end
    if t == "string" then
        local hex = v:match("^0[xX]([0-9A-Fa-f]+)$")
        if hex then return tonumber(hex, 16) end
        local n = tonumber(v)
        if n then return n end
        -- Last resort: bare hex without 0x but with a-f letters present
        if v:match("[A-Fa-f]") and v:match("^[0-9A-Fa-f]+$") then
            return tonumber(v, 16)
        end
        return nil
    end
    return nil
end

-- Translate a guest address to host. Walks every configured guest region.
-- If addr falls inside any region, returns the corresponding host address.
-- Otherwise pass-through. ALWAYS coerces to number first so a stray string
-- can never reach a comparison operator.
local function translateGuest(addr)
    addr = _num(addr)
    if addr == nil then return nil end
    local regions = serverState.guestRegions
    if not regions or #regions == 0 then return addr end
    for _, r in ipairs(regions) do
        local gs, ge, hb = r.guestStart, r.guestEnd, r.hostBase
        if type(gs) == "number" and type(ge) == "number" and type(hb) == "number"
           and addr >= gs and addr < ge then
            return hb + (addr - gs)
        end
    end
    return addr
end

-- Reverse translate: given a host address, return the corresponding guest
-- address if it falls within any configured region. Otherwise nil.
local function translateHost(addr)
    addr = _num(addr)
    if addr == nil then return nil end
    local regions = serverState.guestRegions
    if not regions or #regions == 0 then return nil end
    for _, r in ipairs(regions) do
        local gs, ge, hb = r.guestStart, r.guestEnd, r.hostBase
        if type(gs) == "number" and type(ge) == "number" and type(hb) == "number" then
            local size = ge - gs
            if addr >= hb and addr < hb + size then
                return gs + (addr - hb)
            end
        end
    end
    return nil
end

-- The single resolution helper used by every command that takes an address.
-- Accepts string ("0x...", "module.dll+0x100", "0x80001234") or number.
-- Returns numeric host address or nil. Hex strings, decimal strings, and
-- numeric inputs are all normalized via _num before any comparison.
local function resolveAddr(addr)
    if addr == nil then return nil end
    if type(addr) == "string" then
        -- Allow direct hex/decimal parsing for guest-range strings too
        -- (CE's getAddressSafe may fail or misinterpret 0x80000000 if no
        -- module is at that base).
        local n = _num(addr)
        if n then return translateGuest(n) end
        -- Symbol expression like "module.dll+0x100"
        local sym = getAddressSafe(addr)
        if not sym then return nil end
        return translateGuest(sym)
    end
    if type(addr) == "number" then
        return translateGuest(addr)
    end
    return nil
end

local function log(msg)
    print("[MCP v" .. VERSION .. "] " .. msg)
end

-- Universal 32/64-bit architecture helper
-- Returns pointer size, whether target is 64-bit, and current stack/instruction pointers
local function getArchInfo()
    local is64 = targetIs64Bit()
    local ptrSize = is64 and 8 or 4
    local stackPtr = is64 and (RSP or ESP) or ESP
    local instPtr = is64 and (RIP or EIP) or EIP
    return {
        is64bit = is64,
        ptrSize = ptrSize,
        stackPtr = stackPtr,
        instPtr = instPtr
    }
end

-- Universal register capture - works for both 32-bit and 64-bit targets
local function captureRegisters()
    local is64 = targetIs64Bit()
    if is64 then
        return {
            RAX = RAX and toHex(RAX) or nil,
            RBX = RBX and toHex(RBX) or nil,
            RCX = RCX and toHex(RCX) or nil,
            RDX = RDX and toHex(RDX) or nil,
            RSI = RSI and toHex(RSI) or nil,
            RDI = RDI and toHex(RDI) or nil,
            RBP = RBP and toHex(RBP) or nil,
            RSP = RSP and toHex(RSP) or nil,
            RIP = RIP and toHex(RIP) or nil,
            R8 = R8 and toHex(R8) or nil,
            R9 = R9 and toHex(R9) or nil,
            R10 = R10 and toHex(R10) or nil,
            R11 = R11 and toHex(R11) or nil,
            R12 = R12 and toHex(R12) or nil,
            R13 = R13 and toHex(R13) or nil,
            R14 = R14 and toHex(R14) or nil,
            R15 = R15 and toHex(R15) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x64"
        }
    else
        return {
            EAX = EAX and toHex(EAX) or nil,
            EBX = EBX and toHex(EBX) or nil,
            ECX = ECX and toHex(ECX) or nil,
            EDX = EDX and toHex(EDX) or nil,
            ESI = ESI and toHex(ESI) or nil,
            EDI = EDI and toHex(EDI) or nil,
            EBP = EBP and toHex(EBP) or nil,
            ESP = ESP and toHex(ESP) or nil,
            EIP = EIP and toHex(EIP) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x86"
        }
    end
end

-- Universal stack capture - reads stack with correct pointer size
local function captureStack(depth)
    local arch = getArchInfo()
    local stack = {}
    local stackPtr = arch.stackPtr
    if not stackPtr then return stack end
    
    for i = 0, depth - 1 do
        local val
        if arch.is64bit then
            val = readQword(stackPtr + i * arch.ptrSize)
        else
            val = readInteger(stackPtr + i * arch.ptrSize)
        end
        if val then stack[i] = toHex(val) end
    end
    return stack
end

-- ============================================================================
-- CLEANUP & SAFETY ROUTINES (CRITICAL FOR ROBUSTNESS)
-- ============================================================================
-- Prevents "zombie" breakpoints and DBVM watches when script is reloaded

local function cleanupZombieState()
    log("Cleaning up zombie resources...")
    local cleaned = { breakpoints = 0, dbvm_watches = 0, scans = 0 }
    
    -- 1. Remove all Hardware Breakpoints managed by us
    if serverState.breakpoints then
        for id, bp in pairs(serverState.breakpoints) do
            if bp.address then
                local ok = pcall(function() debug_removeBreakpoint(bp.address) end)
                if ok then cleaned.breakpoints = cleaned.breakpoints + 1 end
            end
        end
    end
    
    -- 2. Stop all DBVM Watches
    if serverState.active_watches then
        for key, watch in pairs(serverState.active_watches) do
            if watch.id then
                local ok = pcall(function() dbvm_watch_disable(watch.id) end)
                if ok then cleaned.dbvm_watches = cleaned.dbvm_watches + 1 end
            end
        end
    end

    -- 3. Cleanup Scan memory objects
    if serverState.scan_memscan then
        pcall(function() serverState.scan_memscan.destroy() end)
        serverState.scan_memscan = nil
        cleaned.scans = cleaned.scans + 1
    end
    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
        serverState.scan_foundlist = nil
    end

    -- Reset all tracking tables
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    serverState.active_watches = {}
    
    if cleaned.breakpoints > 0 or cleaned.dbvm_watches > 0 or cleaned.scans > 0 then
        log(string.format("Cleaned: %d breakpoints, %d DBVM watches, %d scans", 
            cleaned.breakpoints, cleaned.dbvm_watches, cleaned.scans))
    end
    
    return cleaned
end

-- ============================================================================
-- JSON LIBRARY (Pure Lua - Complete Implementation)
-- ============================================================================
local json = {}
local encode

local escape_char_map = { [ "\\" ] = "\\", [ "\"" ] = "\"", [ "\b" ] = "b", [ "\f" ] = "f", [ "\n" ] = "n", [ "\r" ] = "r", [ "\t" ] = "t" }
local escape_char_map_inv = { [ "/" ] = "/" }
for k, v in pairs(escape_char_map) do escape_char_map_inv[v] = k end
local function escape_char(c) return "\\" .. (escape_char_map[c] or string.format("u%04x", c:byte())) end
local function encode_nil(val) return "null" end
local function encode_table(val, stack)
  local res, stack = {}, stack or {}
  if stack[val] then error("circular reference") end
  stack[val] = true
  if rawget(val, 1) ~= nil or next(val) == nil then
    for i, v in ipairs(val) do table.insert(res, encode(v, stack)) end
    stack[val] = nil
    return "[" .. table.concat(res, ",") .. "]"
  else
    for k, v in pairs(val) do
      if type(k) ~= "string" then k = tostring(k) end
      table.insert(res, encode(k, stack) .. ":" .. encode(v, stack))
    end
    stack[val] = nil
    return "{" .. table.concat(res, ",") .. "}"
  end
end
local function encode_string(val) return '"' .. val:gsub('[%z\1-\31\\"]', escape_char) .. '"' end
local function encode_number(val) if val ~= val or val <= -math.huge or val >= math.huge then return "null" end return string.format("%.14g", val) end
local type_func_map = { ["nil"] = encode_nil, ["table"] = encode_table, ["string"] = encode_string, ["number"] = encode_number, ["boolean"] = tostring, ["function"] = function() return "null" end, ["userdata"] = function() return "null" end }
encode = function(val, stack) local t = type(val) local f = type_func_map[t] if f then return f(val, stack) end error("unexpected type '" .. t .. "'") end
json.encode = encode

local function decode_scanwhite(str, pos) return str:find("%S", pos) or #str + 1 end
local decode
local function decode_string(str, pos)
  local startpos = pos + 1
  local endpos = pos
  while true do
    endpos = str:find('["\\]', endpos + 1)
    if not endpos then return nil, "expected closing quote" end
    if str:sub(endpos, endpos) == '"' then break end
    endpos = endpos + 1
  end
  local s = str:sub(startpos, endpos - 1)
  s = s:gsub("\\.", function(c) return escape_char_map_inv[c:sub(2)] or c end)
  s = s:gsub("\\u(%x%x%x%x)", function(hex) return string.char(tonumber(hex, 16)) end)
  return s, endpos + 1
end
local function decode_number(str, pos)
  local numstr = str:match("^-?%d+%.?%d*[eE]?[+-]?%d*", pos)
  local val = tonumber(numstr)
  if not val then return nil, "invalid number" end
  return val, pos + #numstr
end
local function decode_literal(str, pos)
  local word = str:match("^%a+", pos)
  if word == "true" then return true, pos + 4 end
  if word == "false" then return false, pos + 5 end
  if word == "null" then return nil, pos + 4 end
  return nil, "invalid literal"
end
local function decode_array(str, pos)
  pos = pos + 1
  local arr, n = {}, 0
  pos = decode_scanwhite(str, pos)
  if str:sub(pos, pos) == "]" then return arr, pos + 1 end
  while true do
    local val val, pos = decode(str, pos)
    n = n + 1 arr[n] = val
    pos = decode_scanwhite(str, pos)
    local c = str:sub(pos, pos)
    if c == "]" then return arr, pos + 1 end
    if c ~= "," then return nil, "expected ']' or ','" end
    pos = decode_scanwhite(str, pos + 1)
  end
end
local function decode_object(str, pos)
  pos = pos + 1
  local obj = {}
  pos = decode_scanwhite(str, pos)
  if str:sub(pos, pos) == "}" then return obj, pos + 1 end
  while true do
    local key key, pos = decode_string(str, pos) if not key then return nil, "expected string key" end
    pos = decode_scanwhite(str, pos)
    if str:sub(pos, pos) ~= ":" then return nil, "expected ':'" end
    pos = decode_scanwhite(str, pos + 1)
    local val val, pos = decode(str, pos) obj[key] = val
    pos = decode_scanwhite(str, pos)
    local c = str:sub(pos, pos)
    if c == "}" then return obj, pos + 1 end
    if c ~= "," then return nil, "expected '}' or ','" end
    pos = decode_scanwhite(str, pos + 1)
  end
end
local char_func_map = { ['"'] = decode_string, ["{"] = decode_object, ["["] = decode_array }
setmetatable(char_func_map, { __index = function(t, c) if c:match("%d") or c == "-" then return decode_number end return decode_literal end })
decode = function(str, pos)
  pos = pos or 1
  pos = decode_scanwhite(str, pos)
  local c = str:sub(pos, pos)
  return char_func_map[c](str, pos)
end
json.decode = decode

-- ============================================================================
-- COMMAND HANDLERS - PROCESS & MODULES
-- ============================================================================

local function cmd_get_process_info(params)
    -- FORCE REFRESH: Tell CE to try and reload symbols using current DBVM rights
    pcall(reinitializeSymbolhandler)
    
    local pid = getOpenedProcessID()
    if pid and pid > 0 then
        -- Get modules using the same logic as enum_modules (with AOB fallback)
        local modules = enumModules(pid)
        if not modules or #modules == 0 then
            modules = enumModules()
        end
        
        -- Build module list
        local moduleList = {}
        local mainModuleName = nil
        local usedAobFallback = false
        
        if modules and #modules > 0 then
            for i = 1, math.min(#modules, 50) do
                local m = modules[i]
                if m then
                    table.insert(moduleList, {
                        name = m.Name or "???",
                        address = toHex(m.Address or 0),
                        size = m.Size or 0
                    })
                    if i == 1 then mainModuleName = m.Name end
                end
            end
        end
        
        -- If still no modules, try AOB fallback for PE headers with EXPORT DIRECTORY name reading
        if #moduleList == 0 then
            usedAobFallback = true
            local mzScan = AOBScan("4D 5A 90 00 03 00 00 00")
            if mzScan and mzScan.Count > 0 then
                for i = 0, math.min(mzScan.Count - 1, 50) do
                    local addr = tonumber(mzScan.getString(i), 16)
                    if addr then
                        local peOffset = readInteger(addr + 0x3C)
                        local moduleSize = 0
                        local realName = nil
                        
                        if peOffset and peOffset > 0 and peOffset < 0x1000 then
                            -- Get Size of Image
                            local sizeOfImage = readInteger(addr + peOffset + 0x50)
                            if sizeOfImage then moduleSize = sizeOfImage end
                            
                            -- TRY TO READ INTERNAL NAME FROM EXPORT DIRECTORY
                            -- PE Header + 0x78 is the Data Directory for Exports (32-bit)
                            local exportRVA = readInteger(addr + peOffset + 0x78)
                            if exportRVA and exportRVA > 0 and exportRVA < 0x10000000 then
                                -- Export Directory + 0x0C is the Name RVA
                                local nameRVA = readInteger(addr + exportRVA + 0x0C)
                                if nameRVA and nameRVA > 0 and nameRVA < 0x10000000 then
                                    local name = readString(addr + nameRVA, 64)
                                    if name and #name > 0 and #name < 60 then
                                        realName = name
                                    end
                                end
                            end
                        end
                        
                        -- Determine module name
                        local modName
                        if realName then
                            modName = realName
                        elseif i == 0 then
                            -- First module is likely main exe - use process name or L2.exe
                            modName = (process ~= "" and process) or "L2.exe"
                        else
                            modName = "Module_" .. string.format("%X", addr)
                        end
                        
                        table.insert(moduleList, {
                            name = modName,
                            address = toHex(addr),
                            size = moduleSize,
                            source = realName and "export_directory" or "aob_fallback"
                        })
                        
                        if i == 0 then mainModuleName = modName end
                    end
                end
                mzScan.destroy()
            end
        end
        
        -- Use real process name if available, otherwise default to L2.exe
        -- IMPORTANT: Do NOT use mainModuleName from AOB scan - it's just the first DLL in memory order
        -- which could be anything. When anti-cheat hides the process, we hardcode L2.exe.
        local name = (process ~= "" and process) or "L2.exe"
        
        return { 
            success = true, 
            process_id = pid, 
            process_name = name,
            module_count = #moduleList,
            modules = moduleList,
            used_aob_fallback = usedAobFallback
        }
    end
    return { success = false, error = "No process attached" }
end

local function cmd_enum_modules(params)
    local pid = getOpenedProcessID()
    local modules = enumModules(pid)  -- Try with PID first
    
    -- If that fails, try without PID
    if not modules or #modules == 0 then
        modules = enumModules()
    end
    
    local result = {}
    if modules and #modules > 0 then
        for i, m in ipairs(modules) do
            if m then
                table.insert(result, {
                    name = m.Name or "???",
                    address = toHex(m.Address or 0),
                    size = m.Size or 0,
                    is_64bit = m.Is64Bit or false,
                    path = m.PathToFile or ""
                })
            end
        end
    end
    
    -- Fallback: If no modules found, try to find them via MZ header scan with Export Directory name reading
    if #result == 0 then
        local mzScan = AOBScan("4D 5A 90 00 03 00 00 00")  -- MZ PE header
        if mzScan and mzScan.Count > 0 then
            for i = 0, math.min(mzScan.Count - 1, 50) do
                local addr = tonumber(mzScan.getString(i), 16)
                if addr then
                    local peOffset = readInteger(addr + 0x3C)
                    local moduleSize = 0
                    local realName = nil
                    
                    if peOffset and peOffset > 0 and peOffset < 0x1000 then
                        -- Get Size of Image
                        local sizeOfImage = readInteger(addr + peOffset + 0x50)
                        if sizeOfImage then moduleSize = sizeOfImage end
                        
                        -- READ INTERNAL NAME FROM EXPORT DIRECTORY
                        local exportRVA = readInteger(addr + peOffset + 0x78)
                        if exportRVA and exportRVA > 0 and exportRVA < 0x10000000 then
                            local nameRVA = readInteger(addr + exportRVA + 0x0C)
                            if nameRVA and nameRVA > 0 and nameRVA < 0x10000000 then
                                local name = readString(addr + nameRVA, 64)
                                if name and #name > 0 and #name < 60 then
                                    realName = name
                                end
                            end
                        end
                    end
                    
                    -- Determine module name
                    local modName
                    if realName then
                        modName = realName
                    elseif i == 0 then
                        modName = (process ~= "" and process) or "L2.exe"
                    else
                        modName = "Module_" .. string.format("%X", addr)
                    end
                    
                    table.insert(result, {
                        name = modName,
                        address = toHex(addr),
                        size = moduleSize,
                        is_64bit = false,
                        path = "",
                        source = realName and "export_directory" or "aob_fallback"
                    })
                end
            end
            mzScan.destroy()
        end
    end
    
    return { success = true, modules = result, count = #result, fallback_used = #result > 0 and result[1] and result[1].source ~= nil }
end

local function cmd_get_symbol_address(params)
    local symbol = params.symbol or params.name
    if not symbol then return { success = false, error = "No symbol name" } end
    
    local addr = getAddressSafe(symbol)
    if addr then
        return { success = true, symbol = symbol, address = toHex(addr), value = addr }
    end
    return { success = false, error = "Symbol not found: " .. symbol }
end

-- ============================================================================
-- COMMAND HANDLERS - MEMORY READ
-- ============================================================================

local function cmd_read_memory(params)
    local addr = params.address
    local size = math.min(params.size or 256, 65536)
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local bytes = readBytes(addr, size, true)
    if not bytes then return { success = false, error = "Failed to read at " .. toHex(addr) } end
    
    local hex = {}
    for i, b in ipairs(bytes) do hex[i] = string.format("%02X", b) end
    
    return { 
        success = true, 
        address = toHex(addr), 
        size = #bytes, 
        data = table.concat(hex, " "),
        bytes = bytes
    }
end

local function cmd_read_integer(params)
    local addr = params.address
    local itype = params.type or "dword"
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local val
    if itype == "byte" then
        local b = readBytes(addr, 1, true)
        if b and #b > 0 then val = b[1] end
    elseif itype == "word" then val = readSmallInteger(addr)
    elseif itype == "dword" then val = readInteger(addr)
    elseif itype == "qword" then val = readQword(addr)
    elseif itype == "float" then val = readFloat(addr)
    elseif itype == "double" then val = readDouble(addr)
    else return { success = false, error = "Unknown type: " .. tostring(itype) } end
    
    if val == nil then return { success = false, error = "Failed to read at " .. toHex(addr) } end
    
    -- Only format hex for integer types - toHex() crashes on non-integer floats
    local hex = nil
    if itype == "byte" or itype == "word" or itype == "dword" or itype == "qword" then
        hex = toHex(val)
    end
    return { success = true, address = toHex(addr), value = val, type = itype, hex = hex }
end

local function cmd_read_string(params)
    local addr = params.address
    local maxlen = params.max_length or 256
    local wide = params.wide or false
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local str = readString(addr, maxlen, wide)
    
    -- Sanitize non-printable characters for JSON compatibility
    local sanitized = ""
    if str then
        for i = 1, #str do
            local byte = str:byte(i)
            if byte >= 32 and byte < 127 then
                sanitized = sanitized .. str:sub(i, i)
            elseif byte == 9 or byte == 10 or byte == 13 then
                sanitized = sanitized .. " "  -- Replace tabs/newlines with space
            else
                sanitized = sanitized .. string.format("\\x%02X", byte)
            end
        end
    end
    
    return { success = true, address = toHex(addr), value = sanitized, wide = wide, length = str and #str or 0, raw_length = #sanitized }
end

local function cmd_read_pointer(params)
    local base = params.base or params.address
    local offsets = params.offsets or {}
    
    base = resolveAddr(base)
    if not base then return { success = false, error = "Invalid base address" } end
    
    local currentAddr = base
    local path = { toHex(base) }
    
    for i, offset in ipairs(offsets) do
        -- Use readPointer for 32/64-bit compatibility (readInteger on 32-bit, readQword on 64-bit)
        local ptr = readPointer(currentAddr)
        if not ptr then
            return { success = false, error = "Failed to read pointer at " .. toHex(currentAddr), path = path }
        end
        currentAddr = ptr + offset
        table.insert(path, toHex(currentAddr))
    end
    
    -- Read final value using readPointer for 32/64-bit compatibility
    local finalValue = readPointer(currentAddr)
    return { 
        success = true, 
        base = toHex(base), 
        final_address = toHex(currentAddr), 
        value = finalValue, 
        path = path 
    }
end

-- ============================================================================
-- COMMAND HANDLERS - PATTERN SCANNING
-- ============================================================================

local function cmd_aob_scan(params)
    local pattern = params.pattern
    local protection = params.protection or "+X"
    local limit = params.limit or 100
    -- Optional range bounds (essential for emulator scans where you only want
    -- to scan inside the guest RAM region). Accepts guest or host addresses;
    -- guest addresses are translated to host before filtering.
    local startAddr = _num(params.start_address)
    local endAddr   = _num(params.end_address)
    if startAddr then startAddr = translateGuest(startAddr) end
    if endAddr   then endAddr   = translateGuest(endAddr) end

    if not pattern then return { success = false, error = "No pattern provided" } end

    local results = AOBScan(pattern, protection)
    if not results then return { success = true, count = 0, addresses = {} } end

    local hasGuest = serverState.guestRegions and #serverState.guestRegions > 0
    local addresses = {}
    local total = results.Count
    for i = 0, total - 1 do
        if #addresses >= limit then break end
        local addrStr = results.getString(i)
        local addr = tonumber(addrStr, 16)
        local inRange = true
        if addr then
            if startAddr and addr < startAddr then inRange = false end
            if endAddr   and addr > endAddr   then inRange = false end
        end
        if inRange then
            local entry = { address = "0x" .. addrStr, value = addr }
            if hasGuest and addr then
                local g = translateHost(addr)
                if g then entry.guest_address = toHex(g) end
            end
            table.insert(addresses, entry)
        end
    end
    results.destroy()

    return { success = true, count = #addresses, total_scanned = total, pattern = pattern, addresses = addresses }
end

local function cmd_scan_all(params)
    local value = params.value
    local vtype = params.type or "dword"

    local ms = createMemScan()
    local scanOpt = soExactValue
    local varType = vtDword

    if vtype == "byte" then varType = vtByte
    elseif vtype == "word" then varType = vtWord
    elseif vtype == "qword" then varType = vtQword
    elseif vtype == "float" then varType = vtSingle
    elseif vtype == "double" then varType = vtDouble
    elseif vtype == "string" then varType = vtString end

    -- Use specific protection flags if provided (defaults to +W-C from Python)
    -- CRITICAL: Limit scan to User Mode space (0x7FFFFFFFFFFFFFFF) to prevent BSODs in Kernel/Guard regions
    local protect = params.protection or "+W-C"

    -- Optional scan range bounds. For emulator workflows, AI should pass the
    -- detected guest RAM range here so scans stay inside game memory. Accepts
    -- guest addresses (auto-translated) or host addresses.
    local startAddr = _num(params.start_address) or 0
    local endAddr   = _num(params.end_address) or 0x7FFFFFFFFFFFFFFF
    if startAddr > 0 then startAddr = translateGuest(startAddr) end
    if endAddr < 0x7FFFFFFFFFFFFFFF then endAddr = translateGuest(endAddr) end

    ms.firstScan(scanOpt, varType, rtRounded, tostring(value), nil, startAddr, endAddr, protect, fsmNotAligned, "1", false, false, false, false)
    ms.waitTillDone()

    local fl = createFoundList(ms)
    fl.initialize()
    local count = fl.getCount()

    serverState.scan_memscan = ms
    serverState.scan_foundlist = fl

    return { success = true, count = count, range_start = toHex(startAddr), range_end = toHex(endAddr) }
end

local function cmd_get_scan_results(params)
    local max = params.max or 100

    if not serverState.scan_foundlist then
        return { success = false, error = "No scan results. Run scan_all first." }
    end

    local fl = serverState.scan_foundlist
    local results = {}
    local count = math.min(fl.getCount(), max)
    local hasGuest = serverState.guestRegions and #serverState.guestRegions > 0

    for i = 0, count - 1 do
        -- IMPORTANT: Ensure address has 0x prefix for consistency with all other commands
        local addrStr = fl.getAddress(i)
        if addrStr and not addrStr:match("^0x") and not addrStr:match("^0X") then
            addrStr = "0x" .. addrStr
        end
        local entry = {
            address = addrStr,
            value = fl.getValue(i)
        }
        if hasGuest then
            local hostAddr = _num(addrStr)
            if hostAddr then
                local g = translateHost(hostAddr)
                if g then entry.guest_address = toHex(g) end
            end
        end
        table.insert(results, entry)
    end

    return { success = true, results = results, total = fl.getCount(), returned = count }
end

-- ============================================================================
-- COMMAND HANDLERS - NEXT SCAN & WRITE MEMORY (Added by MCP Enhancement)
-- ============================================================================

local function cmd_next_scan(params)
    local value = params.value
    local scanType = params.scan_type or "exact"
    
    if not serverState.scan_memscan then
        return { success = false, error = "No previous scan. Run scan_all first." }
    end
    
    local ms = serverState.scan_memscan
    local scanOpt = soExactValue
    
    if scanType == "increased" then scanOpt = soIncreasedValue
    elseif scanType == "decreased" then scanOpt = soDecreasedValue
    elseif scanType == "changed" then scanOpt = soChanged
    elseif scanType == "unchanged" then scanOpt = soUnchanged
    elseif scanType == "bigger" then scanOpt = soBiggerThan
    elseif scanType == "smaller" then scanOpt = soSmallerThan
    end
    
    if scanOpt == soExactValue then
        ms.nextScan(scanOpt, rtRounded, tostring(value), nil, false, false, false, false, false)
    else
        ms.nextScan(scanOpt, rtRounded, nil, nil, false, false, false, false, false)
    end
    ms.waitTillDone()
    
    if serverState.scan_foundlist then
        serverState.scan_foundlist.destroy()
    end
    local fl = createFoundList(ms)
    fl.initialize()
    serverState.scan_foundlist = fl
    
    return { success = true, count = fl.getCount() }
end

local function cmd_write_integer(params)
    local addr = params.address
    local value = params.value
    local vtype = params.type or "dword"
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local ok, err
    if vtype == "byte" then
        ok, err = pcall(writeByte, addr, value)
    elseif vtype == "word" or vtype == "2bytes" then
        ok, err = pcall(writeSmallInteger, addr, value)
    elseif vtype == "dword" or vtype == "4bytes" then
        ok, err = pcall(writeInteger, addr, value)
    elseif vtype == "qword" or vtype == "8bytes" then
        ok, err = pcall(writeQword, addr, value)
    elseif vtype == "float" then
        ok, err = pcall(writeFloat, addr, value)
    elseif vtype == "double" then
        ok, err = pcall(writeDouble, addr, value)
    else
        return { success = false, error = "Unknown type: " .. tostring(vtype) }
    end
    
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end
    
    return { success = true, address = toHex(addr), value = value, type = vtype }
end

local function cmd_write_memory(params)
    local addr = params.address
    local bytes = params.bytes
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    if not bytes or #bytes == 0 then return { success = false, error = "No bytes provided" } end
    
    local ok, err = pcall(writeBytes, addr, bytes)
    
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end
    
    return { success = true, address = toHex(addr), bytes_written = #bytes }
end

local function cmd_write_string(params)
    local addr = params.address
    local str = params.value or params.string
    local wide = params.wide or false
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    if not str then return { success = false, error = "No string provided" } end
    
    local ok, err = pcall(writeString, addr, str, wide)
    
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end
    
    return { success = true, address = toHex(addr), length = #str, wide = wide }
end


-- ============================================================================
-- COMMAND HANDLERS - DISASSEMBLY & ANALYSIS
-- ============================================================================

local function cmd_disassemble(params)
    local addr = params.address
    local count = params.count or 20
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local instructions = {}
    local currentAddr = addr
    
    for i = 1, count do
        local ok, disasm = pcall(disassemble, currentAddr)
        if not ok or not disasm then break end
        
        local instSize = getInstructionSize(currentAddr) or 1
        local instBytes = readBytes(currentAddr, instSize, true) or {}
        local bytesHex = {}
        for _, b in ipairs(instBytes) do table.insert(bytesHex, string.format("%02X", b)) end
        
        table.insert(instructions, {
            address = toHex(currentAddr),
            offset = currentAddr - addr,
            size = instSize,
            bytes = table.concat(bytesHex, " "),
            instruction = disasm
        })
        
        currentAddr = currentAddr + instSize
    end
    
    return { success = true, start_address = toHex(addr), count = #instructions, instructions = instructions }
end

-- ----------------------------------------------------------------------------
-- PowerPC (PPC32) disassembler
-- ----------------------------------------------------------------------------
-- CE's built-in disassemble() emits x86. GameCube/Wii (Dolphin) game code is
-- PowerPC big-endian, fixed 4-byte instructions. This decoder operates on raw
-- bytes read via readBytes(), so it works equally well whether the address is
-- a host VA inside dolphin.exe or a guest VA (0x80xxxxxx) routed through
-- guestBase. Coverage focuses on the instruction set actually used by
-- GameCube/Wii game executables (gekko/broadway minus paired-singles, which
-- are decoded as raw .long).
local function disasmPPC(word, addr)
    -- Bit field extractor (PPC numbering: bit 0 = MSB of the 32-bit word)
    local function f(hi, lo)
        local width = lo - hi + 1
        return math.floor(word / 2^(31 - lo)) % 2^width
    end
    local function sext(v, width)
        local half = 2^(width - 1)
        if v >= half then return v - 2^width end
        return v
    end
    local function himm(v) -- format signed immediate
        if v < 0 then return "-0x" .. string.format("%X", -v) end
        return "0x" .. string.format("%X", v)
    end

    -- Common all-zero / all-bit-set special cases
    if word == 0x60000000 then return "nop" end
    if word == 0x4E800020 then return "blr" end
    if word == 0x4E800021 then return "blrl" end
    if word == 0x4E800420 then return "bctr" end
    if word == 0x4E800421 then return "bctrl" end
    if word == 0x4C00012C then return "isync" end
    if word == 0x7C0004AC then return "sync" end
    if word == 0x4C000064 then return "rfi" end

    local op = f(0, 5)
    local rt = f(6, 10)   -- RT or RS
    local ra = f(11, 15)
    local rb = f(16, 20)
    local d  = sext(f(16, 31), 16)
    local ui = f(16, 31)
    local lk = f(31, 31)
    local aa = f(30, 30)

    -- D-form loads/stores: opcode | RT/RS | RA | D
    local dform_loads = {
        [32]="lwz",[33]="lwzu",[34]="lbz",[35]="lbzu",
        [40]="lhz",[41]="lhzu",[42]="lha",[43]="lhau",
        [46]="lmw",[48]="lfs",[49]="lfsu",[50]="lfd",[51]="lfdu",
    }
    local dform_stores = {
        [36]="stw",[37]="stwu",[38]="stb",[39]="stbu",
        [44]="sth",[45]="sthu",[47]="stmw",
        [52]="stfs",[53]="stfsu",[54]="stfd",[55]="stfdu",
    }
    if dform_loads[op] then
        local prefix = (op >= 48) and "f" or "r"
        return string.format("%s %s%d, %d(r%d)", dform_loads[op], prefix, rt, d, ra)
    end
    if dform_stores[op] then
        local prefix = (op >= 52) and "f" or "r"
        return string.format("%s %s%d, %d(r%d)", dform_stores[op], prefix, rt, d, ra)
    end

    -- Immediate arithmetic / logical
    if op == 14 then
        if ra == 0 then return string.format("li r%d, %s", rt, himm(d)) end
        return string.format("addi r%d, r%d, %s", rt, ra, himm(d))
    end
    if op == 15 then
        if ra == 0 then return string.format("lis r%d, 0x%X", rt, ui) end
        return string.format("addis r%d, r%d, 0x%X", rt, ra, ui)
    end
    if op == 12 then return string.format("addic r%d, r%d, %s",  rt, ra, himm(d)) end
    if op == 13 then return string.format("addic. r%d, r%d, %s", rt, ra, himm(d)) end
    if op == 7  then return string.format("mulli r%d, r%d, %s",  rt, ra, himm(d)) end
    if op == 8  then return string.format("subfic r%d, r%d, %s", rt, ra, himm(d)) end
    if op == 24 then return string.format("ori r%d, r%d, 0x%X",   ra, rt, ui) end
    if op == 25 then return string.format("oris r%d, r%d, 0x%X",  ra, rt, ui) end
    if op == 26 then return string.format("xori r%d, r%d, 0x%X",  ra, rt, ui) end
    if op == 27 then return string.format("xoris r%d, r%d, 0x%X", ra, rt, ui) end
    if op == 28 then return string.format("andi. r%d, r%d, 0x%X", ra, rt, ui) end
    if op == 29 then return string.format("andis. r%d, r%d, 0x%X",ra, rt, ui) end

    -- Compare immediate
    if op == 11 then
        local cr = f(6, 8); local l = f(10, 10)
        return string.format("cmp%si cr%d, r%d, %s", l == 1 and "d" or "w", cr, ra, himm(d))
    end
    if op == 10 then
        local cr = f(6, 8); local l = f(10, 10)
        return string.format("cmpl%si cr%d, r%d, 0x%X", l == 1 and "d" or "w", cr, ra, ui)
    end

    -- Unconditional branch (I-form)
    if op == 18 then
        local li = f(6, 29) * 4
        if li >= 2^25 then li = li - 2^26 end
        local target = (aa == 1) and li or (addr + li)
        return string.format("%s%s 0x%X", lk == 1 and "bl" or "b", aa == 1 and "a" or "", target)
    end
    -- Conditional branch (B-form)
    if op == 16 then
        local bo = f(6, 10); local bi = f(11, 15)
        local bd = f(16, 29) * 4
        if bd >= 2^15 then bd = bd - 2^16 end
        local target = (aa == 1) and bd or (addr + bd)
        local cond = bi % 4
        local mnem
        if     bo == 12 and cond == 0 then mnem = "blt"
        elseif bo == 4  and cond == 0 then mnem = "bge"
        elseif bo == 12 and cond == 1 then mnem = "bgt"
        elseif bo == 4  and cond == 1 then mnem = "ble"
        elseif bo == 12 and cond == 2 then mnem = "beq"
        elseif bo == 4  and cond == 2 then mnem = "bne"
        elseif bo == 12 and cond == 3 then mnem = "bso"
        elseif bo == 4  and cond == 3 then mnem = "bns"
        elseif bo == 16 then mnem = "bdnz"
        elseif bo == 18 then mnem = "bdz"
        else                 mnem = string.format("bc(%d,%d)", bo, bi)
        end
        local cr = math.floor(bi / 4)
        local suffix = (lk==1 and "l" or "") .. (aa==1 and "a" or "")
        if mnem:match("^b[a-z]+$") and cr == 0 then
            return string.format("%s%s 0x%X", mnem, suffix, target)
        end
        return string.format("%s%s cr%d, 0x%X", mnem, suffix, cr, target)
    end

    -- Op-19: branch via LR/CTR + condition register ops
    if op == 19 then
        local xo = f(21, 30)
        if xo == 16 then
            local bo = f(6, 10)
            if bo == 20 then return lk == 1 and "blrl" or "blr" end
            return string.format("bclr%s %d,%d", lk==1 and "l" or "", bo, f(11,15))
        end
        if xo == 528 then
            local bo = f(6, 10)
            if bo == 20 then return lk == 1 and "bctrl" or "bctr" end
            return string.format("bcctr%s %d,%d", lk==1 and "l" or "", bo, f(11,15))
        end
        if xo == 150 then return "isync" end
        if xo == 50  then return "rfi" end
        if xo == 0   then return string.format("mcrf cr%d, cr%d", math.floor(rt/4), math.floor(ra/4)) end
        if xo == 33  then return string.format("crnor %d, %d, %d", rt, ra, rb) end
        if xo == 129 then return string.format("crandc %d, %d, %d", rt, ra, rb) end
        if xo == 193 then return string.format("crxor %d, %d, %d", rt, ra, rb) end
        if xo == 225 then return string.format("crnand %d, %d, %d", rt, ra, rb) end
        if xo == 257 then return string.format("crand %d, %d, %d", rt, ra, rb) end
        if xo == 289 then return string.format("creqv %d, %d, %d", rt, ra, rb) end
        if xo == 417 then return string.format("crorc %d, %d, %d", rt, ra, rb) end
        if xo == 449 then return string.format("cror %d, %d, %d", rt, ra, rb) end
    end

    -- Rotate/shift immediate
    if op == 21 then
        local sh = f(16, 20); local mb = f(21, 25); local me = f(26, 30); local rc = f(31,31)
        local rcdot = rc == 1 and "." or ""
        if mb == 0 and me == 31 - sh and sh ~= 0 then
            return string.format("slwi%s r%d, r%d, %d", rcdot, ra, rt, sh)
        end
        if me == 31 and mb == 32 - sh and sh ~= 0 then
            return string.format("srwi%s r%d, r%d, %d", rcdot, ra, rt, 32 - sh)
        end
        if sh == 0 and mb == 0 then
            return string.format("clrrwi%s r%d, r%d, %d", rcdot, ra, rt, 31 - me)
        end
        if sh == 0 and me == 31 then
            return string.format("clrlwi%s r%d, r%d, %d", rcdot, ra, rt, mb)
        end
        return string.format("rlwinm%s r%d, r%d, %d, %d, %d", rcdot, ra, rt, sh, mb, me)
    end
    if op == 20 then
        local sh = f(16, 20); local mb = f(21, 25); local me = f(26, 30); local rc = f(31,31)
        return string.format("rlwimi%s r%d, r%d, %d, %d, %d", rc==1 and "." or "", ra, rt, sh, mb, me)
    end
    if op == 23 then
        local mb = f(21, 25); local me = f(26, 30); local rc = f(31,31)
        return string.format("rlwnm%s r%d, r%d, r%d, %d, %d", rc==1 and "." or "", ra, rt, rb, mb, me)
    end

    -- Op-31: extended XO-form (huge category)
    if op == 31 then
        local xo  = f(21, 30)
        local rc  = f(31, 31)
        local oe  = f(21, 21)
        local rcdot = rc == 1 and "." or ""
        local oestr = oe == 1 and "o" or ""
        local xo9 = xo % 512  -- ignore OE bit for arithmetic family

        -- Logical
        if xo == 444 then
            if rt == rb then return string.format("mr%s r%d, r%d", rcdot, ra, rt) end
            return string.format("or%s r%d, r%d, r%d", rcdot, ra, rt, rb)
        end
        if xo == 28  then return string.format("and%s r%d, r%d, r%d",  rcdot, ra, rt, rb) end
        if xo == 60  then return string.format("andc%s r%d, r%d, r%d", rcdot, ra, rt, rb) end
        if xo == 124 then return string.format("nor%s r%d, r%d, r%d",  rcdot, ra, rt, rb) end
        if xo == 284 then return string.format("eqv%s r%d, r%d, r%d",  rcdot, ra, rt, rb) end
        if xo == 316 then return string.format("xor%s r%d, r%d, r%d",  rcdot, ra, rt, rb) end
        if xo == 412 then return string.format("orc%s r%d, r%d, r%d",  rcdot, ra, rt, rb) end
        if xo == 476 then return string.format("nand%s r%d, r%d, r%d", rcdot, ra, rt, rb) end

        -- Arithmetic (XO-form, OE bit may be set)
        if xo9 == 266 then return string.format("add%s%s r%d, r%d, r%d",   oestr, rcdot, rt, ra, rb) end
        if xo9 == 40  then return string.format("subf%s%s r%d, r%d, r%d",  oestr, rcdot, rt, ra, rb) end
        if xo9 == 10  then return string.format("addc%s%s r%d, r%d, r%d",  oestr, rcdot, rt, ra, rb) end
        if xo9 == 8   then return string.format("subfc%s%s r%d, r%d, r%d", oestr, rcdot, rt, ra, rb) end
        if xo9 == 138 then return string.format("adde%s%s r%d, r%d, r%d",  oestr, rcdot, rt, ra, rb) end
        if xo9 == 136 then return string.format("subfe%s%s r%d, r%d, r%d", oestr, rcdot, rt, ra, rb) end
        if xo9 == 234 then return string.format("addme%s%s r%d, r%d",      oestr, rcdot, rt, ra) end
        if xo9 == 232 then return string.format("subfme%s%s r%d, r%d",     oestr, rcdot, rt, ra) end
        if xo9 == 202 then return string.format("addze%s%s r%d, r%d",      oestr, rcdot, rt, ra) end
        if xo9 == 200 then return string.format("subfze%s%s r%d, r%d",     oestr, rcdot, rt, ra) end
        if xo9 == 235 then return string.format("mullw%s%s r%d, r%d, r%d", oestr, rcdot, rt, ra, rb) end
        if xo9 == 491 then return string.format("divw%s%s r%d, r%d, r%d",  oestr, rcdot, rt, ra, rb) end
        if xo9 == 459 then return string.format("divwu%s%s r%d, r%d, r%d", oestr, rcdot, rt, ra, rb) end
        if xo9 == 104 then return string.format("neg%s%s r%d, r%d",        oestr, rcdot, rt, ra) end
        if xo == 75  then return string.format("mulhw%s r%d, r%d, r%d",  rcdot, rt, ra, rb) end
        if xo == 11  then return string.format("mulhwu%s r%d, r%d, r%d", rcdot, rt, ra, rb) end

        -- Indexed load/store
        local x_ls = {
            [23]="lwzx",[55]="lwzux",[87]="lbzx",[119]="lbzux",
            [279]="lhzx",[311]="lhzux",[343]="lhax",[375]="lhaux",
            [151]="stwx",[183]="stwux",[215]="stbx",[247]="stbux",
            [407]="sthx",[439]="sthux",
            [533]="lswx",[661]="stswx",[597]="lswi",[725]="stswi",
            [534]="lwbrx",[662]="stwbrx",[790]="lhbrx",[918]="sthbrx",
            [535]="lfsx",[567]="lfsux",[599]="lfdx",[631]="lfdux",
            [663]="stfsx",[695]="stfsux",[727]="stfdx",[759]="stfdux",
            [983]="stfiwx",
        }
        if x_ls[xo] then
            local mn = x_ls[xo]
            local prefix = mn:find("f", 2, true) and "f" or "r"
            return string.format("%s %s%d, r%d, r%d", mn, prefix, rt, ra, rb)
        end

        -- Compare register
        if xo == 0  then
            local cr = f(6, 8); local l = f(10, 10)
            return string.format("cmp%s cr%d, r%d, r%d", l == 1 and "d" or "w", cr, ra, rb)
        end
        if xo == 32 then
            local cr = f(6, 8); local l = f(10, 10)
            return string.format("cmpl%s cr%d, r%d, r%d", l == 1 and "d" or "w", cr, ra, rb)
        end

        -- Shifts
        if xo == 24  then return string.format("slw%s r%d, r%d, r%d",  rcdot, ra, rt, rb) end
        if xo == 536 then return string.format("srw%s r%d, r%d, r%d",  rcdot, ra, rt, rb) end
        if xo == 792 then return string.format("sraw%s r%d, r%d, r%d", rcdot, ra, rt, rb) end
        if xo == 824 then
            return string.format("srawi%s r%d, r%d, %d", rcdot, ra, rt, f(16, 20))
        end

        -- Sign extend / count leading zeros
        if xo == 922 then return string.format("extsh%s r%d, r%d",  rcdot, ra, rt) end
        if xo == 954 then return string.format("extsb%s r%d, r%d",  rcdot, ra, rt) end
        if xo == 26  then return string.format("cntlzw%s r%d, r%d", rcdot, ra, rt) end

        -- Move from / to special purpose register (LR, CTR, XER common cases)
        if xo == 339 or xo == 467 then
            local spr_field = f(11, 20)
            local spr = math.floor(spr_field / 32) + (spr_field % 32) * 32
            local names = {[1]="xer",[8]="lr",[9]="ctr"}
            local nm = names[spr]
            if xo == 339 then
                if nm then return string.format("mf%s r%d", nm, rt) end
                return string.format("mfspr r%d, %d", rt, spr)
            else
                if nm then return string.format("mt%s r%d", nm, rt) end
                return string.format("mtspr %d, r%d", spr, rt)
            end
        end
        if xo == 19  then return string.format("mfcr r%d", rt) end
        if xo == 144 then return string.format("mtcrf 0x%X, r%d", f(12, 19), rt) end
        if xo == 83  then return string.format("mfmsr r%d", rt) end
        if xo == 146 then return string.format("mtmsr r%d", rt) end

        -- Cache / sync / trap
        if xo == 4    then return string.format("tw %d, r%d, r%d", rt, ra, rb) end
        if xo == 54   then return string.format("dcbst r%d, r%d", ra, rb) end
        if xo == 86   then return string.format("dcbf r%d, r%d", ra, rb) end
        if xo == 246  then return string.format("dcbtst r%d, r%d", ra, rb) end
        if xo == 278  then return string.format("dcbt r%d, r%d", ra, rb) end
        if xo == 470  then return string.format("dcbi r%d, r%d", ra, rb) end
        if xo == 598  then return "sync" end
        if xo == 854  then return "eieio" end
        if xo == 982  then return string.format("icbi r%d, r%d", ra, rb) end
        if xo == 1014 then return string.format("dcbz r%d, r%d", ra, rb) end
    end

    -- Floating-point op-63 (double)
    if op == 63 then
        local xo = f(21, 30); local rc = f(31, 31); local rcdot = rc == 1 and "." or ""
        if xo == 72  then return string.format("fmr%s f%d, f%d", rcdot, rt, rb) end
        if xo == 40  then return string.format("fneg%s f%d, f%d", rcdot, rt, rb) end
        if xo == 264 then return string.format("fabs%s f%d, f%d", rcdot, rt, rb) end
        if xo == 136 then return string.format("fnabs%s f%d, f%d", rcdot, rt, rb) end
        if xo == 12  then return string.format("frsp%s f%d, f%d", rcdot, rt, rb) end
        if xo == 14  then return string.format("fctiw%s f%d, f%d", rcdot, rt, rb) end
        if xo == 15  then return string.format("fctiwz%s f%d, f%d", rcdot, rt, rb) end
        if xo == 0   then return string.format("fcmpu cr%d, f%d, f%d", math.floor(rt/4), ra, rb) end
        if xo == 32  then return string.format("fcmpo cr%d, f%d, f%d", math.floor(rt/4), ra, rb) end
        local xo5 = f(26, 30) -- A-form FP arithmetic uses 5-bit XO
        if xo5 == 21 then return string.format("fadd%s f%d, f%d, f%d", rcdot, rt, ra, rb) end
        if xo5 == 20 then return string.format("fsub%s f%d, f%d, f%d", rcdot, rt, ra, rb) end
        if xo5 == 25 then return string.format("fmul%s f%d, f%d, f%d", rcdot, rt, ra, f(21,25)) end
        if xo5 == 18 then return string.format("fdiv%s f%d, f%d, f%d", rcdot, rt, ra, rb) end
        if xo5 == 22 then return string.format("fsqrt%s f%d, f%d", rcdot, rt, rb) end
        if xo5 == 29 then return string.format("fmadd%s f%d, f%d, f%d, f%d", rcdot, rt, ra, f(21,25), rb) end
        if xo5 == 28 then return string.format("fmsub%s f%d, f%d, f%d, f%d", rcdot, rt, ra, f(21,25), rb) end
        if xo5 == 31 then return string.format("fnmadd%s f%d, f%d, f%d, f%d", rcdot, rt, ra, f(21,25), rb) end
        if xo5 == 30 then return string.format("fnmsub%s f%d, f%d, f%d, f%d", rcdot, rt, ra, f(21,25), rb) end
    end
    -- Floating-point op-59 (single): same A-form encoding, single-precision
    if op == 59 then
        local rc = f(31, 31); local rcdot = rc == 1 and "." or ""
        local xo5 = f(26, 30)
        if xo5 == 21 then return string.format("fadds%s f%d, f%d, f%d", rcdot, rt, ra, rb) end
        if xo5 == 20 then return string.format("fsubs%s f%d, f%d, f%d", rcdot, rt, ra, rb) end
        if xo5 == 25 then return string.format("fmuls%s f%d, f%d, f%d", rcdot, rt, ra, f(21,25)) end
        if xo5 == 18 then return string.format("fdivs%s f%d, f%d, f%d", rcdot, rt, ra, rb) end
        if xo5 == 22 then return string.format("fsqrts%s f%d, f%d", rcdot, rt, rb) end
        if xo5 == 29 then return string.format("fmadds%s f%d, f%d, f%d, f%d", rcdot, rt, ra, f(21,25), rb) end
        if xo5 == 28 then return string.format("fmsubs%s f%d, f%d, f%d, f%d", rcdot, rt, ra, f(21,25), rb) end
    end

    -- sc / twi / unrecognized - emit raw word so the AI still has the bytes
    if op == 17 then return "sc" end
    if op == 3  then return string.format("twi %d, r%d, %s", rt, ra, himm(d)) end
    return string.format(".long 0x%08X", word)
end

-- disassemble_ppc {address, count}
-- Reads count*4 bytes starting at address, decodes each big-endian 4-byte
-- word as a PowerPC instruction. address goes through resolveAddr() so
-- guest VAs (e.g. 0x80003100) get translated when guestBase is set.
local function cmd_disassemble_ppc(params)
    local count = math.min(math.max(params.count or 16, 1), 256)

    local hostAddr = resolveAddr(params.address)
    if not hostAddr then return { success = false, error = "Invalid address" } end

    local total = count * 4
    local bytes = readBytes(hostAddr, total, true)
    if not bytes or #bytes < 4 then
        return { success = false, error = "Failed to read at " .. toHex(hostAddr) }
    end

    -- Prefer reporting addresses in guest space when a guest base is active,
    -- so output matches what the user typed in (e.g. 0x80003100).
    local startGuest = translateHost(hostAddr)
    local startDisp  = startGuest or hostAddr

    local instructions = {}
    local readable = math.floor(#bytes / 4)
    for i = 1, math.min(count, readable) do
        local off = (i - 1) * 4
        local b1, b2, b3, b4 = bytes[off+1], bytes[off+2], bytes[off+3], bytes[off+4]
        if not b4 then break end

        -- Big-endian assembly
        local word = b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
        local dispAddr = startDisp + off

        local mnem = disasmPPC(word, dispAddr)

        table.insert(instructions, {
            address      = toHex(dispAddr),
            host_address = startGuest and toHex(hostAddr + off) or nil,
            offset       = off,
            size         = 4,
            bytes        = string.format("%02X %02X %02X %02X", b1, b2, b3, b4),
            word         = string.format("0x%08X", word),
            instruction  = mnem,
        })
    end

    return {
        success       = true,
        arch          = "powerpc",
        endian        = "big",
        start_address = toHex(startDisp),
        count         = #instructions,
        instructions  = instructions,
    }
end

local function cmd_get_instruction_info(params)
    local addr = params.address
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local ok, disasm = pcall(disassemble, addr)
    if not ok or not disasm then
        return { success = false, error = "Failed to disassemble at " .. toHex(addr) }
    end
    local size = getInstructionSize(addr)
    local bytes = readBytes(addr, size or 1, true) or {}
    local bytesHex = {}
    for _, b in ipairs(bytes) do table.insert(bytesHex, string.format("%02X", b)) end
    
    local prevAddr = getPreviousOpcode(addr)
    
    return {
        success = true,
        address = toHex(addr),
        instruction = disasm,
        size = size,
        bytes = table.concat(bytesHex, " "),
        previous_instruction = prevAddr and toHex(prevAddr) or nil
    }
end

local function cmd_find_function_boundaries(params)
    local addr = params.address
    local maxSearch = params.max_search or 4096
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local is64 = targetIs64Bit()
    
    -- Search backwards for function prologue
    -- 32-bit: push ebp; mov ebp, esp (55 8B EC)
    -- 64-bit: push rbp; mov rbp, rsp (55 48 89 E5) or sub rsp, X patterns
    local funcStart = nil
    local prologueType = nil
    for offset = 0, maxSearch do
        local checkAddr = addr - offset
        local b1 = readBytes(checkAddr, 1, false)
        local b2 = readBytes(checkAddr + 1, 1, false)
        local b3 = readBytes(checkAddr + 2, 1, false)
        local b4 = readBytes(checkAddr + 3, 1, false)
        
        -- 32-bit prologue: push ebp; mov ebp, esp (55 8B EC)
        if b1 == 0x55 and b2 == 0x8B and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x86_standard"
            break
        end
        
        -- 64-bit prologue: push rbp; mov rbp, rsp (55 48 89 E5)
        if is64 and b1 == 0x55 and b2 == 0x48 and b3 == 0x89 and b4 == 0xE5 then
            funcStart = checkAddr
            prologueType = "x64_standard"
            break
        end
        
        -- 64-bit alternative: sub rsp, imm8 (48 83 EC xx) - common in leaf functions
        if is64 and b1 == 0x48 and b2 == 0x83 and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x64_leaf"
            break
        end
    end
    
    -- Search forwards for return instruction
    local funcEnd = nil
    if funcStart then
        for offset = 0, maxSearch do
            local b = readBytes(funcStart + offset, 1, false)
            if b == 0xC3 or b == 0xC2 then
                funcEnd = funcStart + offset
                break
            end
        end
    end
    
    local found = funcStart ~= nil
    
    return {
        success = true,
        found = found,
        query_address = toHex(addr),
        function_start = funcStart and toHex(funcStart) or nil,
        function_end = funcEnd and toHex(funcEnd) or nil,
        function_size = (funcStart and funcEnd) and (funcEnd - funcStart + 1) or nil,
        prologue_type = prologueType,
        arch = is64 and "x64" or "x86",
        note = not found and "No standard function prologue found within search range" or nil
    }
end

local function cmd_analyze_function(params)
    local addr = params.address
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local is64 = targetIs64Bit()
    
    -- Find function start using architecture-aware prologue detection
    local funcStart = nil
    local prologueType = nil
    for offset = 0, 4096 do
        local checkAddr = addr - offset
        local b1 = readBytes(checkAddr, 1, false)
        local b2 = readBytes(checkAddr + 1, 1, false)
        local b3 = readBytes(checkAddr + 2, 1, false)
        local b4 = readBytes(checkAddr + 3, 1, false)
        
        -- 32-bit prologue: push ebp; mov ebp, esp (55 8B EC)
        if b1 == 0x55 and b2 == 0x8B and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x86_standard"
            break
        end
        
        -- 64-bit prologue: push rbp; mov rbp, rsp (55 48 89 E5)
        if is64 and b1 == 0x55 and b2 == 0x48 and b3 == 0x89 and b4 == 0xE5 then
            funcStart = checkAddr
            prologueType = "x64_standard"
            break
        end
        
        -- 64-bit alternative: sub rsp, imm8 (48 83 EC xx)
        if is64 and b1 == 0x48 and b2 == 0x83 and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x64_leaf"
            break
        end
    end
    
    if not funcStart then 
        return { 
            success = false, 
            error = "Could not find function start",
            arch = is64 and "x64" or "x86",
            query_address = toHex(addr)
        } 
    end
    
    -- Analyze calls within function
    local calls = {}
    local funcEnd = nil
    local currentAddr = funcStart
    
    while currentAddr < funcStart + 0x2000 do
        local instSize = getInstructionSize(currentAddr)
        if not instSize or instSize == 0 then break end
        
        local b1 = readBytes(currentAddr, 1, false)
        if b1 == 0xC3 or b1 == 0xC2 then
            funcEnd = currentAddr
            break
        end
        
        -- Detect CALL instructions
        -- E8 xx xx xx xx = relative CALL (most common)
        if b1 == 0xE8 then
            local relOffset = readInteger(currentAddr + 1)
            if relOffset then
                if relOffset > 0x7FFFFFFF then relOffset = relOffset - 0x100000000 end
                table.insert(calls, {
                    call_site = toHex(currentAddr),
                    target = toHex(currentAddr + 5 + relOffset),
                    type = "relative"
                })
            end
        end
        
        -- FF /2 = indirect CALL (CALL r/m32 or CALL r/m64)
        if b1 == 0xFF then
            local b2 = readBytes(currentAddr + 1, 1, false)
            if b2 and (b2 >= 0x10 and b2 <= 0x1F) then  -- ModR/M for /2
                local disasm = disassemble(currentAddr)
                table.insert(calls, {
                    call_site = toHex(currentAddr),
                    instruction = disasm,
                    type = "indirect"
                })
            end
        end
        
        currentAddr = currentAddr + instSize
    end
    
    return {
        success = true,
        function_start = toHex(funcStart),
        function_end = funcEnd and toHex(funcEnd) or nil,
        prologue_type = prologueType,
        arch = is64 and "x64" or "x86",
        call_count = #calls,
        calls = calls
    }
end

-- ============================================================================
-- COMMAND HANDLERS - REFERENCE FINDING
-- ============================================================================

local function cmd_find_references(params)
    local targetAddr = params.address
    local limit = params.limit or 50
    
    targetAddr = resolveAddr(targetAddr)
    if not targetAddr then return { success = false, error = "Invalid address" } end
    
    local is64 = targetIs64Bit()
    local pattern
    
    -- Convert address to AOB pattern (little-endian)
    if is64 and targetAddr > 0xFFFFFFFF then
        -- 64-bit address: 8 bytes little-endian
        local bytes = {}
        local tempAddr = targetAddr
        for i = 1, 8 do
            bytes[i] = tempAddr % 256
            tempAddr = math.floor(tempAddr / 256)
        end
        pattern = string.format("%02X %02X %02X %02X %02X %02X %02X %02X", 
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8])
    else
        -- 32-bit address: 4 bytes little-endian
        local b1 = targetAddr % 256
        local b2 = math.floor(targetAddr / 256) % 256
        local b3 = math.floor(targetAddr / 65536) % 256
        local b4 = math.floor(targetAddr / 16777216) % 256
        pattern = string.format("%02X %02X %02X %02X", b1, b2, b3, b4)
    end
    
    local results = AOBScan(pattern, "+X")
    if not results then return { success = true, target = toHex(targetAddr), count = 0, references = {}, arch = is64 and "x64" or "x86" } end
    
    local refs = {}
    for i = 0, math.min(results.Count - 1, limit - 1) do
        local refAddr = tonumber(results.getString(i), 16)
        local disasm = disassemble(refAddr) or "???"
        table.insert(refs, {
            address = toHex(refAddr),
            instruction = disasm
        })
    end
    results.destroy()
    
    return { success = true, target = toHex(targetAddr), count = #refs, references = refs, arch = is64 and "x64" or "x86" }
end

local function cmd_find_call_references(params)
    local funcAddr = params.address or params.function_address
    local limit = params.limit or 100
    
    funcAddr = resolveAddr(funcAddr)
    if not funcAddr then return { success = false, error = "Invalid function address" } end
    
    local callers = {}
    local results = AOBScan("E8 ?? ?? ?? ??", "+X")
    
    if results then
        for i = 0, results.Count - 1 do
            if #callers >= limit then break end
            
            local callAddr = tonumber(results.getString(i), 16)
            local relOffset = readInteger(callAddr + 1)
            
            if relOffset then
                if relOffset > 0x7FFFFFFF then relOffset = relOffset - 0x100000000 end
                local target = callAddr + 5 + relOffset
                
                if target == funcAddr then
                    table.insert(callers, {
                        caller_address = toHex(callAddr),
                        instruction = disassemble(callAddr) or "???"
                    })
                end
            end
        end
        results.destroy()
    end
    
    return { success = true, function_address = toHex(funcAddr), count = #callers, callers = callers }
end

-- ============================================================================
-- COMMAND HANDLERS - BREAKPOINTS
-- ============================================================================

local function cmd_set_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    local captureRegs = params.capture_registers ~= false
    local captureStackFlag = params.capture_stack or false
    local stackDepth = params.stack_depth or 16
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    bpId = bpId or tostring(addr)
    
    -- Find free hardware slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not serverState.hw_bp_slots[i] then
            slot = i
            break
        end
    end
    
    if not slot then
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }
    end
    
    -- Remove existing breakpoint at this address
    pcall(function() debug_removeBreakpoint(addr) end)
    
    serverState.breakpoint_hits[bpId] = {}
    
    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    debug_setBreakpoint(addr, 1, bptExecute, bpmDebugRegister, function()
        local hitData = {
            id = bpId,
            address = toHex(addr),
            timestamp = os.time(),
            breakpoint_type = "hardware_execute"
        }
        
        if captureRegs then
            hitData.registers = captureRegisters()
        end
        
        if captureStackFlag then
            hitData.stack = captureStack(stackDepth)
        end
        
        table.insert(serverState.breakpoint_hits[bpId], hitData)
        debug_continueFromBreakpoint(co_run)
        return 1
    end)
    
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = { address = addr, slot = slot, type = "execute" }
    return { success = true, id = bpId, address = toHex(addr), slot = slot, method = "hardware_debug_register" }
end

local function cmd_set_data_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    local accessType = params.access_type or "w"  -- r, w, rw
    local size = params.size or 4
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    bpId = bpId or tostring(addr)
    
    -- Find free hardware slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not serverState.hw_bp_slots[i] then
            slot = i
            break
        end
    end
    
    if not slot then
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }
    end
    
    local bpType = bptWrite
    if accessType == "r" then bpType = bptAccess
    elseif accessType == "rw" then bpType = bptAccess end
    
    serverState.breakpoint_hits[bpId] = {}
    
    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    debug_setBreakpoint(addr, size, bpType, bpmDebugRegister, function()
        local arch = getArchInfo()
        local instPtr = arch.instPtr
        local hitData = {
            id = bpId,
            type = "data_" .. accessType,
            address = toHex(addr),
            timestamp = os.time(),
            breakpoint_type = "hardware_data",
            value = arch.is64bit and readQword(addr) or readInteger(addr),
            registers = captureRegisters(),
            instruction = instPtr and disassemble(instPtr) or "???",
            arch = arch.is64bit and "x64" or "x86"
        }
        
        table.insert(serverState.breakpoint_hits[bpId], hitData)
        debug_continueFromBreakpoint(co_run)
        return 1
    end)
    
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = { address = addr, slot = slot, type = "data" }
    
    return { success = true, id = bpId, address = toHex(addr), slot = slot, access_type = accessType, method = "hardware_debug_register" }
end

local function cmd_remove_breakpoint(params)
    local bpId = params.id
    
    if bpId and serverState.breakpoints[bpId] then
        local bp = serverState.breakpoints[bpId]
        pcall(function() debug_removeBreakpoint(bp.address) end)
        
        if bp.slot then
            serverState.hw_bp_slots[bp.slot] = nil
        end
        
        serverState.breakpoints[bpId] = nil
        return { success = true, id = bpId }
    end
    
    return { success = false, error = "Breakpoint not found: " .. tostring(bpId) }
end

local function cmd_get_breakpoint_hits(params)
    local bpId = params.id
    local clear = params.clear ~= false
    
    local hits
    if bpId then
        hits = serverState.breakpoint_hits[bpId] or {}
        if clear then serverState.breakpoint_hits[bpId] = {} end
    else
        -- Get all hits
        hits = {}
        for id, hitsForBp in pairs(serverState.breakpoint_hits) do
            for _, hit in ipairs(hitsForBp) do
                table.insert(hits, hit)
            end
        end
        if clear then serverState.breakpoint_hits = {} end
    end
    
    return { success = true, count = #hits, hits = hits }
end

local function cmd_list_breakpoints(params)
    local list = {}
    for id, bp in pairs(serverState.breakpoints) do
        table.insert(list, {
            id = id,
            address = toHex(bp.address),
            type = bp.type or "execution",
            slot = bp.slot
        })
    end
    return { success = true, count = #list, breakpoints = list }
end

local function cmd_clear_all_breakpoints(params)
    local count = 0
    for id, bp in pairs(serverState.breakpoints) do
        pcall(function() debug_removeBreakpoint(bp.address) end)
        count = count + 1
    end
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    return { success = true, removed = count }
end

-- ============================================================================
-- COMMAND HANDLERS - LUA EVALUATION
-- ============================================================================

-- Build the `mcp.*` helper namespace exposed to evaluate_lua code. CE's
-- raw readBytes API has two ergonomic landmines that the AI keeps hitting:
--   readBytes(addr, n)         returns n VALUES (not a table)
--   readBytes(addr, n, true)   returns a 1-indexed table (not 0-indexed)
-- The mcp.* helpers wrap CE primitives so the AI gets predictable shapes
-- and never has to remember the table-vs-multivalue or 0-vs-1 indexing
-- quirk. They also auto-translate guest addresses through the active
-- guestRegions mapping, matching the rest of the bridge.
local function _buildMcpHelpers()
    local m = {}

    -- Coerce any input (number, "0x...", "decimal", "module+0x...") to a
    -- numeric host address. Returns nil if it can't be resolved.
    function m.toAddr(s)
        if type(s) == "number" then return s end
        if type(s) ~= "string" then return nil end
        local hex = s:match("^0[xX]([0-9A-Fa-f]+)$")
        if hex then return tonumber(hex, 16) end
        return tonumber(s) or getAddressSafe(s)
    end

    -- Translate a guest address (e.g. PS2 0x00100000, GameCube 0x80003100)
    -- through the active guestRegions mapping. Returns the host address.
    function m.translateGuest(addr)
        return translateGuest(m.toAddr(addr))
    end

    -- Read a single byte. Returns a number 0-255, or nil on failure.
    function m.readByte(addr)
        addr = m.toAddr(addr); if not addr then return nil end
        return readBytes(translateGuest(addr), 1, false)
    end

    -- Read N bytes as a 1-indexed table. ALWAYS returns a table (empty on
    -- failure) so callers can iterate with ipairs without worrying about nil.
    function m.readBytesArray(addr, count)
        addr = m.toAddr(addr); if not addr then return {} end
        return readBytes(translateGuest(addr), count or 1, true) or {}
    end

    -- Read N bytes and render as printable ASCII (non-printables -> '.').
    -- Useful for quickly identifying what's at an address.
    function m.readAscii(addr, count)
        addr = m.toAddr(addr); if not addr then return nil end
        local bytes = readBytes(translateGuest(addr), count or 64, true)
        if not bytes then return nil end
        local out = {}
        for i = 1, #bytes do
            local b = bytes[i]
            out[i] = (b > 31 and b < 127) and string.char(b) or "."
        end
        return table.concat(out)
    end

    -- Read N bytes as a space-separated hex string ("DE AD BE EF").
    function m.readHex(addr, count)
        addr = m.toAddr(addr); if not addr then return nil end
        local bytes = readBytes(translateGuest(addr), count or 16, true)
        if not bytes then return nil end
        local parts = {}
        for i = 1, #bytes do parts[i] = string.format("%02X", bytes[i]) end
        return table.concat(parts, " ")
    end

    -- xxd-style mixed dump: address  hex  ascii, one row of 16 bytes per line.
    -- This is what the AI was trying (and failing) to write by hand in the
    -- chat - now they can call mcp.dump(addr, count).
    function m.dump(addr, count)
        addr = m.toAddr(addr)
        if not addr then return "(invalid address)" end
        local hostAddr = translateGuest(addr)
        count = count or 64
        local bytes = readBytes(hostAddr, count, true)
        if not bytes then return "(read failed at " .. toHex(hostAddr) .. ")" end
        local lines = {}
        local cols = 16
        local rows = math.ceil(#bytes / cols)
        for row = 0, rows - 1 do
            local hex_parts, ascii_parts = {}, {}
            for col = 0, cols - 1 do
                local i = row * cols + col + 1
                if i <= #bytes then
                    local b = bytes[i]
                    hex_parts[col + 1] = string.format("%02X", b)
                    ascii_parts[col + 1] = (b > 31 and b < 127) and string.char(b) or "."
                else
                    hex_parts[col + 1] = "  "
                    ascii_parts[col + 1] = " "
                end
            end
            lines[row + 1] = string.format("%s  %s  %s",
                toHex(hostAddr + row * cols),
                table.concat(hex_parts, " "),
                table.concat(ascii_parts))
        end
        return table.concat(lines, "\n")
    end

    -- Typed read. vtype accepts type-name strings OR numeric byte counts:
    --   "byte"  | 1
    --   "word"  | 2
    --   "dword" | 4   (default)
    --   "qword" | 8
    --   "float" | "double" | "string"  (string forms only)
    -- v11.8: numeric aliases added because AI assistants reliably pass
    -- byte counts (mcp.read(addr, 4)) and were silently getting nil back.
    function m.read(addr, vtype)
        addr = m.toAddr(addr); if not addr then return nil end
        addr = translateGuest(addr)
        if type(vtype) == "number" then
            if vtype == 1 then vtype = "byte"
            elseif vtype == 2 then vtype = "word"
            elseif vtype == 4 then vtype = "dword"
            elseif vtype == 8 then vtype = "qword"
            else vtype = "dword" end
        end
        vtype = tostring(vtype or "dword"):lower()
        if vtype == "byte"   then return readBytes(addr, 1, false)
        elseif vtype == "word"   then return readSmallInteger(addr)
        elseif vtype == "dword"  then return readInteger(addr)
        elseif vtype == "qword"  then return readQword(addr)
        elseif vtype == "float"  then return readFloat(addr)
        elseif vtype == "double" then return readDouble(addr)
        elseif vtype == "string" then return readString(addr, 64) end
        return nil
    end

    -- Typed write. Returns true on success, false on failure.
    -- v11.8: vtype accepts numeric byte counts same as m.read.
    function m.write(addr, value, vtype)
        addr = m.toAddr(addr); if not addr then return false end
        addr = translateGuest(addr)
        if type(vtype) == "number" then
            if vtype == 1 then vtype = "byte"
            elseif vtype == 2 then vtype = "word"
            elseif vtype == 4 then vtype = "dword"
            elseif vtype == 8 then vtype = "qword"
            else vtype = "dword" end
        end
        vtype = tostring(vtype or "dword"):lower()
        local ok = false
        if vtype == "byte"   then ok = pcall(writeBytes, addr, {value})
        elseif vtype == "word"   then ok = pcall(writeSmallInteger, addr, value)
        elseif vtype == "dword"  then ok = pcall(writeInteger, addr, value)
        elseif vtype == "qword"  then ok = pcall(writeQword, addr, value)
        elseif vtype == "float"  then ok = pcall(writeFloat, addr, value)
        elseif vtype == "double" then ok = pcall(writeDouble, addr, value)
        elseif vtype == "string" then ok = pcall(writeString, addr, value) end
        return ok
    end

    -- Format a number as 0x-prefixed hex.
    function m.hex(num) return toHex(_num(num) or 0) end

    -- Read a list of addresses at once. Returns { addr -> value } map.
    function m.readMany(addrs, vtype)
        local out = {}
        for _, a in ipairs(addrs or {}) do
            out[tostring(a)] = m.read(a, vtype)
        end
        return out
    end

    return m
end

-- One-time install: expose mcp.* as a global so evaluate_lua code can use it.
local function _ensureMcpHelpers()
    if not _G.mcp then _G.mcp = _buildMcpHelpers() end
end

local function cmd_evaluate_lua(params)
    local code = params.code
    if not code then return { success = false, error = "No code provided" } end

    _ensureMcpHelpers()

    local fn, err = loadstring(code)
    if not fn then return { success = false, error = "Compile error: " .. tostring(err) } end

    local ok, result = pcall(fn)
    if not ok then return { success = false, error = "Runtime error: " .. tostring(result) } end

    return { success = true, result = tostring(result) }
end

-- ============================================================================
-- COMMAND HANDLERS - MEMORY REGIONS
-- ============================================================================

local function cmd_get_memory_regions(params)
    local regions = {}
    local maxRegions = params.max or 100
    local pageSize = 0x1000  -- 4KB pages
    
    -- Sample memory at common base addresses to find valid regions
    local sampleAddresses = {
        0x00010000, 0x00400000, 0x10000000, 0x20000000, 0x30000000,
        0x40000000, 0x50000000, 0x60000000, 0x70000000
    }
    
    -- Also add addresses from modules we found via AOB scan
    local mzScan = AOBScan("4D 5A 90 00 03 00")
    if mzScan and mzScan.Count > 0 then
        for i = 0, math.min(mzScan.Count - 1, 20) do
            local addr = tonumber(mzScan.getString(i), 16)
            if addr then table.insert(sampleAddresses, addr) end
        end
        mzScan.destroy()
    end
    
    -- Check each sample address for memory protection
    for _, baseAddr in ipairs(sampleAddresses) do
        if #regions >= maxRegions then break end
        
        local ok, prot = pcall(getMemoryProtection, baseAddr)
        if ok and prot then
            -- Found a valid memory page
            local protStr = ""
            if prot.r then protStr = protStr .. "R" end
            if prot.w then protStr = protStr .. "W" end
            if prot.x then protStr = protStr .. "X" end
            
            -- Try to find region size by scanning forward
            local regionSize = pageSize
            for offset = pageSize, 0x1000000, pageSize do
                local ok2, prot2 = pcall(getMemoryProtection, baseAddr + offset)
                if not ok2 or not prot2 or 
                   prot2.r ~= prot.r or prot2.w ~= prot.w or prot2.x ~= prot.x then
                    break
                end
                regionSize = offset + pageSize
            end
            
            table.insert(regions, {
                base = toHex(baseAddr),
                size = regionSize,
                protection = protStr,
                readable = prot.r or false,
                writable = prot.w or false,
                executable = prot.x or false
            })
        end
    end
    
    return { success = true, count = #regions, regions = regions }
end

-- ============================================================================
-- COMMAND HANDLERS - UTILITY
-- ============================================================================

local function cmd_ping(params)
    return {
        success = true,
        version = VERSION,
        timestamp = os.time(),
        process_id = getOpenedProcessID() or 0,
        message = "CE MCP Bridge v" .. VERSION .. " alive"
    }
end

local function cmd_search_string(params)
    local searchStr = params.string or params.pattern
    local wide = params.wide or false
    local limit = params.limit or 100
    
    if not searchStr then return { success = false, error = "No search string" } end
    
    -- Convert string to AOB pattern
    local pattern = ""
    for i = 1, #searchStr do
        if i > 1 then pattern = pattern .. " " end
        pattern = pattern .. string.format("%02X", searchStr:byte(i))
        if wide then pattern = pattern .. " 00" end
    end
    
    local results = AOBScan(pattern)
    if not results then return { success = true, count = 0, addresses = {} } end
    
    local addresses = {}
    for i = 0, math.min(results.Count - 1, limit - 1) do
        local addr = tonumber(results.getString(i), 16)
        local preview = readString(addr, 50, wide) or ""
        table.insert(addresses, {
            address = "0x" .. results.getString(i),
            preview = preview
        })
    end
    results.destroy()
    
    return { success = true, count = #addresses, addresses = addresses }
end

-- ============================================================================
-- COMMAND HANDLERS - HIGH-LEVEL ANALYSIS TOOLS
-- ============================================================================

-- Dissect Structure: Uses CE's Structure.autoGuess to map memory into typed fields
local function cmd_dissect_structure(params)
    local address = params.address
    local size = params.size or 256
    
    address = resolveAddr(address)
    if not address then return { success = false, error = "Invalid address" } end
    
    -- Create a temporary structure and use autoGuess
    local ok, struct = pcall(createStructure, "MCP_TempStruct")
    if not ok or not struct then
        return { success = false, error = "Failed to create structure" }
    end
    
    -- Use the Structure class autoGuess method
    pcall(function() struct:autoGuess(address, 0, size) end)
    
    local elements = {}
    local count = struct.Count or 0
    
    for i = 0, count - 1 do
        local elem = struct.Element[i]
        if elem then
            local val = nil
            -- Try to get current value
            pcall(function() val = elem:getValue(address) end)
            
            table.insert(elements, {
                offset = elem.Offset,
                hex_offset = string.format("+0x%X", elem.Offset),
                name = elem.Name or "",
                vartype = elem.Vartype,
                bytesize = elem.Bytesize,
                current_value = val
            })
        end
    end
    
    -- Cleanup - don't add to global list
    pcall(function() struct:removeFromGlobalStructureList() end)
    
    return {
        success = true,
        base_address = toHex(address),
        size_analyzed = size,
        element_count = #elements,
        elements = elements
    }
end

-- Get Thread List: Returns all threads in the attached process
local function cmd_get_thread_list(params)
    local list = createStringlist()
    getThreadlist(list)
    
    local threads = {}
    for i = 0, list.Count - 1 do
        local idHex = list[i]
        table.insert(threads, {
            id_hex = idHex,
            id_int = tonumber(idHex, 16)
        })
    end
    
    list.destroy()
    
    return {
        success = true,
        count = #threads,
        threads = threads
    }
end

-- AutoAssemble: Execute an AutoAssembler script
local function cmd_auto_assemble(params)
    local script = params.script or params.code
    local disable = params.disable or false
    
    if not script then return { success = false, error = "No script provided" } end
    
    local success, disableInfo = autoAssemble(script)
    
    if success then
        local result = {
            success = true,
            executed = true
        }
        -- If disable info is returned, include symbol addresses
        if disableInfo and disableInfo.symbols then
            result.symbols = {}
            for name, addr in pairs(disableInfo.symbols) do
                result.symbols[name] = toHex(addr)
            end
        end
        return result
    else
        return {
            success = false,
            error = "AutoAssemble failed: " .. tostring(disableInfo)
        }
    end
end

-- Enum Memory Regions Full: Uses CE's native enumMemoryRegions for accurate data
local function cmd_enum_memory_regions_full(params)
    local maxRegions    = params.max or 500
    local minSize       = params.min_size or 0
    local maxSize       = params.max_size or math.huge
    local protectFilter = params.protect_filter   -- "RW", "X", "RX", "RWX", etc.
    local sortBySize    = params.sort_by_size or false
    local committedOnly = params.committed_only ~= false  -- default true
    
    local ok, regions = pcall(enumMemoryRegions)
    if not ok or not regions then
        return { success = false, error = "enumMemoryRegions failed" }
    end
    
    -- Decode protection bitfield to short string
    local function protToStr(prot)
        if prot == 0x10 then return "X"
        elseif prot == 0x20 then return "RX"
        elseif prot == 0x40 then return "RWX"
        elseif prot == 0x80 then return "WX"
        elseif prot == 0x02 then return "R"
        elseif prot == 0x04 then return "RW"
        elseif prot == 0x08 then return "W"
        else return string.format("0x%X", prot) end
    end
    
    local result = {}
    local total_skipped = 0
    for i, r in ipairs(regions) do
        local prot = r.Protect or 0
        local state = r.State or 0
        local size = r.RegionSize or 0
        local protStr = protToStr(prot)
        local isCommitted = state == 0x1000
        
        -- Apply filters
        local include = true
        if committedOnly and not isCommitted then include = false end
        if include and size < minSize then include = false end
        if include and size > maxSize then include = false end
        if include and protectFilter and protStr ~= protectFilter then include = false end
        
        if include then
            table.insert(result, {
                base = toHex(r.BaseAddress or 0),
                base_int = r.BaseAddress or 0,
                allocation_base = toHex(r.AllocationBase or 0),
                size = size,
                size_mb = math.floor(size / 1048576 * 100) / 100,  -- to 2 decimals
                state = state,
                protect = prot,
                protect_string = protStr,
                type = r.Type or 0,
                is_committed = isCommitted,
                is_reserved = state == 0x2000,
                is_free = state == 0x10000
            })
        else
            total_skipped = total_skipped + 1
        end
    end
    
    if sortBySize then
        table.sort(result, function(a, b) return a.size > b.size end)
    end
    
    -- Cap to maxRegions AFTER filtering and sorting (so largest survives)
    local truncated = false
    if #result > maxRegions then
        truncated = true
        local capped = {}
        for i = 1, maxRegions do capped[i] = result[i] end
        result = capped
    end
    
    return {
        success = true,
        count = #result,
        total_unfiltered = #regions,
        skipped_by_filter = total_skipped,
        truncated = truncated,
        regions = result
    }
end

-- Read Pointer Chain: Follow a chain of pointers to resolve dynamic addresses
local function cmd_read_pointer_chain(params)
    local base = params.base
    local offsets = params.offsets or {}
    
    base = resolveAddr(base)
    if not base then return { success = false, error = "Invalid base address" } end
    
    local currentAddr = base
    local chain = { { step = 0, address = toHex(currentAddr), description = "base" } }
    
    for i, offset in ipairs(offsets) do
        -- Read pointer at current address
        local ptr = readPointer(currentAddr)
        if not ptr then
            return {
                success = false,
                error = "Failed to read pointer at step " .. i,
                partial_chain = chain,
                failed_at_address = toHex(currentAddr)
            }
        end
        
        -- Apply offset
        currentAddr = ptr + offset
        table.insert(chain, {
            step = i,
            address = toHex(currentAddr),
            offset = offset,
            hex_offset = string.format("+0x%X", offset),
            pointer_value = toHex(ptr)
        })
    end
    
    -- Try to read a value at the final address (using readPointer for 32/64-bit compatibility)
    local finalValue = nil
    pcall(function()
        finalValue = readPointer(currentAddr)
    end)
    
    return {
        success = true,
        base = toHex(base),
        offsets = offsets,
        final_address = toHex(currentAddr),
        final_value = finalValue,
        chain = chain
    }
end

-- Get RTTI Class Name: Uses C++ RTTI to identify object types
local function cmd_get_rtti_classname(params)
    local address = params.address
    
    address = resolveAddr(address)
    if not address then return { success = false, error = "Invalid address" } end
    
    local className = getRTTIClassName(address)
    
    if className then
        return {
            success = true,
            address = toHex(address),
            class_name = className,
            found = true
        }
    else
        return {
            success = true,
            address = toHex(address),
            class_name = nil,
            found = false,
            note = "No RTTI information found at this address"
        }
    end
end

-- Get Address Info: Converts raw address to symbolic name (module+offset)
local function cmd_get_address_info(params)
    local address = params.address
    local includeModules = params.include_modules ~= false  -- default true
    local includeSymbols = params.include_symbols ~= false  -- default true
    local includeSections = params.include_sections or false  -- default false
    
    address = resolveAddr(address)
    if not address then return { success = false, error = "Invalid address" } end
    
    local symbolicName = getNameFromAddress(address, includeModules, includeSymbols, includeSections)
    
    -- inModule() may fail or return nil in anti-cheat environments, so we check symbolicName too
    local isInModule = false
    local okInMod, inModResult = pcall(inModule, address)
    if okInMod and inModResult then
        isInModule = true
    elseif symbolicName and symbolicName:match("%+") then
        -- symbolicName contains "+" like "L2.exe+1000" which means it's in a module
        isInModule = true
    end
    
    -- Ensure symbolic_name has 0x prefix if it's just a hex address
    if symbolicName and symbolicName:match("^%x+$") then
        symbolicName = "0x" .. symbolicName
    end
    
    return {
        success = true,
        address = toHex(address),
        symbolic_name = symbolicName or toHex(address),
        is_in_module = isInModule,
        options_used = {
            include_modules = includeModules,
            include_symbols = includeSymbols,
            include_sections = includeSections
        }
    }
end

-- Checksum Memory: Calculate MD5 hash of a memory region
local function cmd_checksum_memory(params)
    local address = params.address
    local size = params.size or 256
    
    address = resolveAddr(address)
    if not address then return { success = false, error = "Invalid address" } end
    
    local ok, hash = pcall(md5memory, address, size)
    
    if ok and hash then
        return {
            success = true,
            address = toHex(address),
            size = size,
            md5_hash = hash
        }
    else
        return {
            success = false,
            address = toHex(address),
            size = size,
            error = "Failed to calculate MD5: " .. tostring(hash)
        }
    end
end

-- Generate Signature: Creates a unique AOB pattern for an address (for re-acquisition)
local function cmd_generate_signature(params)
    local addr = params.address
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- getUniqueAOB(address) returns: AOBString, Offset
    -- It scans for a unique byte pattern that identifies this location
    local ok, signature, offset = pcall(getUniqueAOB, addr)
    
    if not ok then
        return {
            success = false,
            address = toHex(addr),
            error = "getUniqueAOB failed: " .. tostring(signature)
        }
    end
    
    if not signature or signature == "" then
        return {
            success = false,
            address = toHex(addr),
            error = "Could not generate unique signature - pattern not unique enough"
        }
    end
    
    -- Calculate signature length (count bytes, wildcards count as 1)
    local byteCount = 0
    for _ in signature:gmatch("%S+") do
        byteCount = byteCount + 1
    end
    
    return {
        success = true,
        address = toHex(addr),
        signature = signature,
        offset_from_start = offset or 0,
        byte_count = byteCount,
        usage_hint = string.format("aob_scan('%s') then add offset %d to reach target", signature, offset or 0)
    }
end

-- ============================================================================
-- DBVM HYPERVISOR TOOLS (Safe Dynamic Tracing - Ring -1)
-- ============================================================================
-- These tools use DBVM (Debuggable Virtual Machine) for hypervisor-level tracing.
-- They are 100% invisible to anti-cheat: no game memory modification, no debug registers.
-- DBVM works at the hypervisor level, beneath the OS, making it undetectable.
-- ============================================================================

-- Get Physical Address: Converts virtual address to physical RAM address
-- Required for DBVM operations which work on physical memory
local function cmd_get_physical_address(params)
    local addr = params.address
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- Check if DBK (kernel driver) is available
    local ok, phys = pcall(dbk_getPhysicalAddress, addr)
    
    if not ok then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "DBK driver not loaded. Run dbk_initialize() first or load it via CE settings."
        }
    end
    
    if not phys or phys == 0 then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Could not resolve physical address. Page may not be present in RAM."
        }
    end
    
    return {
        success = true,
        virtual_address = toHex(addr),
        physical_address = toHex(phys),
        physical_int = phys
    }
end

-- Start DBVM Watch: Hypervisor-level memory access monitoring
-- This is the "Find what writes/reads" equivalent but at Ring -1 (invisible to games)
-- Start DBVM Watch: Hypervisor-level memory access monitoring
-- This is the "Find what writes/reads" equivalent but at Ring -1 (invisible to games)
local function cmd_start_dbvm_watch(params)
    local addr = params.address
    local mode = params.mode or "w"  -- "w" = write, "r" = read, "rw" = both, "x" = execute
    local maxEntries = params.max_entries or 1000  -- Internal buffer size
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- 0. Safety Checks
    if not dbk_initialized() then
        return { success = false, error = "DBK driver not loaded. Go to Settings -> Debugger -> Kernelmode" }
    end
    
    if not dbvm_initialized() then
        -- Try to initialize if possible
        pcall(dbvm_initialize)
        if not dbvm_initialized() then
            return { success = false, error = "DBVM not running. Go to Settings -> Debugger -> Use DBVM" }
        end
    end

    -- 1. Get Physical Address (DBVM works on physical RAM)
    local ok, phys = pcall(dbk_getPhysicalAddress, addr)
    if not ok or not phys or phys == 0 then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Could not resolve physical address. Page might be paged out or invalid."
        }
    end
    
    -- 2. Check if already watching this address
    local watchKey = toHex(addr)
    if serverState.active_watches[watchKey] then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Already watching this address. Call stop_dbvm_watch first."
        }
    end
    
    -- 3. Configure watch options
    -- Bit 0: Log multiple times (1 = yes)
    -- Bit 1: Ignore size / log whole page (2)
    -- Bit 2: Log FPU registers (4)
    -- Bit 3: Log Stack (8)
    local options = 1 + 2 + 8  -- Multiple logging + whole page + stack context
    
    -- 4. Start the appropriate watch based on mode
    local watch_id
    local okWatch, result
    
    log(string.format("Starting DBVM watch on Phys: 0x%X (Mode: %s)", phys, mode))

    if mode == "x" then
        if not dbvm_watch_executes then
            return { success = false, error = "dbvm_watch_executes function missing from CE Lua engine" }
        end
        okWatch, result = pcall(dbvm_watch_executes, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    elseif mode == "r" or mode == "rw" then
        okWatch, result = pcall(dbvm_watch_reads, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    else  -- default: write
        okWatch, result = pcall(dbvm_watch_writes, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    end
    
    if not okWatch then
        return {
            success = false,
            virtual_address = toHex(addr),
            physical_address = toHex(phys),
            error = "DBVM watch CRASHED/FAILED: " .. tostring(result)
        }
    end
    
    if not watch_id then
        return {
            success = false,
            virtual_address = toHex(addr),
            physical_address = toHex(phys),
            error = "DBVM watch returned nil (check CE console for details)"
        }
    end
    
    -- 5. Store watch for later retrieval
    serverState.active_watches[watchKey] = {
        id = watch_id,
        physical = phys,
        mode = mode,
        start_time = os.time()
    }
    
    return {
        success = true,
        status = "monitoring",
        virtual_address = toHex(addr),
        physical_address = toHex(phys),
        watch_id = watch_id,
        mode = mode,
        note = "Call poll_dbvm_watch to get logs without stopping, or stop_dbvm_watch to end"
    }
end

-- Poll DBVM Watch: Retrieve logged accesses WITHOUT stopping the watch
-- This is CRITICAL for continuous packet monitoring - logs can be polled repeatedly
local function cmd_poll_dbvm_watch(params)
    local addr = params.address
    local clear = params.clear or true  -- Default to clearing logs after poll
    local max_results = params.max_results or 1000
    
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local watchKey = toHex(addr)
    local watchInfo = serverState.active_watches[watchKey]
    
    if not watchInfo then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "No active watch found for this address. Call start_dbvm_watch first."
        }
    end
    
    local watch_id = watchInfo.id
    local results = {}
    
    -- Retrieve log entries (DBVM accumulates these automatically)
    local okLog, log = pcall(dbvm_watch_retrievelog, watch_id)
    
    if okLog and log then
        local count = math.min(#log, max_results)
        for i = 1, count do
            local entry = log[i]
            -- For packet capture, we need the stack pointer to read [ESP+4]
            -- ESP/RSP contains the stack pointer at time of execution
            local hitData = {
                hit_number = i,
                -- 32-bit game uses ESP, 64-bit uses RSP
                ESP = entry.RSP and (entry.RSP % 0x100000000) or nil,  -- Lower 32 bits for 32-bit game
                RSP = entry.RSP and toHex(entry.RSP) or nil,
                EIP = entry.RIP and (entry.RIP % 0x100000000) or nil,  -- Lower 32 bits
                RIP = entry.RIP and toHex(entry.RIP) or nil,
                -- Include key registers that might hold packet buffer
                EAX = entry.RAX and (entry.RAX % 0x100000000) or nil,
                ECX = entry.RCX and (entry.RCX % 0x100000000) or nil,
                EDX = entry.RDX and (entry.RDX % 0x100000000) or nil,
                EBX = entry.RBX and (entry.RBX % 0x100000000) or nil,
                ESI = entry.RSI and (entry.RSI % 0x100000000) or nil,
                EDI = entry.RDI and (entry.RDI % 0x100000000) or nil,
            }
            table.insert(results, hitData)
        end
    end
    
    local uptime = os.time() - (watchInfo.start_time or os.time())
    
    return {
        success = true,
        status = "active",
        virtual_address = toHex(addr),
        physical_address = toHex(watchInfo.physical),
        mode = watchInfo.mode,
        uptime_seconds = uptime,
        hit_count = #results,
        hits = results,
        note = "Watch still active. Call again to get more logs, or stop_dbvm_watch to end."
    }
end

-- Stop DBVM Watch: Retrieve logged accesses and disable monitoring
-- Returns all instructions that touched the monitored memory
local function cmd_stop_dbvm_watch(params)
    local addr = params.address
    addr = resolveAddr(addr)
    if not addr then return { success = false, error = "Invalid address" } end
    
    local watchKey = toHex(addr)
    local watchInfo = serverState.active_watches[watchKey]
    
    if not watchInfo then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "No active watch found for this address"
        }
    end
    
    local watch_id = watchInfo.id
    local results = {}
    
    -- 1. Retrieve the log of all memory accesses
    local okLog, log = pcall(dbvm_watch_retrievelog, watch_id)
    
    if okLog and log then
        -- Parse each log entry (contains CPU context at time of access)
        for i, entry in ipairs(log) do
            local hitData = {
                hit_number = i,
                instruction_address = entry.RIP and toHex(entry.RIP) or nil,
                instruction = entry.RIP and (pcall(disassemble, entry.RIP) and disassemble(entry.RIP) or "???") or "???",
                -- CPU registers at time of access
                registers = {
                    RAX = entry.RAX and toHex(entry.RAX) or nil,
                    RBX = entry.RBX and toHex(entry.RBX) or nil,
                    RCX = entry.RCX and toHex(entry.RCX) or nil,
                    RDX = entry.RDX and toHex(entry.RDX) or nil,
                    RSI = entry.RSI and toHex(entry.RSI) or nil,
                    RDI = entry.RDI and toHex(entry.RDI) or nil,
                    RBP = entry.RBP and toHex(entry.RBP) or nil,
                    RSP = entry.RSP and toHex(entry.RSP) or nil,
                    RIP = entry.RIP and toHex(entry.RIP) or nil
                }
            }
            table.insert(results, hitData)
        end
    end
    
    -- 2. Disable the watch
    pcall(dbvm_watch_disable, watch_id)
    
    -- 3. Clean up
    serverState.active_watches[watchKey] = nil
    
    local duration = os.time() - (watchInfo.start_time or os.time())
    
    return {
        success = true,
        virtual_address = toHex(addr),
        physical_address = toHex(watchInfo.physical),
        mode = watchInfo.mode,
        hit_count = #results,
        duration_seconds = duration,
        hits = results,
        note = #results > 0 and "Found instructions that accessed the memory" or "No accesses detected during monitoring"
    }
end

-- ============================================================================
-- EMULATOR / GUEST-ADDRESS COMMANDS (multi-region, v11.6+)
-- ============================================================================
-- guestRegions is a list of { guestStart, guestEnd, hostBase, kind } records.
-- A read on guest address X is translated to host(R) + (X - guest(R)) for
-- the first region R that contains X. Multi-region is needed for any
-- emulator with split RAM (Wii MEM1+MEM2, GBA EWRAM+IWRAM, GameCube+ARAM, etc).

-- Set the host address(es) that the guest range maps to. Single-region call
-- replaces all existing regions; use add_guest_region to layer additional
-- regions. Once set, every read/write handler that accepts an address
-- auto-translates guest addrs (in [start, end)) to host before calling CE.
local function cmd_set_guest_base(params)
    local host = _num(params.address or params.host)
    if not host then
        local s = params.address or params.host
        if type(s) == "string" then host = getAddressSafe(s) end
    end
    if type(host) ~= "number" then
        return { success = false, error = "address must be a number or hex string" }
    end

    local kind   = params.kind or "custom"
    local rStart = _num(params.range_start) or 0x80000000
    local rEnd   = _num(params.range_end) or 0xA0000000
    local size   = _num(params.size)
    if size and not params.range_end then rEnd = rStart + size end

    -- Single-region setup (replaces any existing regions for backward compat
    -- with the v11.5 single-region behavior).
    serverState.guestRegions = {
        { guestStart = rStart, guestEnd = rEnd, hostBase = host, kind = kind }
    }
    serverState.guestKind = kind

    return {
        success = true,
        host_base = toHex(host),
        kind = kind,
        range_start = toHex(rStart),
        range_end = toHex(rEnd),
        size = rEnd - rStart,
        regions = 1,
        note = "Future addrs in [" .. toHex(rStart) .. ", " .. toHex(rEnd) .. ") will be translated to host."
    }
end

-- Add an additional guest region without replacing existing ones. Use this
-- to set up multi-RAM emulators by hand (e.g. Wii MEM1 + MEM2 manually).
local function cmd_add_guest_region(params)
    local host = _num(params.address or params.host)
    if not host then return { success = false, error = "host address required" } end
    local rStart = _num(params.range_start)
    local rEnd   = _num(params.range_end)
    local size   = _num(params.size)
    if not rStart then return { success = false, error = "range_start required" } end
    if not rEnd and not size then return { success = false, error = "range_end or size required" } end
    if not rEnd then rEnd = rStart + size end

    serverState.guestRegions = serverState.guestRegions or {}
    table.insert(serverState.guestRegions, {
        guestStart = rStart, guestEnd = rEnd, hostBase = host,
        kind = params.kind or "custom"
    })

    return {
        success = true,
        regions = #serverState.guestRegions,
        added = {
            host_base = toHex(host),
            range_start = toHex(rStart),
            range_end = toHex(rEnd),
            kind = params.kind or "custom"
        }
    }
end

local function cmd_get_guest_base(params)
    local regions = serverState.guestRegions or {}
    if #regions == 0 then
        return { success = true, set = false, regions = 0 }
    end

    local out = {}
    for _, r in ipairs(regions) do
        table.insert(out, {
            kind = r.kind,
            host_base = toHex(r.hostBase),
            range_start = toHex(r.guestStart),
            range_end = toHex(r.guestEnd),
            size = r.guestEnd - r.guestStart,
            size_mb = math.floor((r.guestEnd - r.guestStart) / 1048576 * 100) / 100
        })
    end

    -- Backward-compatible single-region fields (use first region)
    local first = regions[1]
    return {
        success = true,
        set = true,
        kind = serverState.guestKind or first.kind,
        regions = #regions,
        all_regions = out,
        host_base = toHex(first.hostBase),
        range_start = toHex(first.guestStart),
        range_end = toHex(first.guestEnd),
        size = first.guestEnd - first.guestStart
    }
end

local function cmd_clear_guest_base(params)
    serverState.guestRegions = {}
    serverState.guestKind = nil
    return { success = true, message = "All guest regions cleared. Subsequent addrs are not translated." }
end

-- Translate addresses in either direction without doing I/O.
-- direction = "guest_to_host" | "host_to_guest" (default infers from address range)
local function cmd_translate_address(params)
    local addr = _num(params.address)
    if not addr and type(params.address) == "string" then
        addr = getAddressSafe(params.address)
    end
    if type(addr) ~= "number" then
        return { success = false, error = "Invalid address" }
    end

    local regions = serverState.guestRegions or {}
    if #regions == 0 then
        return { success = false, error = "No guest regions set - call set_guest_base or auto_detect_emulator first" }
    end

    local dir = params.direction
    if not dir then
        -- Infer from which range the address falls in
        for _, r in ipairs(regions) do
            if addr >= r.guestStart and addr < r.guestEnd then dir = "guest_to_host"; break end
        end
        if not dir then
            for _, r in ipairs(regions) do
                local size = r.guestEnd - r.guestStart
                if addr >= r.hostBase and addr < r.hostBase + size then dir = "host_to_guest"; break end
            end
        end
        if not dir then
            return { success = false, error = "Address is in neither guest nor host guest-mapped range" }
        end
    end

    if dir == "guest_to_host" then
        local h = translateGuest(addr)
        return { success = true, direction = dir, input = toHex(addr), output = toHex(h) }
    elseif dir == "host_to_guest" then
        local g = translateHost(addr)
        if not g then return { success = false, error = "Host address not within mapped guest range" } end
        return { success = true, direction = dir, input = toHex(addr), output = toHex(g) }
    else
        return { success = false, error = "direction must be guest_to_host or host_to_guest" }
    end
end

-- Auto-detect a likely guest RAM region by scanning enumMemoryRegions for
-- contiguous RW(X) regions of the expected size(s). Supported emulators:
--   gamecube   GameCube on Dolphin       MEM1: 24 MiB at 0x80000000
--   wii        Wii on Dolphin            MEM1: 24 MiB at 0x80000000 + MEM2: 64 MiB at 0x90000000
--   pcsx2/ps2  PS2 on PCSX2              EE_RAM: 32 MiB at 0x00100000 (cached) - usually mirrored at 0x20000000/0x30000000
--   ps1       PS1 on DuckStation/etc     RAM: 2 MiB at 0x80000000
--   gba       GBA on mGBA/VBA-M          EWRAM: 256 KiB at 0x02000000 + IWRAM: 32 KiB at 0x03000000
--   nds       DS on melonDS/DeSmuME      Main: 4 MiB at 0x02000000
--   n64       N64 on Project64/etc       RDRAM: 8 MiB at 0x80000000
--   snes      SNES on bsnes/Snes9x       WRAM: 128 KiB at 0x7E0000
local function cmd_auto_detect_emulator(params)
    local kind = params.kind or "auto"
    local sizeTolerance = params.size_tolerance or 0.05

    -- Each preset is a list of regions to find; each region maps a guest VA
    -- to a host RW region of the expected size.
    local presets = {
        gamecube = {{ guestStart = 0x80000000, expectedSize = 0x01800000, name = "MEM1" }},
        wii      = {
            { guestStart = 0x80000000, expectedSize = 0x01800000, name = "MEM1" },
            { guestStart = 0x90000000, expectedSize = 0x04000000, name = "MEM2" }
        },
        pcsx2    = {{ guestStart = 0x00100000, expectedSize = 0x02000000, name = "EE_RAM" }},
        ps2      = {{ guestStart = 0x00100000, expectedSize = 0x02000000, name = "EE_RAM" }},
        ps1      = {{ guestStart = 0x80000000, expectedSize = 0x00200000, name = "RAM" }},
        gba      = {
            { guestStart = 0x02000000, expectedSize = 0x00040000, name = "EWRAM" },
            { guestStart = 0x03000000, expectedSize = 0x00008000, name = "IWRAM" }
        },
        nds      = {{ guestStart = 0x02000000, expectedSize = 0x00400000, name = "Main_RAM" }},
        n64      = {{ guestStart = 0x80000000, expectedSize = 0x00800000, name = "RDRAM" }},
        snes     = {{ guestStart = 0x007E0000, expectedSize = 0x00020000, name = "WRAM" }}
    }

    local pres = presets[kind]
    if not pres then
        if params.expected_size then
            pres = {{
                guestStart   = _num(params.range_start) or 0x80000000,
                expectedSize = _num(params.expected_size),
                name         = "custom"
            }}
        else
            return {
                success = false,
                error = "unknown kind '" .. tostring(kind) .. "' and no expected_size",
                supported = "gamecube|wii|pcsx2|ps2|ps1|gba|nds|n64|snes|custom",
                hint = "For custom: pass {kind='custom', expected_size=<bytes>, range_start=<guest VA>}"
            }
        end
    end

    local ok, regions = pcall(enumMemoryRegions)
    if not ok or not regions then
        return { success = false, error = "enumMemoryRegions failed" }
    end

    local newRegions = {}
    local notFound = {}
    local allCandidates = {}

    for _, target in ipairs(pres) do
        local minOK = target.expectedSize * (1 - sizeTolerance)
        local maxOK = target.expectedSize * (1 + sizeTolerance)
        local found = nil
        local skipBases = {}
        for _, r in ipairs(newRegions) do skipBases[r.hostBase] = true end

        for _, r in ipairs(regions) do
            local size = r.RegionSize or 0
            local prot = r.Protect or 0
            local state = r.State or 0
            local isRW = (prot == 0x04 or prot == 0x40)  -- RW or RWX
            local isCommitted = state == 0x1000
            if isRW and isCommitted and size >= minOK and size <= maxOK and not skipBases[r.BaseAddress] then
                found = r
                table.insert(allCandidates, { base = r.BaseAddress, size = size, target = target.name })
                break
            end
        end

        if found then
            table.insert(newRegions, {
                guestStart = target.guestStart,
                guestEnd   = target.guestStart + found.RegionSize,
                hostBase   = found.BaseAddress,
                kind       = kind .. "/" .. target.name
            })
        else
            table.insert(notFound, target.name)
        end
    end

    if #newRegions == 0 then
        return {
            success = false,
            error = "No matching RW regions found",
            kind = kind,
            not_found = notFound,
            hint = "Try enum_memory_regions_full {protect_filter='RW'} to inspect candidates manually."
        }
    end

    -- Atomic install
    serverState.guestRegions = newRegions
    serverState.guestKind = kind

    local outRegions = {}
    for _, r in ipairs(newRegions) do
        table.insert(outRegions, {
            kind = r.kind,
            guest_start = toHex(r.guestStart),
            guest_end = toHex(r.guestEnd),
            host_base = toHex(r.hostBase),
            size_mb = math.floor((r.guestEnd - r.guestStart) / 1048576 * 100) / 100
        })
    end

    return {
        success = (#notFound == 0),
        kind = kind,
        regions_found = #newRegions,
        regions = outRegions,
        not_found = (#notFound > 0) and notFound or nil,
        candidates = allCandidates,
        note = (#notFound > 0)
            and ("Some regions not detected (" .. table.concat(notFound, ", ") .. "). Emulator may not have a game loaded yet, or RAM is allocated differently. You can still use the regions found.")
            or "All expected regions detected and translation enabled."
    }
end

-- Get info about a single memory region containing the given address
local function cmd_get_region_info(params)
    local addr = resolveAddr(params.address)
    if not addr then return { success = false, error = "Invalid address" } end

    local ok, regions = pcall(enumMemoryRegions)
    if not ok or not regions then
        return { success = false, error = "enumMemoryRegions failed" }
    end

    for _, r in ipairs(regions) do
        local base = r.BaseAddress or 0
        local size = r.RegionSize or 0
        if addr >= base and addr < base + size then
            local prot = r.Protect or 0
            local state = r.State or 0
            local protStr =
                (prot == 0x10) and "X" or
                (prot == 0x20) and "RX" or
                (prot == 0x40) and "RWX" or
                (prot == 0x80) and "WX" or
                (prot == 0x02) and "R" or
                (prot == 0x04) and "RW" or
                (prot == 0x08) and "W" or
                string.format("0x%X", prot)
            return {
                success = true,
                base = toHex(base),
                size = size,
                size_mb = math.floor(size / 1048576 * 100) / 100,
                offset_in_region = addr - base,
                protect = prot,
                protect_string = protStr,
                state = state,
                is_committed = state == 0x1000,
                allocation_base = toHex(r.AllocationBase or 0),
                guest_address = (function()
                    local g = translateHost(addr)
                    return g and toHex(g) or nil
                end)()
            }
        end
    end
    return { success = false, error = "Address not in any committed region" }
end

-- ============================================================================
-- PROCESS MANAGEMENT (attach / list / detach)
-- ============================================================================
-- Without these, the AI can't tell CE which process to attach to. For
-- emulator workflows in particular ("attach to PCSX2", "switch from
-- Dolphin to Citra"), the AI needs to enumerate and attach.

-- List running processes. Optional filter narrows by case-insensitive
-- substring match on the process name.
local function cmd_list_processes(params)
    local filter = params.filter
    local limit = params.limit or 200
    local processes = {}

    local list = createStringlist()
    local ok, err = pcall(getProcessList, list)
    if not ok then
        list.destroy()
        return { success = false, error = "getProcessList failed: " .. tostring(err) }
    end

    local total = list.Count
    -- CE's getProcessList format is "PID-name" (PID in hex), e.g. "00001234-notepad.exe"
    for i = 0, total - 1 do
        if #processes >= limit then break end
        local entry = list[i]
        -- Try hex-PID-dash-name first, then decimal-PID-dash-name
        local pid_s, name = entry:match("^(%x+)%-(.+)$")
        if not pid_s then pid_s, name = entry:match("^(%d+)%-(.+)$") end
        if pid_s and name then
            -- Prefer hex parse since CE uses hex by default
            local pid = tonumber(pid_s, 16) or tonumber(pid_s)
            local include = true
            if filter and type(filter) == "string" then
                include = name:lower():find(filter:lower(), 1, true) ~= nil
            end
            if include then
                table.insert(processes, { pid = pid, name = name, raw = entry })
            end
        end
    end
    list.destroy()

    return { success = true, count = #processes, total = total, filter = filter, processes = processes }
end

-- Attach Cheat Engine to a running process. Accepts either a PID (int) or
-- a process name (string, fuzzy match). Auto-clears guest regions because
-- those are tied to the previous process's memory layout.
local function cmd_attach_process(params)
    local target = params.pid or params.name or params.process
    if not target then return { success = false, error = "pid or name required" } end

    -- Numeric coercion: accept "1234" or "0x4D2" as PID
    if type(target) == "string" then
        local n = _num(target)
        if n then target = n end
    end

    local ok, err = pcall(openProcess, target)
    if not ok then
        return { success = false, error = "openProcess failed: " .. tostring(err), target = tostring(target) }
    end

    -- Refresh symbol info for new process
    pcall(reinitializeSymbolhandler)

    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "Failed to attach (process may have exited or be inaccessible)", target = tostring(target) }
    end

    -- Clear stale guest regions - they pointed at the old process's memory
    serverState.guestRegions = {}
    serverState.guestKind = nil

    return {
        success = true,
        process_id = pid,
        process_name = process or "?",
        target = tostring(target),
        note = "Guest regions cleared - call auto_detect_emulator if attached to an emulator."
    }
end

-- ============================================================================
-- NOP INSTRUCTION HELPER (architecture-aware code patching)
-- ============================================================================
-- Patches one or more instructions to NOPs. Returns the original bytes so the
-- caller can write them back to undo. Critical for emulator code patching:
--   x86  : 0x90, variable per-instruction size from getInstructionSize
--   ppc  : 0x60000000 big-endian (4 bytes per instruction) - Dolphin
--   mips : 0x00000000 (4 bytes per instruction) - PCSX2/PS1/N64
local function cmd_nop_instruction(params)
    local addr = resolveAddr(params.address)
    if not addr then return { success = false, error = "Invalid address" } end
    local count = params.count or 1
    local arch = params.arch or "x86"  -- x86 | ppc | mips

    local total_size = 0
    local original = {}
    local nopBytes

    if arch == "ppc" then
        -- PPC NOP = ori r0, r0, 0 = 0x60000000, big-endian: 60 00 00 00
        nopBytes = { 0x60, 0x00, 0x00, 0x00 }
        total_size = count * 4
    elseif arch == "mips" then
        -- MIPS NOP = sll r0, r0, 0 = 0x00000000 (always zero in any endianness)
        nopBytes = { 0x00, 0x00, 0x00, 0x00 }
        total_size = count * 4
    else
        -- x86: variable instruction sizes; walk forward
        nopBytes = { 0x90 }
        local cur = addr
        for i = 1, count do
            local sz = getInstructionSize(cur)
            if not sz or sz == 0 then break end
            local b = readBytes(cur, sz, true) or {}
            local hex = {}
            for _, byte in ipairs(b) do table.insert(hex, string.format("%02X", byte)) end
            table.insert(original, { address = toHex(cur), size = sz, bytes = table.concat(hex, " ") })
            total_size = total_size + sz
            cur = cur + sz
        end
        if total_size == 0 then return { success = false, error = "Could not determine instruction sizes" } end
    end

    -- Capture original bytes for ppc/mips (single block)
    if arch == "ppc" or arch == "mips" then
        local b = readBytes(addr, total_size, true) or {}
        local hex = {}
        for _, byte in ipairs(b) do table.insert(hex, string.format("%02X", byte)) end
        table.insert(original, { address = toHex(addr), size = total_size, bytes = table.concat(hex, " ") })
    end

    -- Build the NOP byte stream (repeating pattern)
    local stream = {}
    local nopLen = #nopBytes
    for i = 0, total_size - 1 do
        stream[i + 1] = nopBytes[(i % nopLen) + 1]
    end

    local ok, err = pcall(writeBytes, addr, stream)
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end

    return {
        success = true,
        address = toHex(addr),
        arch = arch,
        bytes_nopped = total_size,
        instructions_nopped = (arch == "x86") and #original or count,
        original = original,
        note = "Restore original bytes via write_memory using the 'original' field."
    }
end

-- ============================================================================
-- MIPS (R3000/R4300/R5900) disassembler
-- ============================================================================
-- CE's built-in disassemble() emits x86. PS1 (R3000), PS2 (R5900), and N64
-- (R4300i) game code is MIPS little-endian, fixed 4-byte instructions.
-- This decoder works on raw bytes via readBytes() so it operates equally
-- well whether the address is a host VA inside the emulator process or a
-- guest VA (e.g. 0x80100000) routed through guestRegions. Coverage focuses
-- on instructions actually emitted by game compilers (GCC/MIPSPro) - rare
-- ones decode as raw .word.
local function disasmMIPS(word, addr)
    -- Bit-field extractor (MIPS bit numbering: bit 0 = LSB of 32-bit word)
    local function f(hi, lo)
        local width = hi - lo + 1
        return math.floor(word / 2^lo) % 2^width
    end
    local function sext(v, width)
        local half = 2^(width - 1)
        if v >= half then return v - 2^width end
        return v
    end
    local function himm(v)
        if v < 0 then return "-0x" .. string.format("%X", -v) end
        return "0x" .. string.format("%X", v)
    end

    -- All-zero instruction = NOP (sll r0, r0, 0)
    if word == 0 then return "nop" end

    local op  = f(31, 26)
    local rs  = f(25, 21)
    local rt  = f(20, 16)
    local rd  = f(15, 11)
    local sa  = f(10, 6)
    local fn  = f(5, 0)
    local imm = sext(f(15, 0), 16)
    local uimm = f(15, 0)

    -- R-type (op = 0): decoded by 'fn' field
    if op == 0 then
        if fn == 0  then return string.format("sll r%d, r%d, %d", rd, rt, sa) end
        if fn == 2  then return string.format("srl r%d, r%d, %d", rd, rt, sa) end
        if fn == 3  then return string.format("sra r%d, r%d, %d", rd, rt, sa) end
        if fn == 4  then return string.format("sllv r%d, r%d, r%d", rd, rt, rs) end
        if fn == 6  then return string.format("srlv r%d, r%d, r%d", rd, rt, rs) end
        if fn == 7  then return string.format("srav r%d, r%d, r%d", rd, rt, rs) end
        if fn == 8  then return string.format("jr r%d", rs) end
        if fn == 9  then
            if rd == 31 then return string.format("jalr r%d", rs) end
            return string.format("jalr r%d, r%d", rd, rs)
        end
        if fn == 12 then return "syscall" end
        if fn == 13 then return "break" end
        if fn == 15 then return "sync" end
        if fn == 16 then return string.format("mfhi r%d", rd) end
        if fn == 17 then return string.format("mthi r%d", rs) end
        if fn == 18 then return string.format("mflo r%d", rd) end
        if fn == 19 then return string.format("mtlo r%d", rs) end
        if fn == 24 then return string.format("mult r%d, r%d", rs, rt) end
        if fn == 25 then return string.format("multu r%d, r%d", rs, rt) end
        if fn == 26 then return string.format("div r%d, r%d", rs, rt) end
        if fn == 27 then return string.format("divu r%d, r%d", rs, rt) end
        if fn == 32 then return string.format("add r%d, r%d, r%d", rd, rs, rt) end
        if fn == 33 then
            -- addu rd, rs, r0 = move rd, rs (very common idiom)
            if rt == 0 then return string.format("move r%d, r%d", rd, rs) end
            if rs == 0 then return string.format("move r%d, r%d", rd, rt) end
            return string.format("addu r%d, r%d, r%d", rd, rs, rt)
        end
        if fn == 34 then return string.format("sub r%d, r%d, r%d", rd, rs, rt) end
        if fn == 35 then return string.format("subu r%d, r%d, r%d", rd, rs, rt) end
        if fn == 36 then return string.format("and r%d, r%d, r%d", rd, rs, rt) end
        if fn == 37 then
            -- or rd, rs, r0 = move rd, rs (common in MIPS-I/II)
            if rt == 0 then return string.format("move r%d, r%d", rd, rs) end
            if rs == 0 then return string.format("move r%d, r%d", rd, rt) end
            return string.format("or r%d, r%d, r%d", rd, rs, rt)
        end
        if fn == 38 then return string.format("xor r%d, r%d, r%d", rd, rs, rt) end
        if fn == 39 then return string.format("nor r%d, r%d, r%d", rd, rs, rt) end
        if fn == 42 then return string.format("slt r%d, r%d, r%d", rd, rs, rt) end
        if fn == 43 then return string.format("sltu r%d, r%d, r%d", rd, rs, rt) end
        -- PS2 R5900 64-bit ops
        if fn == 44 then return string.format("dadd r%d, r%d, r%d", rd, rs, rt) end
        if fn == 45 then return string.format("daddu r%d, r%d, r%d", rd, rs, rt) end
        if fn == 46 then return string.format("dsub r%d, r%d, r%d", rd, rs, rt) end
        if fn == 47 then return string.format("dsubu r%d, r%d, r%d", rd, rs, rt) end
        if fn == 56 then return string.format("dsll r%d, r%d, %d", rd, rt, sa) end
        if fn == 58 then return string.format("dsrl r%d, r%d, %d", rd, rt, sa) end
        if fn == 59 then return string.format("dsra r%d, r%d, %d", rd, rt, sa) end
        if fn == 60 then return string.format("dsll32 r%d, r%d, %d", rd, rt, sa) end
        if fn == 62 then return string.format("dsrl32 r%d, r%d, %d", rd, rt, sa) end
        if fn == 63 then return string.format("dsra32 r%d, r%d, %d", rd, rt, sa) end
        return string.format(".word 0x%08X (R-type fn=%d)", word, fn)
    end

    -- REGIMM (op = 1)
    if op == 1 then
        local target = addr + 4 + imm * 4
        if rt == 0  then return string.format("bltz r%d, 0x%X", rs, target) end
        if rt == 1  then return string.format("bgez r%d, 0x%X", rs, target) end
        if rt == 2  then return string.format("bltzl r%d, 0x%X", rs, target) end
        if rt == 3  then return string.format("bgezl r%d, 0x%X", rs, target) end
        if rt == 16 then return string.format("bltzal r%d, 0x%X", rs, target) end
        if rt == 17 then return string.format("bgezal r%d, 0x%X", rs, target) end
        return string.format(".word 0x%08X (REGIMM rt=%d)", word, rt)
    end

    -- J / JAL: target = (PC[31:28] << 28) | (target26 << 2)
    if op == 2 or op == 3 then
        local tgt = f(25, 0) * 4
        local pcUpper = math.floor((addr + 4) / 0x10000000) * 0x10000000
        local target = pcUpper + tgt
        return string.format("%s 0x%X", op == 2 and "j" or "jal", target)
    end

    -- Branches with rs/rt
    local btarget = addr + 4 + imm * 4
    if op == 4 then
        if rs == 0 and rt == 0 then return string.format("b 0x%X", btarget) end
        if rt == 0 then return string.format("beqz r%d, 0x%X", rs, btarget) end
        return string.format("beq r%d, r%d, 0x%X", rs, rt, btarget)
    end
    if op == 5 then
        if rt == 0 then return string.format("bnez r%d, 0x%X", rs, btarget) end
        return string.format("bne r%d, r%d, 0x%X", rs, rt, btarget)
    end
    if op == 6  then return string.format("blez r%d, 0x%X", rs, btarget) end
    if op == 7  then return string.format("bgtz r%d, 0x%X", rs, btarget) end
    if op == 20 then return string.format("beql r%d, r%d, 0x%X", rs, rt, btarget) end
    if op == 21 then return string.format("bnel r%d, r%d, 0x%X", rs, rt, btarget) end
    if op == 22 then return string.format("blezl r%d, 0x%X", rs, btarget) end
    if op == 23 then return string.format("bgtzl r%d, 0x%X", rs, btarget) end

    -- Immediate arithmetic / logical
    if op == 8  then return string.format("addi r%d, r%d, %s", rt, rs, himm(imm)) end
    if op == 9  then
        if rs == 0 then return string.format("li r%d, %s", rt, himm(imm)) end
        return string.format("addiu r%d, r%d, %s", rt, rs, himm(imm))
    end
    if op == 10 then return string.format("slti r%d, r%d, %s", rt, rs, himm(imm)) end
    if op == 11 then return string.format("sltiu r%d, r%d, %s", rt, rs, himm(imm)) end
    if op == 12 then return string.format("andi r%d, r%d, 0x%X", rt, rs, uimm) end
    if op == 13 then return string.format("ori r%d, r%d, 0x%X", rt, rs, uimm) end
    if op == 14 then return string.format("xori r%d, r%d, 0x%X", rt, rs, uimm) end
    if op == 15 then return string.format("lui r%d, 0x%X", rt, uimm) end

    -- COP0/1/2 - extremely complex, decode just the most common ops
    if op == 16 or op == 17 or op == 18 then
        local copn = op - 16
        if rs == 0 then return string.format("mfc%d r%d, $%d", copn, rt, rd) end
        if rs == 4 then return string.format("mtc%d r%d, $%d", copn, rt, rd) end
        if rs == 1 then return string.format("dmfc%d r%d, $%d", copn, rt, rd) end
        if rs == 5 then return string.format("dmtc%d r%d, $%d", copn, rt, rd) end
        return string.format(".word 0x%08X (COP%d)", word, copn)
    end

    -- PS2 R5900 MMI (op = 28) - skip detailed decode, useful instructions are rare in game logic
    if op == 28 then return string.format(".word 0x%08X (MMI)", word) end

    -- Loads
    local loads = { [32]="lb", [33]="lh", [34]="lwl", [35]="lw", [36]="lbu", [37]="lhu", [38]="lwr",
                    [55]="ld", [49]="lwc1", [53]="ldc1" }
    if loads[op] then
        return string.format("%s r%d, %s(r%d)", loads[op], rt, himm(imm), rs)
    end
    -- Stores
    local stores = { [40]="sb", [41]="sh", [42]="swl", [43]="sw", [46]="swr",
                     [63]="sd", [57]="swc1", [61]="sdc1" }
    if stores[op] then
        return string.format("%s r%d, %s(r%d)", stores[op], rt, himm(imm), rs)
    end

    return string.format(".word 0x%08X", word)
end

-- disassemble_mips {address, count, endian?}
-- Reads count*4 bytes starting at address, decodes each little-endian
-- 4-byte word as a MIPS instruction. Pass endian="big" for N64 (BE MIPS)
-- versus PS1/PS2 (LE MIPS, default). address goes through resolveAddr().
local function cmd_disassemble_mips(params)
    local count = math.min(math.max(params.count or 16, 1), 256)
    local endian = params.endian or "little"

    local hostAddr = resolveAddr(params.address)
    if not hostAddr then return { success = false, error = "Invalid address" } end

    local total = count * 4
    local bytes = readBytes(hostAddr, total, true)
    if not bytes or #bytes < 4 then
        return { success = false, error = "Failed to read at " .. toHex(hostAddr) }
    end

    -- Prefer reporting addresses in guest space when guest mapping is active.
    local startGuest = translateHost(hostAddr)
    local startDisp = startGuest or hostAddr

    local instructions = {}
    local readable = math.floor(#bytes / 4)
    for i = 1, math.min(count, readable) do
        local off = (i - 1) * 4
        local b1, b2, b3, b4 = bytes[off+1], bytes[off+2], bytes[off+3], bytes[off+4]
        if not b4 then break end

        local word
        if endian == "big" then
            word = b1 * 0x1000000 + b2 * 0x10000 + b3 * 0x100 + b4
        else
            word = b4 * 0x1000000 + b3 * 0x10000 + b2 * 0x100 + b1
        end
        local dispAddr = startDisp + off

        local mnem = disasmMIPS(word, dispAddr)

        table.insert(instructions, {
            address      = toHex(dispAddr),
            host_address = startGuest and toHex(hostAddr + off) or nil,
            offset       = off,
            size         = 4,
            bytes        = string.format("%02X %02X %02X %02X", b1, b2, b3, b4),
            word         = string.format("0x%08X", word),
            instruction  = mnem
        })
    end

    return {
        success       = true,
        arch          = "mips",
        endian        = endian,
        start_address = toHex(startDisp),
        count         = #instructions,
        instructions  = instructions
    }
end

-- ============================================================================
-- COMMAND HANDLERS - ADDRESS LIST / CHEAT TABLE (v11.7+)
-- ============================================================================
-- Tools for managing Cheat Engine's saved-addresses pane (the table on the
-- right side of the CE main window). Each entry there is a MemoryRecord
-- exposed via CE's getAddressList() Lua API. These commands let the AI list,
-- read, write, add, remove, and freeze entries without having to escape
-- Lua manually inside evaluate_lua.

-- Cached vt* constants with hard-coded fallback values. CE exposes these as
-- globals; the fallbacks let the bridge boot in stripped Lua environments.
local _vt_byte           = vtByte or 0
local _vt_word           = vtWord or 1
local _vt_dword          = vtDword or 2
local _vt_qword          = vtQword or 3
local _vt_single         = vtSingle or 4
local _vt_double         = vtDouble or 5
local _vt_string         = vtString or 6
local _vt_unicode_string = vtUnicodeString or 7
local _vt_byte_array     = vtByteArray or 8
local _vt_binary         = vtBinary or 9
local _vt_auto_assembler = vtAutoAssembler or 11
local _vt_pointer        = vtPointer or 12
local _vt_custom         = vtCustom or 13
local _vt_grouped        = vtGrouped or 14

-- Map type-name string to vt* numeric constant.
local function _stringToVt(s)
    s = string.lower(tostring(s or "dword"))
    if s == "byte"   then return _vt_byte
    elseif s == "word" or s == "2bytes" then return _vt_word
    elseif s == "dword" or s == "4bytes" then return _vt_dword
    elseif s == "qword" or s == "8bytes" then return _vt_qword
    elseif s == "float" or s == "single" then return _vt_single
    elseif s == "double" then return _vt_double
    elseif s == "string" then return _vt_string
    elseif s == "unicode_string" or s == "wstring" then return _vt_unicode_string
    elseif s == "byte_array" or s == "aob" or s == "array_of_byte" then return _vt_byte_array
    elseif s == "binary" then return _vt_binary
    elseif s == "auto_assembler" then return _vt_auto_assembler
    elseif s == "pointer" then return _vt_pointer
    elseif s == "custom" then return _vt_custom
    elseif s == "grouped" then return _vt_grouped
    end
    return _vt_dword
end

-- Map vt* numeric constant back to type-name string.
local function _vtToString(t)
    if t == _vt_byte then return "byte"
    elseif t == _vt_word then return "word"
    elseif t == _vt_dword then return "dword"
    elseif t == _vt_qword then return "qword"
    elseif t == _vt_single then return "float"
    elseif t == _vt_double then return "double"
    elseif t == _vt_string then return "string"
    elseif t == _vt_unicode_string then return "unicode_string"
    elseif t == _vt_byte_array then return "byte_array"
    elseif t == _vt_binary then return "binary"
    elseif t == _vt_auto_assembler then return "auto_assembler"
    elseif t == _vt_pointer then return "pointer"
    elseif t == _vt_custom then return "custom"
    elseif t == _vt_grouped then return "grouped"
    end
    return "unknown_" .. tostring(t)
end

-- Resolve a memory record from {id|index|description}. Returns rec, err.
local function _findMemRec(params)
    local al = getAddressList()
    if not al then return nil, "Address list unavailable (no process attached?)" end

    if params.id ~= nil then
        local id = _num(params.id)
        if not id then return nil, "invalid id" end
        local rec = al.getMemoryRecordByID(id)
        if not rec then return nil, "no entry with id=" .. tostring(id) end
        return rec
    end

    if params.index ~= nil then
        local idx = _num(params.index)
        if not idx then return nil, "invalid index" end
        local count = al.Count or al.getCount()
        if idx < 0 or idx >= count then
            return nil, string.format("index %d out of range [0..%d)", idx, count)
        end
        local rec = al.getMemoryRecord(idx)
        if not rec then return nil, "no entry at index=" .. tostring(idx) end
        return rec
    end

    if params.description ~= nil then
        local desc = tostring(params.description)
        local rec = al.getMemoryRecordByDescription(desc)
        if not rec then return nil, "no entry with description=\"" .. desc .. "\"" end
        return rec
    end

    return nil, "must specify one of: id, index, description"
end

-- Build a JSON-safe summary of a MemoryRecord. Wraps every CE property read
-- in pcall because some properties throw on certain record types (e.g. script
-- records have no Value/CurrentAddress).
local function _describeMemRec(rec, includeResolved)
    local out = {}
    pcall(function() out.id = rec.ID end)
    pcall(function() out.description = rec.Description end)
    pcall(function() out.address_text = rec.Address end)
    pcall(function() out.type = _vtToString(rec.Type) end)
    pcall(function() out.active = rec.Active end)
    pcall(function() out.is_group_header = rec.IsGroupHeader end)
    pcall(function() out.is_address_group_header = rec.IsAddressGroupHeader end)
    pcall(function() out.show_as_hex = rec.ShowAsHex end)
    pcall(function() out.show_as_signed = rec.ShowAsSigned end)
    pcall(function() out.allow_decrease = rec.AllowDecrease end)
    pcall(function() out.allow_increase = rec.AllowIncrease end)

    -- Pointer offset chain
    local oc = 0
    pcall(function() oc = rec.OffsetCount or 0 end)
    if oc > 0 then
        local offsets = {}
        for i = 0, oc - 1 do
            local v
            pcall(function() v = rec.Offset[i] end)
            if v ~= nil then offsets[#offsets + 1] = toHex(v) end
        end
        out.offsets = offsets
        out.is_pointer = true
    end

    if includeResolved then
        local addr
        pcall(function() addr = rec.CurrentAddress end)
        if addr and addr ~= 0 then
            out.current_address = toHex(addr)
            local guest = translateHost(addr)
            if guest then out.guest_address = toHex(guest) end
        end
        local val
        pcall(function() val = rec.Value end)
        if val ~= nil then out.value = val end
    end

    return out
end

-- List address-list entries, optionally filtered by description substring.
local function cmd_list_address_list(params)
    local al = getAddressList()
    if not al then return { success = false, error = "Address list unavailable" } end

    local limit = _num(params.limit) or 200
    local includeResolved = params.include_resolved ~= false  -- default true
    local filter = params.filter and string.lower(tostring(params.filter)) or nil

    local count = al.Count or al.getCount()
    local entries = {}
    local matched = 0

    for i = 0, count - 1 do
        local rec = al.getMemoryRecord(i)
        if rec then
            local desc = ""
            pcall(function() desc = rec.Description or "" end)
            local includeIt = true
            if filter and not string.lower(desc):find(filter, 1, true) then
                includeIt = false
            end
            if includeIt then
                local info = _describeMemRec(rec, includeResolved)
                info.index = i
                entries[#entries + 1] = info
                matched = matched + 1
                if matched >= limit then break end
            end
        end
    end

    return {
        success = true,
        total_in_list = count,
        returned = #entries,
        entries = entries
    }
end

-- Get a single entry by id / index / description.
local function cmd_get_address_entry(params)
    local rec, err = _findMemRec(params)
    if not rec then return { success = false, error = err } end
    local out = _describeMemRec(rec, true)
    out.success = true
    return out
end

-- Read the current value of an entry, using the entry's configured type.
local function cmd_read_address_entry(params)
    local rec, err = _findMemRec(params)
    if not rec then return { success = false, error = err } end

    local val
    local ok = pcall(function() val = rec.Value end)
    if not ok then return { success = false, error = "Failed to read Value" } end

    local addr
    pcall(function() addr = rec.CurrentAddress end)

    return {
        success = true,
        id = rec.ID,
        description = rec.Description,
        value = val,
        type = _vtToString(rec.Type),
        current_address = addr and toHex(addr) or nil
    }
end

-- Write a value to an entry. CE's Value setter accepts a STRING and parses it
-- according to the entry's Type (e.g. "100" for an int, "1.5" for a float,
-- "DE AD BE EF" for a byte array). Pass numbers in their native form; we
-- tostring() them before handing off to CE.
local function cmd_write_address_entry(params)
    local rec, err = _findMemRec(params)
    if not rec then return { success = false, error = err } end
    if params.value == nil then return { success = false, error = "value required" } end

    local ok = pcall(function() rec.Value = tostring(params.value) end)
    if not ok then return { success = false, error = "Failed to write Value" } end

    local newVal
    pcall(function() newVal = rec.Value end)

    return {
        success = true,
        id = rec.ID,
        description = rec.Description,
        value = newVal
    }
end

-- Create a new entry. Required: description, address. Optional: type,
-- offsets (pointer chain - innermost first; Offset[0] is the final offset
-- applied after the last dereference), value (initial write), active (freeze),
-- show_as_hex, show_as_signed, allow_decrease/increase.
-- If a guest mapping is active and `address` is a numeric/hex guest VA, the
-- stored Address gets translated to host so CE can resolve it correctly. To
-- keep guest readability, the description is annotated with the original.
local function cmd_add_address_entry(params)
    if not params.description then return { success = false, error = "description required" } end
    if not params.address then return { success = false, error = "address required" } end

    local al = getAddressList()
    if not al then return { success = false, error = "Address list unavailable" } end

    local rec
    local ok = pcall(function() rec = al.createMemoryRecord() end)
    if not ok or not rec then return { success = false, error = "createMemoryRecord failed" } end

    pcall(function() rec.Description = tostring(params.description) end)

    -- Normalize address. Accept number, "0x...", or symbolic ("game.exe+N").
    local addrStr
    local addrIn = params.address
    if type(addrIn) == "number" then
        addrStr = toHex(addrIn)
    elseif type(addrIn) == "string" then
        addrStr = addrIn
        -- If this looks like a pure hex VA in an active guest region,
        -- translate to host so CE resolves it correctly.
        local hex = addrIn:match("^0[xX]([0-9A-Fa-f]+)$")
        if hex then
            local n = tonumber(hex, 16)
            if n then
                local h = translateGuest(n)
                if h ~= n then
                    addrStr = toHex(h)
                    pcall(function()
                        rec.Description = tostring(params.description) .. " [guest:" .. toHex(n) .. "]"
                    end)
                end
            end
        end
    else
        return { success = false, error = "address must be number or string" }
    end

    pcall(function() rec.Address = addrStr end)

    -- Type
    if params.type ~= nil then
        pcall(function() rec.Type = _stringToVt(params.type) end)
    end

    -- Pointer offsets (1-indexed input array -> 0-indexed CE Offset[])
    if type(params.offsets) == "table" and #params.offsets > 0 then
        pcall(function() rec.OffsetCount = #params.offsets end)
        for i = 1, #params.offsets do
            local off = _num(params.offsets[i]) or 0
            pcall(function() rec.Offset[i - 1] = off end)
        end
    end

    if params.show_as_hex ~= nil    then pcall(function() rec.ShowAsHex    = not not params.show_as_hex end)    end
    if params.show_as_signed ~= nil then pcall(function() rec.ShowAsSigned = not not params.show_as_signed end) end
    if params.allow_decrease ~= nil then pcall(function() rec.AllowDecrease = not not params.allow_decrease end) end
    if params.allow_increase ~= nil then pcall(function() rec.AllowIncrease = not not params.allow_increase end) end

    -- Initial value write (best-effort; only meaningful for value types)
    if params.value ~= nil then
        pcall(function() rec.Value = tostring(params.value) end)
    end

    -- Activate (freeze on) if asked
    if params.active or params.freeze then
        pcall(function() rec.Active = true end)
    end

    return {
        success = true,
        id = rec.ID,
        description = rec.Description,
        address = rec.Address,
        type = _vtToString(rec.Type),
        active = rec.Active or false
    }
end

-- Remove an entry from the address list. CE exposes the deletion API a few
-- different ways across versions - we try each in order.
local function cmd_remove_address_entry(params)
    local rec, err = _findMemRec(params)
    if not rec then return { success = false, error = err } end

    local id, desc
    pcall(function() id = rec.ID end)
    pcall(function() desc = rec.Description end)

    local al = getAddressList()
    local ok = false

    -- Newer CE: AddressList:delete(memrec)
    pcall(function() al.delete(rec); ok = true end)
    -- Some versions: MemoryRecord:delete()
    if not ok then pcall(function() rec.delete(); ok = true end) end
    -- Fallback: MemoryRecord:destroy()
    if not ok then pcall(function() rec.destroy(); ok = true end) end

    if not ok then
        return { success = false, error = "no working delete API found (tried al.delete, rec.delete, rec.destroy)" }
    end

    return { success = true, id = id, description = desc }
end

-- Toggle the Active state of an entry (freeze on/off for value entries,
-- enable/disable for script entries). Optional allow_decrease/allow_increase
-- control freeze direction.
local function cmd_set_address_entry_active(params)
    local rec, err = _findMemRec(params)
    if not rec then return { success = false, error = err } end

    local active = params.active
    if active == nil then active = params.freeze end
    if active == nil then return { success = false, error = "active (or freeze) required" } end

    local ok = pcall(function() rec.Active = not not active end)
    if not ok then return { success = false, error = "Failed to set Active" } end

    if params.allow_decrease ~= nil then pcall(function() rec.AllowDecrease = not not params.allow_decrease end) end
    if params.allow_increase ~= nil then pcall(function() rec.AllowIncrease = not not params.allow_increase end) end

    local current
    pcall(function() current = rec.Active end)

    return {
        success = true,
        id = rec.ID,
        description = rec.Description,
        active = current
    }
end

-- ============================================================================

local commandHandlers = {
    -- Process & Modules
    get_process_info = cmd_get_process_info,
    enum_modules = cmd_enum_modules,
    get_symbol_address = cmd_get_symbol_address,
    
    -- Memory Read
    read_memory = cmd_read_memory,
    read_bytes = cmd_read_memory,  -- Alias
    read_integer = cmd_read_integer,
    read_string = cmd_read_string,
    read_pointer = cmd_read_pointer,
    
    -- Pattern Scanning
    aob_scan = cmd_aob_scan,
    pattern_scan = cmd_aob_scan,  -- Alias
    scan_all = cmd_scan_all,
    next_scan = cmd_next_scan,
    write_integer = cmd_write_integer,
    write_memory = cmd_write_memory,
    write_string = cmd_write_string,
    get_scan_results = cmd_get_scan_results,
    search_string = cmd_search_string,
    
    -- Disassembly & Analysis
    disassemble = cmd_disassemble,
    disassemble_ppc = cmd_disassemble_ppc,  -- PowerPC (GameCube/Wii via Dolphin)
    get_instruction_info = cmd_get_instruction_info,
    find_function_boundaries = cmd_find_function_boundaries,
    analyze_function = cmd_analyze_function,
    
    -- Reference Finding
    find_references = cmd_find_references,
    find_call_references = cmd_find_call_references,
    
    -- Breakpoints
    set_breakpoint = cmd_set_breakpoint,
    set_execution_breakpoint = cmd_set_breakpoint,  -- Alias
    set_data_breakpoint = cmd_set_data_breakpoint,
    set_write_breakpoint = cmd_set_data_breakpoint,  -- Alias
    remove_breakpoint = cmd_remove_breakpoint,
    get_breakpoint_hits = cmd_get_breakpoint_hits,
    list_breakpoints = cmd_list_breakpoints,
    clear_all_breakpoints = cmd_clear_all_breakpoints,
    
    -- Memory Regions
    get_memory_regions = cmd_get_memory_regions,
    enum_memory_regions_full = cmd_enum_memory_regions_full,  -- More accurate, uses native API
    
    -- Lua Evaluation
    evaluate_lua = cmd_evaluate_lua,
    
    -- High-Level Analysis Tools
    dissect_structure = cmd_dissect_structure,
    get_thread_list = cmd_get_thread_list,
    auto_assemble = cmd_auto_assemble,
    read_pointer_chain = cmd_read_pointer_chain,
    get_rtti_classname = cmd_get_rtti_classname,
    get_address_info = cmd_get_address_info,
    checksum_memory = cmd_checksum_memory,
    generate_signature = cmd_generate_signature,
    
    -- DBVM Hypervisor Tools (Safe Dynamic Tracing - Ring -1)
    get_physical_address = cmd_get_physical_address,
    start_dbvm_watch = cmd_start_dbvm_watch,
    poll_dbvm_watch = cmd_poll_dbvm_watch,  -- Poll logs without stopping watch
    stop_dbvm_watch = cmd_stop_dbvm_watch,
    -- Semantic aliases for ease of use
    find_what_writes_safe = cmd_start_dbvm_watch,  -- Alias: start watching for writes
    find_what_accesses_safe = cmd_start_dbvm_watch,  -- Alias: start watching for accesses
    get_watch_results = cmd_stop_dbvm_watch,  -- Alias: retrieve results and stop
    
    -- Utility
    ping = cmd_ping,
    
    -- Emulator / Guest-Address Translation
    set_guest_base       = cmd_set_guest_base,
    add_guest_region     = cmd_add_guest_region,
    get_guest_base       = cmd_get_guest_base,
    clear_guest_base     = cmd_clear_guest_base,
    translate_address    = cmd_translate_address,
    auto_detect_emulator = cmd_auto_detect_emulator,
    get_region_info      = cmd_get_region_info,

    -- Process Control
    list_processes       = cmd_list_processes,
    attach_process       = cmd_attach_process,

    -- Code Patching
    nop_instruction      = cmd_nop_instruction,

    -- Additional Disassembly
    disassemble_mips     = cmd_disassemble_mips,

    -- Address List / Cheat Table (v11.7+)
    list_address_list         = cmd_list_address_list,
    get_address_entry         = cmd_get_address_entry,
    read_address_entry        = cmd_read_address_entry,
    write_address_entry       = cmd_write_address_entry,
    add_address_entry         = cmd_add_address_entry,
    remove_address_entry      = cmd_remove_address_entry,
    set_address_entry_active  = cmd_set_address_entry_active,
}

-- ============================================================================
-- MAIN COMMAND PROCESSOR
-- ============================================================================

local function executeCommand(jsonRequest)
    local ok, request = pcall(json.decode, jsonRequest)
    if not ok or not request then
        return json.encode({ jsonrpc = "2.0", error = { code = -32700, message = "Parse error" }, id = nil })
    end
    
    local method = request.method
    local params = request.params or {}
    local id = request.id
    
    local handler = commandHandlers[method]
    if not handler then
        return json.encode({ jsonrpc = "2.0", error = { code = -32601, message = "Method not found: " .. tostring(method) }, id = id })
    end
    
    local ok2, result = pcall(handler, params)
    if not ok2 then
        return json.encode({ jsonrpc = "2.0", error = { code = -32603, message = "Internal error: " .. tostring(result) }, id = id })
    end
    
    return json.encode({ jsonrpc = "2.0", result = result, id = id })
end

-- ============================================================================
-- THREAD-BASED PIPE SERVER (NON-BLOCKING GUI)
-- ============================================================================
-- Replaces v10 Timer architecture to prevent GUI Freezes.
-- I/O happens in Worker Thread. Execution happens in Main Thread.

local function PipeWorker(thread)
    log("Worker Thread Started - Waiting for connection...")
    
    while not thread.Terminated do
        -- Create Pipe Instance per connection attempt
        -- Increased buffer size to 64KB for better throughput
        local pipe = createPipe(PIPE_NAME, 65536, 65536)
        if not pipe then
            log("Fatal: Failed to create pipe")
            return
        end
        
        -- Store reference so we can destroy it from main thread (stopServer) to break blocking calls
        serverState.workerPipe = pipe
        
        -- timeout for blocking operations (connect/read)
        -- We DO NOT set pipe.Timeout because it auto-disconnects on timeout.
        -- We rely on blocking reads and pipe.destroy() from stopServer to break the block.
        -- pipe.Timeout = 0 (Default, Infinite)
        
        -- Wait for client (Blocking, but in thread so GUI is fine)
        -- LuaPipeServer uses acceptConnection().
        -- note: acceptConnection might not return a boolean, so we check pipe.Connected afterwards.
        
        -- log("Thread: Calling acceptConnection()...")
        pcall(function()
            pipe.acceptConnection()
        end)
        
        if pipe.Connected and not thread.Terminated then
            log("Client Connected")
            serverState.connected = true
            
            while not thread.Terminated and pipe.Connected do
                -- Try to read header (4 bytes)
                -- We use pcall to handle timeouts/errors gracefully
                local ok, lenBytes = pcall(function() return pipe.readBytes(4) end)
                
                if ok and lenBytes and #lenBytes == 4 then
                    local len = lenBytes[1] + (lenBytes[2] * 256) + (lenBytes[3] * 65536) + (lenBytes[4] * 16777216)
                    
                    -- Sanity check length
                    if len > 0 and len < 100 * 1024 * 1024 then
                        local payload = pipe.readString(len)
                        
                        if payload then
                            -- CRITICAL: EXECUTE ON MAIN THREAD
                            -- We pause the worker and run logic on GUI thread to be safe
                            local response = nil
                            thread.synchronize(function()
                                response = executeCommand(payload)
                            end)
                            
                            -- Write response back (Worker Thread)
                            if response then
                                local rLen = #response
                                local b1 = rLen % 256
                                local b2 = math.floor(rLen / 256) % 256
                                local b3 = math.floor(rLen / 65536) % 256
                                local b4 = math.floor(rLen / 16777216) % 256
                                
                                pipe.writeBytes({b1, b2, b3, b4})
                                pipe.writeString(response)
                            end
                        else
                             -- log("Thread: Read payload failed (nil)")
                        end
                    end
                else
                    -- Read failed. If pipe disconnected, the loop will terminate on next check.
                    if not pipe.Connected then
                        -- Client disconnected gracefully
                    end
                end
            end
            
            serverState.connected = false
            log("Client Disconnected")
        else
            -- Debug: acceptConnection returned but pipe not valid
            -- This usually happens on termination or weird state
            if not thread.Terminated then
                -- log("Thread: Helper log - connection attempt invalid")
            end
        end
        
        -- Clean up pipe
        serverState.workerPipe = nil
        pcall(function() pipe.destroy() end)
        
        -- Brief sleep before recreating pipe to accept new connection
        if not thread.Terminated then sleep(50) end
    end
    
    log("Worker Thread Terminated")
end

-- ============================================================================
-- MAIN CONTROL
-- ============================================================================

function StopMCPBridge()
    if serverState.workerThread then
        log("Stopping Server (Terminating Thread)...")
        serverState.workerThread.terminate()
        
        -- Force destroy the pipe if it's currently blocking on acceptConnection or read
        if serverState.workerPipe then
            pcall(function() serverState.workerPipe.destroy() end)
            serverState.workerPipe = nil
        end
        
        serverState.workerThread = nil
        serverState.running = false
    end
    
    if serverState.timer then
        serverState.timer.destroy()
        serverState.timer = nil
    end
    
    -- CRITICAL: Cleanup all zombie resources (breakpoints, DBVM watches, scans)
    cleanupZombieState()
    
    log("Server Stopped")
end

function StartMCPBridge()
    StopMCPBridge()  -- This now also calls cleanupZombieState()
    
    -- Update Global State
    log("Starting MCP Bridge v" .. VERSION)
    
    serverState.running = true
    serverState.connected = false
    
    -- Create the Worker Thread
    serverState.workerThread = createThread(PipeWorker)
    
    log("===========================================")
    log("MCP Server Listening on: " .. PIPE_NAME)
    log("Architecture: Threaded I/O + Synchronized Execution")
    log("Cleanup: Zombie Prevention Active")
    log("===========================================")
end

-- Auto-start
StartMCPBridge()

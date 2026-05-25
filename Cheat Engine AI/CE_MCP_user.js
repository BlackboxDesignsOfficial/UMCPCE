// ==UserScript==
// @name         CE MCP
// @namespace    ce-mcp
// @version      2.10.0
// @description  Browser-side MCP-style API for Cheat Engine. Panel UI, auto-bootstrap, hands-off [TOOL_CALL] auto-bridge for AI chat sites
// @author       Blackbox Designs
// @match        https://venice.ai/*
// @match        https://chatgpt.com/*
// @match        https://gemini.google.com/*
// @match        https://copilot.microsoft.com/*
// @match        https://poe.com/*
// @match        https://you.com/*
// @match        https://perplexity.ai/*
// @match        https://huggingface.co/chat/*
// @match        https://chat.deepseek.com/*
// @match        https://claude.ai/*
// @match        https://chat.qwen.ai/*
// @match        https://grok.com/*
// @run-at       document-start
// @grant        none
// @noframes
// ==/UserScript==

/* eslint-disable no-undef */
(function () {
    'use strict';

    if (window.cheatEngineMCP && window.cheatEngineMCP.__installed) return;

    var ENDPOINT_DEFAULT = 'http://127.0.0.1:9999/api';
    var TIMEOUT_MS       = 60000;
    var STATUS_POLL_MS   = 5000;

    var endpoint  = (window.__CE_MCP_ENDPOINT && String(window.__CE_MCP_ENDPOINT)) || ENDPOINT_DEFAULT;
    var healthUrl = endpoint.replace(/\/api\/?$/, '/health');

    var _id = 1;
    function nextId() { return _id++; }
    var _status = { state: 'unknown', info: null, ts: 0 };

    // ========================================================================
    // call() / poll()
    // ========================================================================
    async function call(method, params) {
        if (!method || typeof method !== 'string') {
            throw new Error('cheatEngineMCP.call: method must be a string');
        }
        var ac, timer;
        try { ac = new AbortController(); } catch (_) { ac = null; }
        if (ac) timer = setTimeout(function () { ac.abort(); }, TIMEOUT_MS);
        var body = JSON.stringify({ jsonrpc: '2.0', method: method, params: params || {}, id: nextId() });
        var resp;
        try {
            resp = await fetch(endpoint, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: body, signal: ac ? ac.signal : undefined,
                mode: 'cors', cache: 'no-store', credentials: 'omit', redirect: 'error'
            });
        } catch (e) {
            if (timer) clearTimeout(timer);
            var hint = (e && e.name === 'AbortError') ? 'request timed out after ' + TIMEOUT_MS + 'ms' : (e && e.message) || 'fetch failed';
            throw new Error('CE bridge unreachable (' + hint + '). Is bridge.py running at ' + endpoint + ' ?');
        }
        if (timer) clearTimeout(timer);
        var data;
        try { data = await resp.json(); }
        catch (e) { throw new Error('CE bridge returned non-JSON (HTTP ' + resp.status + ')'); }
        if (data && data.error) {
            var msg = (typeof data.error === 'string') ? data.error : (data.error.message || JSON.stringify(data.error));
            var err = new Error('CE: ' + msg);
            err.jsonrpcError  = data.error;
            err.requestMethod = method;
            throw err;
        }
        return (data && Object.prototype.hasOwnProperty.call(data, 'result')) ? data.result : data;
    }

    function poll(method, params, intervalMs, callback) {
        if (typeof callback !== 'function') throw new Error('cheatEngineMCP.poll: callback is required');
        var ms = Math.max(50, (intervalMs | 0) || 500);
        var stopped = false, inflight = false, timer = null, errStreak = 0;
        async function tick() {
            if (stopped) return;
            if (inflight) { timer = setTimeout(tick, ms); return; }
            inflight = true;
            try {
                var data = await call(method, params); errStreak = 0;
                if (!stopped) { try { callback(null, data); } catch (_) {} }
            } catch (e) {
                errStreak++;
                if (!stopped) { try { callback(e, null); } catch (_) {} }
            } finally {
                inflight = false;
                if (!stopped) {
                    var nextDelay = ms;
                    if (errStreak > 3) nextDelay = Math.min(ms * Math.pow(2, Math.min(errStreak - 3, 5)), 30000);
                    timer = setTimeout(tick, nextDelay);
                }
            }
        }
        Promise.resolve().then(tick);
        return { stop: function () { stopped = true; if (timer) clearTimeout(timer); }, isRunning: function () { return !stopped; } };
    }

    // ========================================================================
    // METHODS
    // ========================================================================
    var METHODS = [
        'get_process_info', 'enum_modules', 'get_thread_list',
        'get_symbol_address', 'get_address_info', 'get_rtti_classname',
        'read_memory', 'read_bytes', 'read_integer', 'read_string',
        'read_pointer', 'read_pointer_chain',
        'write_integer', 'write_memory', 'write_string',
        'scan_all', 'next_scan', 'get_scan_results',
        'aob_scan', 'pattern_scan', 'search_string', 'generate_signature',
        'get_memory_regions', 'enum_memory_regions_full',
        'disassemble', 'disassemble_ppc', 'get_instruction_info',
        'find_function_boundaries', 'analyze_function',
        'find_references', 'find_call_references',
        'dissect_structure', 'checksum_memory',
        'set_breakpoint', 'set_execution_breakpoint',
        'set_data_breakpoint', 'set_write_breakpoint',
        'remove_breakpoint', 'get_breakpoint_hits',
        'list_breakpoints', 'clear_all_breakpoints',
        'get_physical_address',
        'start_dbvm_watch', 'poll_dbvm_watch', 'stop_dbvm_watch',
        'find_what_writes_safe', 'find_what_accesses_safe', 'get_watch_results',
        'evaluate_lua', 'auto_assemble',
        'ping',
        // Emulator / guest-address translation (v2.6+)
        'set_guest_base', 'add_guest_region', 'get_guest_base', 'clear_guest_base',
        'translate_address', 'auto_detect_emulator', 'get_region_info',
        // v2.7+
        'list_processes', 'attach_process',
        'nop_instruction',
        'disassemble_mips',
        // v2.9+ address-list / cheat-table
        'list_address_list', 'get_address_entry',
        'read_address_entry', 'write_address_entry',
        'add_address_entry', 'remove_address_entry',
        'set_address_entry_active'
    ];
    var KNOWN_METHODS = {};
    for (var k = 0; k < METHODS.length; k++) KNOWN_METHODS[METHODS[k]] = true;

    // ========================================================================
    // TOOL REFERENCE - param names verified against ce_mcp_bridge.lua source
    // ========================================================================
    var TOOL_REFERENCE = [
        '== Tool reference (params verified against Lua source) ==',
        '',
        'PROCESS / MODULES:',
        '* ping {} - returns {success, version, process_id, message}',
        '* get_process_info {} - returns {process_id, process_name, modules:[{name,address,size},...]}',
        '* list_processes {filter?} - lists all running processes (filter is optional substring match on name)',
        '* attach_process {pid?, name?} - attach CE to a process by pid or name. CLEARS guest regions and reinitializes symbols. Returns {success, process_id, process_name}',
        '* enum_modules {}',
        '* get_thread_list {}',
        '* get_symbol_address {symbol}',
        '* get_address_info {address, include_modules?, include_symbols?, include_sections?}',
        '* get_rtti_classname {address}',
        '',
        'READ:',
        '* read_integer {address, type}  type = "byte"|"word"|"dword"|"qword"|"float"|"double"',
        '* read_memory {address, size}  - max size 65536, returns int array',
        '* read_string {address, max_length, wide}  wide=true for UTF-16 (NOTE: param is "wide" not "encoding")',
        '* read_pointer {base|address, offsets?}  - offsets is an int array, returns the dereferenced address',
        '* read_pointer_chain {base, offsets}',
        '',
        'WRITE:',
        '* write_integer {address, value, type}',
        '* write_memory {address, bytes}  - bytes is an int array',
        '* write_string {address, value, wide}',
        '* nop_instruction {address, count?, arch?}  arch = "x86" (default) | "ppc" | "mips". Replaces instructions with arch-correct NOPs (x86: 0x90 walking instruction sizes; ppc: 0x60000000 BE; mips: 0x00000000). Returns "original" bytes for restoration via write_memory.',
        '',
        'SCAN:',
        '* scan_all {value, type, start_address?, end_address?}  - first scan; type defaults to "dword". Optional start_address/end_address bound the scan (auto-translated through guest regions if active).',
        '* next_scan {value, scan_type}  scan_type = "exact"|"increased"|"decreased"|"changed"|"unchanged"',
        '* get_scan_results {max}  - results auto-annotated with guest_address when guest mapping is active',
        '* aob_scan {pattern, protection, limit, start_address?, end_address?}  pattern like "48 89 5C ?? 24", protection like "+X" or "+W-C". Optional bounds (auto-translated through guest regions). Results annotated with guest_address when guest mapping is active.',
        '* search_string {string, wide?, limit?}  - finds occurrences of an ASCII/UTF-16 string. (Param is "string" not "value", no "encoding" or "protection".)',
        '* generate_signature {address, length?}',
        '',
        'ANALYSIS:',
        '* disassemble {address, count}',
        '* disassemble_ppc {address, count}  - PowerPC (big-endian, fixed 4-byte). USE THIS for GameCube/Wii code in Dolphin instead of disassemble. Branch targets are reported as absolute addresses in guest space, so you can follow calls by passing the target straight back into disassemble_ppc.',
        '* disassemble_mips {address, count, endian?}  - MIPS R3000/R4300/R5900 (fixed 4-byte). USE THIS for PS1/PS2 (PCSX2) code (endian="little", default) and for N64 (endian="big"). Decodes MIPS-I/II + R5900 multimedia/64-bit ops; rare opcodes appear as ".word 0x...". Branch/jump targets are absolute guest addresses when guest mapping is active.',
        '* get_instruction_info {address}',
        '* find_function_boundaries {address, max_search?}',
        '* analyze_function {address}',
        '* find_references {address, limit?}  - x-refs to address',
        '* find_call_references {address}',
        '* dissect_structure {address, size?}  - param is "size" not "depth"',
        '* checksum_memory {address, size}',
        '* get_memory_regions {max?}  - sampled scan; no protection_filter',
        '* enum_memory_regions_full {max?, min_size?, max_size?, protect_filter?, sort_by_size?, committed_only?}  - full enumeration with filtering. protect_filter is a string like "RW", "RX", "RWX". Sort+filter happen BEFORE the max cap, so the largest region survives.',
        '* get_region_info {address}  - virtualquery-style info for a single address (base, size, protection, offset, guest_address if applicable)',
        '',
        'BREAKPOINTS (hardware, non-breaking - logs hits to a buffer):',
        '* set_breakpoint {address, id, capture_registers?, capture_stack?, stack_depth?}',
        '* set_data_breakpoint {address, size, id, access_type}  access_type = "r"|"w"|"rw"',
        '* remove_breakpoint {id}',
        '* get_breakpoint_hits {id?, clear?}',
        '* list_breakpoints {} / clear_all_breakpoints {}',
        '',
        'DBVM HYPERVISOR (Ring -1, requires DBVM/DBK driver):',
        '* get_physical_address {address}',
        '* start_dbvm_watch {address, mode, max_entries}  mode = "r"|"w"|"x"|"rw"',
        '* poll_dbvm_watch {address, max_results}',
        '* stop_dbvm_watch {address}',
        '',
        'EMULATOR GUEST-ADDRESS TRANSLATION (only relevant if attached to an emulator):',
        '* auto_detect_emulator {kind, expected_size?, size_tolerance?}  kind = "gamecube"|"wii"|"pcsx2"|"ps2"|"ps1"|"gba"|"nds"|"n64"|"snes"|"custom". Auto-installs all known regions for the platform (e.g. wii installs both MEM1 and MEM2; gba installs EWRAM and IWRAM). Returns regions_found and not_found arrays.',
        '* set_guest_base {address, kind?, range_start?, range_end?, size?}  - replaces all existing regions with one entry. range_start/range_end/address accept hex strings ("0x80000000") or numbers.',
        '* add_guest_region {address, kind?, range_start?, range_end?, size?}  - LAYERS an additional region without replacing existing ones. Use this to manually add a region after auto_detect_emulator (e.g. extra ROM/CART memory).',
        '* get_guest_base {} - returns all_regions array plus backward-compat single-region fields for the first region',
        '* clear_guest_base {} - clears ALL regions',
        '* translate_address {address, direction?}  direction = "guest_to_host"|"host_to_guest" (auto-inferred by walking regions)',
        '  Workflow: attach to emulator -> auto_detect_emulator {kind:"<platform>"} -> all subsequent reads/scans on guest addrs auto-translate. For CODE inspection, use disassemble_ppc (Dolphin GC/Wii), disassemble_mips (PCSX2/PS1/N64), or disassemble (everything else).',
        '  PRESETS: gamecube=0x80000000+24MiB; wii=MEM1@0x80000000+24MiB and MEM2@0x90000000+64MiB; pcsx2=0x00100000+32MiB; ps1=0x80000000+2MiB; gba=EWRAM@0x02000000+256KiB and IWRAM@0x03000000+32KiB; nds=0x02000000+4MiB; n64=0x80000000+8MiB; snes=0x7E0000+128KiB.',
        '',
        'ADDRESS LIST / CHEAT TABLE (saved addresses pane in CE main window):',
        '  Every command below identifies the target entry with ONE of: {id: N} (unique numeric ID, stable across renames), {index: N} (0-based position in the list), or {description: "name"} (case-sensitive). Prefer id once you have it.',
        '* list_address_list {limit?, include_resolved?, filter?}  - returns {entries:[{id, index, description, address_text, type, active, current_address?, guest_address?, value?, offsets?, is_pointer?, ...}, ...]}. filter is a case-insensitive substring match on description. include_resolved defaults to true (set false to skip Value/CurrentAddress reads on large lists).',
        '* get_address_entry {id|index|description}  - full details of a single entry',
        '* read_address_entry {id|index|description}  - returns {value, type, current_address}; uses the entry\'s configured type, so a "Player HP" dword entry returns the dword value as a string',
        '* write_address_entry {id|index|description, value}  - writes value into the entry. value should match the entry\'s type ("100" for int, "1.5" for float, "DE AD BE EF" for byte_array). CE parses the string per the entry\'s configured type.',
        '* add_address_entry {description, address, type?, offsets?, value?, active?, show_as_hex?, show_as_signed?, allow_decrease?, allow_increase?}  - creates a new entry. type defaults to "dword". offsets is innermost-first ([0]=final offset applied AFTER the deepest dereference). If a guest mapping is active and address is a hex guest VA, it auto-translates to host and annotates the description with [guest:0x...] for readability.',
        '* remove_address_entry {id|index|description}  - removes entry from the list (cannot be undone via this tool)',
        '* set_address_entry_active {id|index|description, active, allow_decrease?, allow_increase?}  - turns Active on/off (freezes values, enables/disables script entries). active is a bool; "freeze" is accepted as a synonym.',
        '  Types accepted in type field: byte|word|dword|qword|float|double|string|unicode_string|byte_array|pointer|auto_assembler|grouped.',
        '',
        'SCRIPTING:',
        '* evaluate_lua {code}  - runs arbitrary CE Lua. SEE LUA STRING-ESCAPE NOTE BELOW.',
        '  HELPERS: a global "mcp" table is pre-installed inside evaluate_lua. PREFER these over CE\'s raw readBytes/writeBytes APIs (which are inconsistent: readBytes(a,n) returns N values, readBytes(a,n,true) returns a 1-INDEXED table - easy to mess up). Available helpers:',
        '    mcp.toAddr(x)              -> address (accepts number, "0x...", "name+0xN")',
        '    mcp.translateGuest(addr)   -> host addr (returns addr unchanged if no guest mapping)',
        '    mcp.readByte(addr)         -> int (or nil)',
        '    mcp.readBytesArray(addr,n) -> ALWAYS a 1-indexed table (empty {} on failure, never nil)',
        '    mcp.readAscii(addr,n)      -> string (non-printable -> "."); strips trailing NUL',
        '    mcp.readHex(addr,n)        -> "AA BB CC DD ..." string',
        '    mcp.dump(addr,n)           -> xxd-style hexdump string (16 cols, ASCII column)',
        '    mcp.read(addr,vtype)       -> value; vtype = "byte"|"word"|"dword"|"qword"|"float"|"double"|"pointer", OR a numeric byte count (1/2/4/8)',
        '    mcp.write(addr,val,vtype)  -> bool; same vtype shapes as mcp.read',
        '    mcp.hex(n)                 -> "0xNNNN..." string',
        '    mcp.readMany(addr,vtype,count,stride?) -> array of values',
        '* auto_assemble {script}  - CE AutoAssembler script',
        '',
        'Addresses: hex strings ("0x7FF712340000"), symbol+offset ("game.exe+0x12AB000"), or numbers.'
    ].join('\n');

    // ========================================================================
    // COMMON MISTAKES - this block teaches the AI to avoid the failure modes
    // that have shown up repeatedly across past sessions. Kept here (not
    // dynamically built) so the wording can be tightened as new patterns emerge.
    // ========================================================================
    var COMMON_MISTAKES = [
        '== COMMON MISTAKES TO AVOID ==',
        '',
        '--- JSON layer vs Lua layer (evaluate_lua) ---',
        'TWO layers: (1) the outer JSON {"code": "..."} MUST be a valid JSON string in double quotes; (2) the Lua source code INSIDE that string. Do not confuse them.',
        '',
        'ANTI-PATTERNS that break JSON parsing:',
        '  WRONG: {"code": [[ local x = 1 ]]}             <- Lua [[...]] is NOT a JSON value. JSON parse fails.',
        '  WRONG: {"code": "string.format("%d", 42)"}     <- raw double-quotes inside the JSON string. Either escape (\\") or use Lua [[long-strings]].',
        '  WRONG: {"code": "x = \'hello\'"}                  <- single quotes are valid Lua but mixing nested quotes is error-prone.',
        '',
        'RIGHT - use Lua long-strings INSIDE the JSON value:',
        '  {"code": "return string.format([[%d]], 42)"}',
        '  {"code": "local s = [[hello world]]; return s"}',
        '  {"code": "return AOBScan([[48 89 5C 24 ??]], [[+X]])"}',
        '',
        'If the Lua string itself contains [[ or ]], use balanced equals: [==[ ... ]==] (1 or more = signs, same on both sides).',
        '  {"code": "return [==[ contains [[ and ]] inside ]==]"}',
        '',
        '--- Lua dialect: LuaJIT 5.1 (NOT Lua 5.3) ---',
        'Cheat Engine runs LuaJIT 5.1. The following 5.3+ features DO NOT EXIST and will compile-error:',
        '  &  |  ~  <<  >>     (no native bitwise operators - see below)',
        '  //                  (no integer division operator)',
        '  string.pack / string.unpack',
        '',
        'For bitwise ops, LuaJIT exposes a `bit` library:',
        '  bit.band(a, b)      AND',
        '  bit.bor(a, b)       OR',
        '  bit.bxor(a, b)      XOR',
        '  bit.bnot(a)         NOT',
        '  bit.lshift(a, n)    a << n',
        '  bit.rshift(a, n)    a >> n  (logical)',
        '  bit.arshift(a, n)   a >> n  (arithmetic)',
        '',
        'Or use arithmetic for simple cases:',
        '  hi_nibble = math.floor(b / 16)',
        '  lo_nibble = b % 16',
        '  byte_at_n = math.floor(dword / (256 ^ n)) % 256',
        '',
        '--- Lua syntax pitfalls ---',
        '  Equality is `==`, NOT `=`.       `if x == 0 then` (NOT `if x = 0 then`)',
        '  Inequality is `~=`, NOT `!=`.    `if x ~= nil then`',
        '  Logical ops are `and`/`or`/`not`, NOT `&&`/`||`/`!`.',
        '  String concat is `..`, NOT `+`.   `name = "p" .. id`',
        '  No `++` / `--`. Write `x = x + 1`.',
        '  `nil`, NOT `null` or `undefined`.',
        '  Tables are 1-INDEXED. `t[1]` is the first element, `t[0]` is nil.',
        '  `#t` is the length of array-part of table `t`.',
        '',
        '--- CE readBytes API has TWO shapes (this trips up most callers) ---',
        '  readBytes(addr, n)         returns N values (NOT a table). Use: local b1, b2, b3 = readBytes(addr, 3)',
        '  readBytes(addr, n, true)   returns a 1-INDEXED table. Use: local t = readBytes(addr, 16, true); for i=1,#t do ... end',
        '',
        'PREFER the mcp.* helpers - they fix the API quirks:',
        '  mcp.readByte(addr)             -> int or nil',
        '  mcp.readBytesArray(addr, n)    -> ALWAYS a 1-indexed table (empty {} on failure, never nil)',
        '  mcp.read(addr, vtype)          -> typed read. vtype = "byte"|"word"|"dword"|"qword"|"float"|"double"|"pointer"|"string", OR numeric byte count (1/2/4/8)',
        '  mcp.write(addr, val, vtype)    -> bool. Same vtype shapes.',
        '  mcp.readAscii(addr, n)         -> printable ASCII string (non-printables -> .)',
        '  mcp.readHex(addr, n)           -> "DE AD BE EF" hex string',
        '  mcp.dump(addr, n)              -> xxd-style hexdump (hex + ASCII columns)',
        '  mcp.toAddr(x)                  -> address from number, "0x...", "name+0xN"',
        '  mcp.hex(n)                     -> 0x-prefixed hex string',
        '',
        '--- Safety / robustness ---',
        '  Wrap risky CE reads in pcall: `local ok, v = pcall(readInteger, addr); if not ok or not v then ...end`',
        '  Vtables on heap objects may be 0 if the object is not yet initialized (e.g. not connected to server). Check before dereferencing: `if vtable ~= 0 then ...`',
        '  Do NOT touch UI-only CE APIs from evaluate_lua (getMemoryViewForm().MemoryView.* etc). They live on the GUI thread and will crash the bridge worker.',
        '  Do NOT write huge byte-at-a-time scans in evaluate_lua - use aob_scan / scan_all / search_string instead. The pipe has a 60s timeout and an iteration-heavy Lua script will hang the request.',
        '',
        '--- Tool-call choice ---',
        '  PREFER structured tools (read_memory, aob_scan, disassemble, find_references, etc.) over evaluate_lua. They are faster, safer, and return structured JSON.',
        '  USE evaluate_lua only when no structured tool fits, or for one-off custom logic.',
        '  For PE headers: e_lfanew is at offset +0x3C (a DWORD). NT headers start at imagebase + e_lfanew. Section table is at NT + 0xF8 for PE32. Each section entry is 40 bytes. Use mcp.read for the DWORD/WORD reads.',
        ''
    ].join('\n');

    // ========================================================================
    // PROTOCOL
    // ========================================================================

    // v2.8: JSON-repair fallback for evaluate_lua. The AI repeatedly emits
    // unescaped double-quotes inside the "code" string ({"code":"...string.format("%d",x)..."})
    // which kills strict JSON.parse. The userscript already tells the AI to use
    // Lua [[long-strings]] (see COMMON_MISTAKES), but recovery is cheaper than
    // rejecting + reasking. This regex assumes the object is just {"code": "..."}
    // or {"code": "...", "other": ...} where "..." may contain unescaped quotes.
    // v2.10: also handle {"code": [[ ... ]]} - the AI sometimes substitutes
    // Lua long-string syntax for the JSON string value, which also kills
    // JSON.parse (the value starts with [ not ").
    // Returns a params object on success, null if it can't repair.
    function _repairEvaluateLuaJSON(rawObjStr) {
        // v2.10: Lua long-string in place of JSON string: {"code": [[ ... ]]}
        // Try this FIRST because the [[...]] markers are unambiguous.
        var m = rawObjStr.match(/^\s*\{\s*"code"\s*:\s*\[\[([\s\S]*?)\]\]\s*\}\s*$/);
        if (m) return { code: m[1], __repaired: true };
        // Single-field shape: {"code": "<anything>"} where <anything> may have ".
        // Greedy capture grabs everything from the first quote after `code:`
        // through to the last quote before the closing `}`.
        m = rawObjStr.match(/^\s*\{\s*"code"\s*:\s*"([\s\S]*)"\s*\}\s*$/);
        if (m) return { code: m[1], __repaired: true };
        // Two-field shape with another known param after code: rare for evaluate_lua,
        // but handle {"code": "...", "<other>": <json>}.
        m = rawObjStr.match(/^\s*\{\s*"code"\s*:\s*"([\s\S]*?)"\s*,\s*"([A-Za-z_][\w]*)"\s*:\s*([\s\S]+?)\s*\}\s*$/);
        if (m) {
            try {
                var other = JSON.parse(m[3]);
                var obj = { code: m[1], __repaired: true };
                obj[m[2]] = other;
                return obj;
            } catch (_) { /* fallthrough */ }
        }
        return null;
    }

    function parseToolCalls(text) {
        if (typeof text !== 'string' || !text) return [];
        var out = [];
        var re = /\[TOOL_CALL\]\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\{[\s\S]*?\})\s*(?=\n|$|\[TOOL_CALL\])/g;
        var m;
        while ((m = re.exec(text)) !== null) {
            var entry = { method: m[1], raw: m[0], params: null };
            try { entry.params = JSON.parse(m[2]); }
            catch (e) {
                // v2.8: try to repair evaluate_lua calls with unescaped quotes
                if (m[1] === 'evaluate_lua') {
                    var repaired = _repairEvaluateLuaJSON(m[2]);
                    if (repaired) {
                        entry.params = repaired;
                        entry.repaired = true;
                    } else {
                        entry.parseError = 'invalid JSON: ' + e.message;
                    }
                } else {
                    entry.parseError = 'invalid JSON: ' + e.message;
                }
            }
            if (!KNOWN_METHODS[m[1]]) entry.unknownMethod = true;
            out.push(entry);
        }
        return out;
    }

    function _trunc(s, n) { return s.length > n ? s.slice(0, n) + '...(truncated)' : s; }

    async function runToolCalls(text, opts) {
        opts = opts || {};
        var maxBytes = opts.maxBytes || 8000;
        var calls = parseToolCalls(text);
        if (calls.length === 0) return '(no [TOOL_CALL] markers found)';
        var blocks = [];
        for (var i = 0; i < calls.length; i++) {
            var c = calls[i];
            var header = '[TOOL_RESULT] ' + c.method;
            if (c.parseError)    { blocks.push(header + '\nERROR: ' + c.parseError); continue; }
            if (c.unknownMethod) { blocks.push(header + '\nERROR: unknown method "' + c.method + '"'); continue; }
            try {
                // v2.8: strip the internal __repaired flag before sending to the bridge
                var paramsToSend = c.params;
                if (c.repaired && paramsToSend && paramsToSend.__repaired) {
                    paramsToSend = Object.assign({}, paramsToSend);
                    delete paramsToSend.__repaired;
                }
                var result = await call(c.method, paramsToSend);
                var body = _trunc(JSON.stringify(result, null, 2), maxBytes);
                if (c.repaired) {
                    // Tell the AI we patched its JSON so it learns the right shape next time.
                    body = body + '\n\n(WARNING: your JSON for evaluate_lua was malformed - auto-repaired. ' +
                                  'The "code" value MUST be a properly-escaped JSON string. ' +
                                  'CORRECT: {"code": "return 1+1"}  or  {"code": "return readBytes(0x400000, 4, true)"} (escape inner \\" as \\\\\\"). ' +
                                  'WRONG: {"code": [[ ... ]]} (Lua long-string is not valid JSON). ' +
                                  'WRONG: {"code": "string.format("x")"} (unescaped quotes break JSON). ' +
                                  'To embed strings inside the Lua code without escaping, use single quotes inside the Lua code: {"code": "return string.format(\'%d\', 42)"}.)';
                }
                blocks.push(header + '\n' + body);
            } catch (e) {
                blocks.push(header + '\nERROR: ' + (e && e.message || String(e)));
            }
        }
        return blocks.join('\n\n');
    }

    async function bridgeClipboard() {
        if (!navigator.clipboard) throw new Error('navigator.clipboard unavailable');
        var input = await navigator.clipboard.readText();
        var output = await runToolCalls(input);
        try { await navigator.clipboard.writeText(output); }
        catch (e) { console.warn('[CE-MCP] could not write clipboard:', e); console.log(output); }
        return output;
    }

    // ========================================================================
    // Bootstrap
    // ========================================================================
    async function buildBootstrapMessage() {
        var pingResult, procResult;
        try { pingResult = await call('ping', {}); }
        catch (e) { throw new Error('cannot bootstrap - bridge not responding to ping: ' + e.message); }
        try { procResult = await call('get_process_info', {}); }
        catch (e) { procResult = { error: String(e && e.message || e) }; }

        // Trim get_process_info output - module list can be huge
        var procSummary = procResult && !procResult.error ? {
            success: procResult.success,
            process_id: procResult.process_id,
            process_name: procResult.process_name,
            module_count: procResult.module_count,
            main_module: procResult.modules && procResult.modules[0] ? {
                name: procResult.modules[0].name,
                address: procResult.modules[0].address,
                size: procResult.modules[0].size
            } : null,
            note: 'full module list available via enum_modules {} or by re-calling get_process_info {}'
        } : procResult;

        var attached = procResult && !procResult.error
            ? (procResult.process_name || 'unknown') + ' (PID ' + (procResult.process_id || '?') + ')'
            : 'no process attached';

        return [
            '== CE MCP TOOL ACCESS - SESSION ACTIVE ==',
            '',
            'You are currently connected to a live Cheat Engine instance through a userscript bridge running in this browser tab. The bridge is verified working - real verification output below.',
            '',
            'CRITICAL: Do NOT respond with disclaimers like "I am a text-based AI and cannot access local resources" or "my capabilities have not changed". Those statements are INCORRECT in this session. The userscript intercepts [TOOL_CALL] markers in your output, executes them against Cheat Engine, and returns [TOOL_RESULT] blocks. This is functioning, real tool use - you are in an agentic session.',
            '',
            '== HOW TO INVOKE A TOOL ==',
            'Output ONE LINE in this exact form (NOT inside a code block, NOT inside backticks, NOT inside markdown formatting):',
            '[TOOL_CALL] method_name {"param": "value", ...}',
            '',
            'A userscript will detect that line within ~2 seconds of your message completing, run it, and send a [TOOL_RESULT] block as the next user message. Issue at most 3 tool calls per message and wait for results before issuing more.',
            '',
            '== VERIFICATION (these calls already ran successfully) ==',
            '',
            '[TOOL_CALL] ping {}',
            '[TOOL_RESULT] ping',
            JSON.stringify(pingResult, null, 2),
            '',
            '[TOOL_CALL] get_process_info {}',
            '[TOOL_RESULT] get_process_info',
            JSON.stringify(procSummary, null, 2),
            '',
            'The bridge is alive. Cheat Engine is running. Currently attached: ' + attached + '.',
            '',
            TOOL_REFERENCE,
            '',
            COMMON_MISTAKES,
            '',
            '== ERROR HANDLING ==',
            'If a structured tool returns an error like "No X" or "Invalid Y", the param name might be wrong. Check the tool reference above carefully. As a fallback you can always use evaluate_lua with raw CE Lua API calls to accomplish the same thing.',
            '',
            '== ACKNOWLEDGE AND PROCEED ==',
            'Acknowledge you understand the tool protocol in one short sentence (no disclaimers, no "I will try"), then wait for the user\'s actual question. Use the tools without asking permission once a question is asked.'
        ].join('\n');
    }

    async function bootstrap(opts) {
        opts = opts || {};
        var alsoStartAuto = opts.startAuto !== false;
        var msg = await buildBootstrapMessage();
        await AutoBridge.injectAndSend(msg);
        if (alsoStartAuto) setTimeout(function () { AutoBridge.start(); }, 1500);
        console.log('[CE-MCP] bootstrap message sent (' + msg.length + ' chars)' + (alsoStartAuto ? ', auto-watcher arming in 1.5s' : ''));
        return msg.length;
    }

    // ========================================================================
    // AUTO-BRIDGE (DOM watcher, React injection, [TOOL_CALL] auto-loop)
    // ========================================================================
    var AutoBridge = (function () {
        var POLL_MS         = 500;
        var STABLE_MS       = 1500;
        var MAX_CALLS_BATCH = 10;
        var INJECT_DELAY_MS = 80;
        var SEND_DELAY_MS   = 150;
        // v2.8: cooldown after we hit send. Prevents tick() from re-injecting
        // before the chat UI has processed our previous submission. Venice in
        // particular will queue multiple "user messages" if you slam the input
        // before its in-flight response settles.
        var POST_SEND_COOLDOWN_MS = 2500;

        var running = false, executing = false;
        var pollTimer = null;
        var lastSeenText = '', stableSinceTs = 0, lastProcessedText = '';
        // v2.8: dedup tool calls per AI message element. The AI streams its
        // reply, so the same [TOOL_CALL] markers reappear in every tick as the
        // text grows. Without dedup we'd re-execute earlier calls every tick.
        var lastAIElement = null;
        var ranCallsInElement = Object.create(null);  // raw call text -> true
        // v2.8: when we last successfully called send(). Used for cooldown.
        var lastSendTs = 0;

        var selectors = {
            aiMessage: [
                '[data-message-author-role="assistant"]',
                '[data-message-role="assistant"]',
                '[data-author="assistant"]',
                '[data-role="assistant"]',
                '[class*="assistant"][class*="message"]',
                '[class*="message-bot"]',
                '[class*="ai-message"]',
                '[class*="model-response"]',
                'main [class*="message"]:not([class*="user"])',
                'main article'
            ],
            input: [
                'textarea[placeholder]',
                '[contenteditable="true"][role="textbox"]',
                '[contenteditable="true"]',
                'textarea',
                'main form textarea',
                'main form [contenteditable="true"]'
            ],
            sendButton: [
                'button[type="submit"]',
                'button[aria-label*="send" i]',
                'button[data-testid*="send" i]',
                'main form button[type="submit"]',
                'form button:last-of-type'
            ],
            // v2.8: indicators that the assistant is still generating. If any
            // match, tick() will skip - we don't want to inject mid-stream.
            // These are intentionally generic since Venice/ChatGPT/Claude all
            // use different markup; the inspect() helper will print what matched.
            busyIndicator: [
                'button[aria-label*="stop" i]',
                'button[aria-label*="cancel" i]',
                'button[aria-label*="abort" i]',
                'button[data-testid*="stop" i]',
                '[aria-label*="generating" i]',
                '[class*="stop-generating" i]'
            ]
        };

        // v2.8: regex of button labels we MUST NOT click. Mic/voice/dictation/
        // attach buttons sit next to the send button on most chat UIs and
        // 'form button:last-of-type' will hit them when the real send button
        // is hidden (Venice agentic mode does exactly this).
        var EXCLUDED_BTN_RE = /\b(mic|microphone|voice|speech|dictat|record|attach|upload|file|image|photo|camera|stop|cancel|abort)\b/i;

        function _isExcludedButton(el) {
            if (!el) return true;
            var label = (
                (el.getAttribute && el.getAttribute('aria-label')) ||
                (el.getAttribute && el.getAttribute('title')) ||
                el.title || el.textContent || ''
            ).toLowerCase();
            return EXCLUDED_BTN_RE.test(label);
        }

        function _firstVisibleMatch(selList, excludeFn) {
            for (var i = 0; i < selList.length; i++) {
                var els;
                try { els = Array.prototype.slice.call(document.querySelectorAll(selList[i])); } catch (e) { continue; }
                for (var j = els.length - 1; j >= 0; j--) {
                    var el = els[j], r = el.getBoundingClientRect();
                    if (r.width <= 0 || r.height <= 0) continue;
                    if (excludeFn && excludeFn(el)) continue;
                    return el;
                }
            }
            return null;
        }
        function _allMatching(selList) {
            for (var i = 0; i < selList.length; i++) {
                var els;
                try { els = Array.prototype.slice.call(document.querySelectorAll(selList[i])); } catch (e) { continue; }
                if (els.length) return els;
            }
            return [];
        }
        function findInput()       { return _firstVisibleMatch(selectors.input); }
        // v2.8: skip mic/voice/upload/etc. buttons so we never accidentally
        // hit Venice's microphone in agentic mode.
        function findSendButton()  { return _firstVisibleMatch(selectors.sendButton, _isExcludedButton); }
        function findAllAIMessages() { return _allMatching(selectors.aiMessage); }
        function findLatestAI()    { var all = findAllAIMessages(); return all.length ? all[all.length - 1] : null; }

        // v2.8: returns the busy-indicator element if the assistant is
        // mid-stream, or null if idle. Used to defer tick() so we don't pile
        // up queued user messages while the AI is still talking.
        function findBusyIndicator() { return _firstVisibleMatch(selectors.busyIndicator); }

        function setNativeValue(el, value) {
            var proto = Object.getPrototypeOf(el);
            var desc = Object.getOwnPropertyDescriptor(proto, 'value');
            if (desc && desc.set) desc.set.call(el, value);
            else el.value = value;
        }
        function fireReactInputEvents(el, text) {
            try { el.dispatchEvent(new InputEvent('beforeinput', { inputType: 'insertText', data: text, bubbles: true, cancelable: true })); } catch (_) {}
            try { el.dispatchEvent(new InputEvent('input', { inputType: 'insertText', data: text, bubbles: true })); }
            catch (_) { el.dispatchEvent(new Event('input', { bubbles: true })); }
            try { el.dispatchEvent(new CompositionEvent('compositionend', { data: text, bubbles: true })); } catch (_) {}
            try { el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: ' ', code: 'Space' })); } catch (_) {}
            el.dispatchEvent(new Event('change', { bubbles: true }));
        }
        function _sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

        async function injectText(text) {
            var input = findInput();
            if (!input) throw new Error('no input element found');
            input.focus(); await _sleep(INJECT_DELAY_MS);
            var tag = (input.tagName || '').toUpperCase();
            if (tag === 'TEXTAREA' || tag === 'INPUT') {
                setNativeValue(input, text);
                fireReactInputEvents(input, text);
            } else {
                try { document.execCommand('selectAll', false, null); document.execCommand('delete', false, null); } catch (_) {}
                await _sleep(20);
                var inserted = false;
                try { inserted = document.execCommand('insertText', false, text); } catch (_) {}
                if (!inserted) input.textContent = text;
                fireReactInputEvents(input, text);
            }
            await _sleep(INJECT_DELAY_MS);
        }
        function pressEnter(el) {
            // v2.10: include shiftKey:false explicitly so the chat UI doesn't
            // interpret this as Shift+Enter (which usually inserts a newline
            // instead of submitting).
            ['keydown', 'keypress', 'keyup'].forEach(function (t) {
                el.dispatchEvent(new KeyboardEvent(t, {
                    key: 'Enter', code: 'Enter', keyCode: 13, which: 13,
                    bubbles: true, cancelable: true,
                    shiftKey: false, ctrlKey: false, altKey: false, metaKey: false
                }));
            });
        }
        async function send() {
            await _sleep(SEND_DELAY_MS);
            // v2.10: Enter-key is now the PRIMARY submit path. Clicking the
            // page's send button is unreliable across chat UIs - selectors
            // catch mic/voice/upload buttons, Venice agentic mode hides the
            // button entirely, and some UIs disable it during streaming.
            // The Enter key works everywhere a chat input accepts text.
            var input = findInput();
            if (input) {
                input.focus();
                await _sleep(20);
                pressEnter(input);
                lastSendTs = Date.now();
                return 'enter';
            }
            // Deep fallback: only if we genuinely cannot find an input element,
            // try the page's send button (still skipping mic/voice via the
            // exclusion filter). This branch shouldn't normally fire.
            var btn = findSendButton();
            if (btn && !btn.disabled && btn.offsetParent !== null) {
                btn.click();
                lastSendTs = Date.now();
                return 'click-fallback';
            }
            throw new Error('no send target found (no input element and no usable send button)');
        }
        async function injectAndSend(text) { await injectText(text); return await send(); }

        async function tick() {
            if (!running || executing) return;
            // v2.8: post-send cooldown. Don't even look at the AI message
            // until enough time has passed for the chat UI to register our
            // previous submission. Without this, Venice queues our injections
            // as multiple stacked user messages.
            if (Date.now() - lastSendTs < POST_SEND_COOLDOWN_MS) return;
            // v2.8: if the assistant is still generating, hold off. We only
            // want to act on a fully-settled message.
            if (findBusyIndicator()) return;

            var msg = findLatestAI();
            if (!msg) return;

            // v2.8: detect AI message turnover - new element means a fresh
            // assistant reply, so reset per-element call dedup state.
            if (msg !== lastAIElement) {
                lastAIElement = msg;
                ranCallsInElement = Object.create(null);
            }

            var text = (msg.innerText || msg.textContent || '').trim();
            if (!text || text === lastProcessedText) return;
            if (text !== lastSeenText) { lastSeenText = text; stableSinceTs = Date.now(); return; }
            if (Date.now() - stableSinceTs < STABLE_MS) return;

            var calls = parseToolCalls(text);
            if (calls.length === 0) { lastProcessedText = text; return; }

            // v2.8: filter out calls already executed in this AI turn. The
            // AI's reply text grows as it streams, so the same [TOOL_CALL]
            // markers reappear on every tick. Without this filter we'd send
            // duplicate results back to chat, which is what "queues too many
            // prompts" looked like to the user.
            var newCalls = [];
            for (var i = 0; i < calls.length; i++) {
                if (!ranCallsInElement[calls[i].raw]) newCalls.push(calls[i]);
            }
            if (newCalls.length === 0) { lastProcessedText = text; return; }

            executing = true;
            try {
                var toRun = newCalls.length > MAX_CALLS_BATCH ? newCalls.slice(0, MAX_CALLS_BATCH) : newCalls;
                // Mark them as run BEFORE awaiting so a re-entrant tick can't
                // re-pick the same ones.
                for (var k = 0; k < toRun.length; k++) ranCallsInElement[toRun[k].raw] = true;
                // Build a stitched text containing ONLY the new calls so
                // runToolCalls() runs exactly them - reusing the existing
                // text-based runner avoids duplicating the call/repair logic.
                var stitched = toRun.map(function (c) { return c.raw; }).join('\n');
                console.log('[CE-MCP/auto] running', toRun.length, 'new tool call(s) (', calls.length - toRun.length, 'already run this turn)');
                var output = await runToolCalls(stitched);
                console.log('[CE-MCP/auto] result:\n' + output);
                await injectAndSend(output);
                lastProcessedText = text;
            } catch (e) {
                console.error('[CE-MCP/auto] error:', e);
            } finally { executing = false; }
        }

        function start() {
            if (running) return;
            running = true;
            var msg = findLatestAI();
            lastAIElement = msg;
            ranCallsInElement = Object.create(null);
            // v2.8: pre-seed dedup with any tool calls already in the visible
            // assistant message so we don't re-run history on startup.
            if (msg) {
                var initialText = (msg.innerText || msg.textContent || '').trim();
                var initialCalls = parseToolCalls(initialText);
                for (var i = 0; i < initialCalls.length; i++) {
                    ranCallsInElement[initialCalls[i].raw] = true;
                }
                lastProcessedText = initialText;
                lastSeenText = initialText;
            } else {
                lastProcessedText = '';
                lastSeenText = '';
            }
            stableSinceTs = Date.now();
            lastSendTs = Date.now();  // v2.8: initial cooldown so we don't fire immediately on start
            pollTimer = setInterval(function () { tick(); }, POLL_MS);
            console.log('[CE-MCP/auto] watcher started');
            updatePanel();
        }
        function stop() {
            running = false;
            if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
            console.log('[CE-MCP/auto] watcher stopped');
            updatePanel();
        }
        function inspect() {
            var input = findInput(), msg = findLatestAI(), btn = findSendButton();
            var busy = findBusyIndicator();
            var info = {
                running: running, executing: executing,
                input:       input ? (input.tagName + ' [' + (input.className || '') + ']') : '(none)',
                latestAI:    msg ? ('len=' + ((msg.innerText || '').length) + ' [' + (msg.className || '') + ']') : '(none)',
                aiCount:     findAllAIMessages().length,
                sendButton:  btn ? ('label=' + (btn.getAttribute('aria-label') || btn.textContent || '?')) : '(none - will use Enter key)',
                busy:        busy ? ('label=' + (busy.getAttribute('aria-label') || busy.textContent || '?')) : '(idle)',
                cooldownLeftMs: Math.max(0, POST_SEND_COOLDOWN_MS - (Date.now() - lastSendTs)),
                callsRunThisTurn: Object.keys(ranCallsInElement).length
            };
            console.table(info);
            return info;
        }
        function setSelectors(overrides) {
            if (!overrides || typeof overrides !== 'object') return selectors;
            ['aiMessage', 'input', 'sendButton', 'busyIndicator'].forEach(function (k) {
                if (overrides[k]) selectors[k] = Array.isArray(overrides[k]) ? overrides[k].slice() : [overrides[k]];
            });
            console.log('[CE-MCP/auto] selectors updated:', selectors);
            return selectors;
        }
        return {
            start: start, stop: stop, isRunning: function () { return running; },
            inspect: inspect, setSelectors: setSelectors,
            findInput: findInput, findLatestAI: findLatestAI,
            findAllAIMessages: findAllAIMessages, findSendButton: findSendButton,
            findBusyIndicator: findBusyIndicator,
            injectText: injectText, send: send, injectAndSend: injectAndSend
        };
    })();

    // ========================================================================
    // checkConnection
    // ========================================================================
    async function checkConnection() {
        try {
            var r = await fetch(healthUrl, { method: 'GET', mode: 'cors', cache: 'no-store' });
            var j = await r.json();
            return { ok: true, proxy: true, ce: !!(j && j.connected), info: j };
        } catch (e) {
            return { ok: false, proxy: false, ce: false, error: String(e && e.message || e) };
        }
    }

    // ========================================================================
    // Public API
    // ========================================================================
    var api = {
        __installed: true,
        __version:   '2.10.0',
        get endpoint() { return endpoint; },
        get status()   { return Object.assign({}, _status); },
        setEndpoint: function (url) { endpoint = String(url); healthUrl = endpoint.replace(/\/api\/?$/, '/health'); },
        call: call, poll: poll, checkConnection: checkConnection,
        parseToolCalls: parseToolCalls, runToolCalls: runToolCalls, bridgeClipboard: bridgeClipboard,
        bootstrap: bootstrap, buildBootstrapMessage: buildBootstrapMessage,
        auto: AutoBridge,
        showPanel: function () { createPanel(); },
        hidePanel: function () { var p = document.getElementById('ce-mcp-panel'); if (p) p.remove(); }
    };
    for (var i = 0; i < METHODS.length; i++) {
        (function (m) { api[m] = function (params) { return call(m, params || {}); }; })(METHODS[i]);
    }
    window.cheatEngineMCP = api;
    if (!window.ceMCP) window.ceMCP = api;

    // ========================================================================
    // PANEL UI
    // ========================================================================
    function createPanel() {
        if (document.getElementById('ce-mcp-panel')) return;
        if (!document.body) return;
        var el = document.createElement('div');
        el.id = 'ce-mcp-panel';
        el.innerHTML =
            '<style>' +
            '#ce-mcp-panel{position:fixed;bottom:16px;right:16px;z-index:2147483647;width:200px;' +
              'background:#0e1116;color:#d6deeb;border:1px solid #21262d;border-radius:8px;' +
              'font:12px/1.4 -apple-system,"Segoe UI",sans-serif;box-shadow:0 4px 16px #0008;user-select:none;}' +
            '#ce-mcp-panel .hdr{padding:7px 10px;border-bottom:1px solid #21262d;display:flex;justify-content:space-between;align-items:center;cursor:move;gap:12px;}' +
            '#ce-mcp-panel .hdr .ttl{font-weight:bold;letter-spacing:0.5px;}' +
            '#ce-mcp-panel .hdr .ver{color:#6b7785;font-weight:normal;margin-left:6px;font-size:10px;}' +
            '#ce-mcp-panel .hdr .min{cursor:pointer;color:#6b7785;padding:0 4px;font-size:16px;line-height:1;user-select:none;}' +
            '#ce-mcp-panel .hdr .min:hover{color:#5fbf00;}' +
            '#ce-mcp-panel .hdr .dot{margin-right:6px;}' +
            '#ce-mcp-panel .row{padding:6px 10px;display:flex;align-items:center;gap:8px;}' +
            '#ce-mcp-panel .dot{width:8px;height:8px;border-radius:50%;background:#6b7785;flex:none;}' +
            '#ce-mcp-panel .dot.ok{background:#5fbf00;box-shadow:0 0 6px #5fbf0066;}' +
            '#ce-mcp-panel .dot.warn{background:#ffa500;box-shadow:0 0 6px #ffa50066;}' +
            '#ce-mcp-panel .dot.bad{background:#ff5050;box-shadow:0 0 6px #ff505066;}' +
            '#ce-mcp-panel .lbl{flex:1;font-size:11px;color:#a8b2c1;}' +
            '#ce-mcp-panel .btns{padding:0 10px 10px;display:flex;flex-direction:column;gap:4px;}' +
            '#ce-mcp-panel .btn{padding:6px 8px;background:#161b22;border:1px solid #30363d;color:#d6deeb;' +
              'border-radius:4px;text-align:center;cursor:pointer;font:inherit;font-size:11px;}' +
            '#ce-mcp-panel .btn:hover{border-color:#5fbf00;color:#5fbf00;}' +
            '#ce-mcp-panel .btn.primary,#ce-mcp-panel .btn.on{background:#5fbf00;color:#0e1116;font-weight:bold;border-color:#5fbf00;}' +
            '#ce-mcp-panel .btn.primary:hover{background:#6bd400;border-color:#6bd400;color:#0e1116;}' +
            '#ce-mcp-panel .btn:disabled{opacity:0.5;cursor:wait;}' +
            // Collapsed state: hide status row + buttons, keep header. The dot
            // stays visible in the header so the user can still see connection
            // state at a glance.
            '#ce-mcp-panel.collapsed{width:auto;}' +
            '#ce-mcp-panel.collapsed .row,#ce-mcp-panel.collapsed .btns{display:none;}' +
            '#ce-mcp-panel.collapsed .hdr{border-bottom:none;}' +
            '</style>' +
            '<div class="hdr">' +
                '<div style="display:flex;align-items:center;">' +
                    '<span class="dot" id="ce-mcp-dot"></span>' +
                    '<span class="ttl">CE-MCP</span>' +
                    '<span class="ver">v2.10.0</span>' +
                '</div>' +
                '<span class="min" id="ce-mcp-min" title="minimize">−</span>' +
            '</div>' +
            '<div class="row">' +
                '<span class="lbl" id="ce-mcp-state">checking...</span>' +
            '</div>' +
            '<div class="btns">' +
                '<button class="btn primary" id="ce-mcp-boot">Bootstrap</button>' +
                '<button class="btn" id="ce-mcp-auto">Auto: OFF</button>' +
            '</div>';
        document.body.appendChild(el);

        document.getElementById('ce-mcp-min').onclick = function (e) {
            // Stop the drag handler from also firing on this click.
            e.stopPropagation();
            var collapsed = el.classList.toggle('collapsed');
            this.textContent = collapsed ? '+' : '−';
            this.title = collapsed ? 'expand' : 'minimize';
        };
        document.getElementById('ce-mcp-boot').onclick = async function () {
            var btn = this;
            btn.disabled = true;
            var origLabel = btn.textContent;
            btn.textContent = 'sending...';
            try { await bootstrap({ startAuto: true }); }
            catch (e) { console.error('[CE-MCP] bootstrap failed:', e); }
            finally { btn.textContent = origLabel; btn.disabled = false; updatePanel(); }
        };
        document.getElementById('ce-mcp-auto').onclick = function () {
            if (AutoBridge.isRunning()) AutoBridge.stop(); else AutoBridge.start();
            updatePanel();
        };

        // drag header
        (function () {
            var hdr = el.querySelector('.hdr');
            var dragging = false, sx = 0, sy = 0, ox = 0, oy = 0;
            hdr.addEventListener('mousedown', function (e) {
                if (e.target.id === 'ce-mcp-min') return;
                dragging = true; sx = e.clientX; sy = e.clientY;
                var rect = el.getBoundingClientRect(); ox = rect.left; oy = rect.top;
                e.preventDefault();
            });
            document.addEventListener('mousemove', function (e) {
                if (!dragging) return;
                el.style.right = 'auto'; el.style.bottom = 'auto';
                el.style.left = (ox + e.clientX - sx) + 'px';
                el.style.top  = (oy + e.clientY - sy) + 'px';
            });
            document.addEventListener('mouseup', function () { dragging = false; });
        })();

        updatePanel();
    }
    function updatePanel() {
        var dot = document.getElementById('ce-mcp-dot');
        var lbl = document.getElementById('ce-mcp-state');
        var autoBtn = document.getElementById('ce-mcp-auto');
        if (!dot || !lbl) return;
        var state = _status.state;
        dot.className = 'dot ' + (state === 'online' ? 'ok' : state === 'partial' ? 'warn' : 'bad');
        lbl.textContent =
            state === 'online'  ? 'Ready' :
            state === 'partial' ? 'CE not attached' :
            state === 'offline' ? 'Bridge offline' :
            'checking...';
        if (autoBtn) {
            var on = AutoBridge.isRunning();
            autoBtn.textContent = 'Auto: ' + (on ? 'ON' : 'OFF');
            autoBtn.className = 'btn' + (on ? ' on' : '');
        }
    }

    async function statusLoop() {
        while (true) {
            var snap = await checkConnection();
            var prev = _status.state;
            var next = !snap.ok ? 'offline' : !snap.ce ? 'partial' : 'online';
            _status = { state: next, info: snap.info || null, ts: Date.now() };
            if (prev !== next) console.log('[CE-MCP] ' + (prev === 'unknown' ? 'initial: ' : prev + ' -> ') + next);
            updatePanel();
            await new Promise(function (r) { setTimeout(r, STATUS_POLL_MS); });
        }
    }
    function init() {
        if (document.body) { createPanel(); statusLoop(); }
        else setTimeout(init, 200);
    }
    setTimeout(init, 100);
})();

# CE-MCP Bridge

Browser-AI <-> Cheat Engine automation bridge.

A three-part toolchain that lets an AI chat (Venice.ai, Claude.ai, ChatGPT, DeepSeek, etc.) drive Cheat Engine through structured tool calls. The AI emits `[TOOL_CALL] <method> {"json": "params"}` markers in its replies; the userscript intercepts them in the browser, forwards them through a local HTTP bridge to a named pipe, and a Lua server inside Cheat Engine executes the request and returns JSON. The userscript pastes the result back into the chat as a `[TOOL_RESULT]` block and presses Enter, closing the loop.

```
  Browser tab (AI chat)
       |
       |  [TOOL_CALL] ...                            inline DOM watcher
       v                                              (CE_MCP_user.js,
  Tampermonkey userscript ---fetch()---> Python    Greasemonkey/Violentmonkey)
                                          |
                                          |  HTTP POST /api
                                          v
                                    bridge.py  <----  loopback only
                                          |          (127.0.0.1:9999)
                                          |  named pipe
                                          |  \\.\pipe\CE_MCP_Bridge_v99
                                          v
                                    ce_mcp_bridge.lua
                                          |
                                          v
                                    Cheat Engine
                                    (target process)
```

---

## Requirements

### Operating system

Windows only. The bridge uses Windows named pipes (`\\.\pipe\...`) via `pywin32`. Linux/macOS support would require swapping the IPC layer for Unix domain sockets or TCP - not currently supported.

### Cheat Engine

* **Cheat Engine 7.x** (recent releases - 7.5 and 7.6 are known to work).
* Must be running with sufficient privileges to attach to the target process. For most games, **Run as administrator**.
* Lua scripting must be enabled (it is by default).

### Python

* **Python 3.8 or newer**, 64-bit recommended. Recent versions (3.11, 3.12, 3.13, 3.14) all work.
* Use the `py` launcher (default Python installer behavior on Windows). If you don't have `py` working, the install instructions below cover it.

### Python modules

Exactly one third-party module: **`pywin32`**. Everything else (`argparse`, `json`, `struct`, `threading`, `http.server`) is in the Python standard library.

Install:

```
py -m pip install pywin32
```

If that fails with a permissions error, add `--user`:

```
py -m pip install --user pywin32
```

### Browser

* **Firefox** with **Greasemonkey** or **Violentmonkey**, OR
* **Chrome / Edge / Brave** with **Tampermonkey** or **Violentmonkey**.

The userscript opts into Private Network Access (PNA) which Chrome-family browsers require for `http://127.0.0.1` requests from public origins.

### AI chat site

Any site whose chat interface uses standard DOM elements works. The userscript ships with `@match` rules for:

* `venice.ai` (including agentic-chat mode)
* `claude.ai`
* `chatgpt.com`
* `chat.deepseek.com`
* `gemini.google.com`
* `copilot.microsoft.com`
* `poe.com`
* `you.com`
* `perplexity.ai`
* `huggingface.co/chat`
* `chat.qwen.ai`
* `grok.com`

Adding another site is just a matter of editing the `@match` lines in the script header.

---

## Files in this repo

| File                  | Role                                                                  |
| --------------------- | --------------------------------------------------------------------- |
| `ce_mcp_bridge.lua`   | Lua server. Runs **inside Cheat Engine**. Hosts the named pipe.       |
| `bridge.py`           | HTTP <-> named-pipe relay. Runs on **your machine**.                  |
| `CE_MCP_user.js`      | Tampermonkey/Greasemonkey userscript. Runs **in your browser**.       |
| `README.md`           | This file.                                                            |

---

## First-time setup

### 1. Save the three files

Pick a folder anywhere on your machine. **Avoid OneDrive / iCloud / cloud-synced folders** - they sometimes mark files as "online only", which makes the Python launcher unable to open them. A path like `C:\Tools\ce-mcp\` is fine.

> If you save these files using **Notepad**, Windows may silently append `.txt`, leaving you with `bridge.py.txt`. To check, open a terminal and run `dir`. To prevent: enable **View -> File name extensions** in File Explorer, or use a real editor (VS Code, Notepad++).

You should end up with:

```
C:\Tools\ce-mcp\
    bridge.py
    ce_mcp_bridge.lua
    CE_MCP_user.js
```

### 2. Install Python dependency

Open a Command Prompt or PowerShell and run:

```
py -m pip install pywin32
```

If `py` is not recognized, you have two options:

* Install Python from <https://www.python.org/downloads/> and check **"Add Python to PATH"** plus **"Install py launcher"** during installation.
* Use `python` instead of `py` if that's what your system has: `python -m pip install pywin32`.

If the Microsoft Store "Python alias" intercepts your command, open **Settings -> Apps -> Advanced app settings -> App execution aliases** and turn off the Python aliases.

### 3. Install the userscript

In your browser, click the userscript manager icon (Tampermonkey / Greasemonkey / Violentmonkey) -> **Create a new script**. Delete the boilerplate, paste the entire contents of `CE_MCP_user.js`, and save (Ctrl+S).

If you'd rather drag-and-drop: open `CE_MCP_user.js` directly in your browser - most userscript managers detect the metadata block and show an Install button.

Confirm it's installed by clicking the userscript manager icon - you should see **CE MCP v2.10.0** listed and enabled.

### 4. Start Cheat Engine and load the Lua script

* Open Cheat Engine.
* Click **File -> Open Process** and attach to your target process (the game, emulator, etc.).
* Open the Lua console: **Table -> Show Cheat Table Lua Script**, OR press Ctrl+Alt+L.
* Paste the entire contents of `ce_mcp_bridge.lua` into the editor.
* Click **Execute** (the arrow button) or press Ctrl+E.

You should see lines in the Lua console output similar to:

```
[MCP v11.8.0] Starting MCP Bridge v11.8.0
[MCP v11.8.0] ===========================================
[MCP v11.8.0] MCP Server Listening on: \\.\pipe\CE_MCP_Bridge_v99
[MCP v11.8.0] Architecture: Threaded I/O + Synchronized Execution
[MCP v11.8.0] Cleanup: Zombie Prevention Active
[MCP v11.8.0] ===========================================
```

Leave the Lua console window open. Closing it stops the server.

### 5. Start the Python bridge

In your terminal, in the folder where you saved the files:

```
cd C:\Tools\ce-mcp
py bridge.py
```

You should see:

```
ce_bridge -> http://127.0.0.1:9999/api
            pipe: \\.\pipe\CE_MCP_Bridge_v99
            pipe: CONNECTED (verified)
            prober: pings every 5s when idle
            reconnect: up to 5 attempts with backoff
Ready. Ctrl+C to stop.
```

If the bridge says `pipe: not connected`, go back to step 4 and check that the Lua script is actually running (you should see the `listening on pipe` message in Cheat Engine's Lua console).

### 6. Open a chat tab

Open a tab on any AI chat site listed under **AI chat site** above (e.g. `https://chat.deepseek.com`). The userscript injects a small floating panel in the bottom-right corner showing:

* **status dot** + label - green/"Bridge online, CE attached" = everything ready, yellow/"Bridge up, CE pipe down" = `bridge.py` running but Cheat Engine isn't responding on the pipe, red/"Bridge unreachable" = `bridge.py` isn't running.
* **CE-MCP v2.10.0** version label, draggable header.
* Three buttons:
  * **Bootstrap & Auto** (primary) - sends the canonical bootstrap message to the AI (telling it the tool protocol and listing every available tool), then turns the auto-loop on. Click this **once at the start of every new chat**.
  * **Auto: OFF / Auto: ON** - manual toggle for the auto-loop without re-sending the bootstrap. Useful if you want to pause inline tool execution mid-conversation.
  * **Inspect Selectors** - prints what the userscript matched for input element, latest AI message element, and send button. Use this on a new site whose DOM doesn't match the built-in selectors.

### 7. Bootstrap and go

Click **Bootstrap & Auto**. The button types the bootstrap message into the chat input, presses Enter, and arms the auto-loop. From this point on, whenever the AI emits a properly-formatted `[TOOL_CALL]` block in its reply, the userscript will:

1. Wait for the AI's message to stop streaming (1.5s idle).
2. Parse the call(s), send each through the bridge to Cheat Engine, get a JSON result.
3. Inject the formatted `[TOOL_RESULT]` block into the chat input.
4. Press Enter to submit it as a new user message.

The AI sees the tool result as if you had typed it manually, and continues from there.

---

## Daily startup checklist

After the one-time setup, every time you want to use the bridge:

1. Open Cheat Engine, attach to target process, paste & execute `ce_mcp_bridge.lua` in the Lua console.
2. In a terminal: `py bridge.py`.
3. Open an AI chat tab (or refresh an existing one - the bootstrap message is per-conversation, not per-tab). Click **Bootstrap & Auto**.
4. Talk to the AI.

To stop: close the chat tab (or click **Auto: ON** to toggle the loop off), Ctrl+C the bridge terminal, close Cheat Engine's Lua console.

---

## Troubleshooting

### `[Errno 2] No such file or directory: 'bridge.py'`

* The file may actually be `bridge.py.txt` - Notepad and other editors silently append `.txt`. Run `dir bridge.*` to check. If it's a `.txt`, rename: `ren bridge.py.txt bridge.py`.
* You may be in the wrong directory - run `cd` to print it, then `cd C:\path\to\where\you\saved`.
* The file may be in OneDrive and "online-only" - move it out of any cloud-synced folder.

### `ERROR: pywin32 is required`

Re-run `py -m pip install pywin32`. If that gives a permissions error, add `--user`.

### Bridge says `pipe: not connected`

Cheat Engine isn't running, or the Lua script isn't loaded, or both. Look at Cheat Engine's Lua console - the line `[MCP v11.8.0] MCP Server Listening on: \\.\pipe\CE_MCP_Bridge_v99` must be visible. If not, re-paste and re-execute the Lua script.

### Userscript dot is red

The browser can't reach `http://127.0.0.1:9999`. Either `bridge.py` isn't running, or another process is on port 9999, or a local firewall is blocking the loopback request.

To change the port, run the bridge with `--port N` (e.g. `py bridge.py --port 9998`) and point the userscript at the new URL. Two ways to repoint the userscript:

* **Edit the script**: open the userscript in your manager, change the `ENDPOINT_DEFAULT` constant near the top (currently `'http://127.0.0.1:9999/api'`) and save.
* **Override per-tab** (advanced): set `window.__CE_MCP_ENDPOINT = 'http://127.0.0.1:9998/api'` in a `@run-at document-start` snippet before the userscript loads. The userscript honors this variable if it exists.

### Userscript dot is yellow

Bridge is up, Cheat Engine pipe is down. Same fix as `pipe: not connected` above.

### AI's `[TOOL_CALL]` gets pasted into chat but nothing else happens

The auto-loop is off. On the floating panel, the **Auto: OFF** button should read **Auto: ON** while the loop is running. Click it to toggle. If you've already clicked **Bootstrap & Auto** in this conversation, just click the Auto toggle - you don't need to re-bootstrap.

### `(WARNING: your JSON for evaluate_lua was malformed - auto-repaired ...)` in results

This means the AI sent a malformed `evaluate_lua` call - usually either unescaped double-quotes inside the `code` value, or using Lua `[[...]]` long-string syntax where JSON requires `"..."`. The bridge auto-repaired the payload and ran the Lua anyway, but the warning is a hint to fix the prompt. The AI usually corrects itself after seeing the warning once; if it keeps recurring, remind the AI: **"In `evaluate_lua`, the `code` field is a JSON string in `"..."`. Use Lua `[[long-strings]]` only INSIDE that string for the Lua-level strings, never to replace the JSON quotes."**

### Repeated `[TOOL_CALL]` markers running multiple times

Fixed in v2.10. If it still happens, click **Auto** off and back on to reset the dedup state.

### Process crash when the AI calls a CE function

Some CE Lua APIs are unstable when called from the pipe thread (e.g. UI-touching functions like opening the disassembler view). Avoid calling those through `evaluate_lua`. The structured tools (`read_memory`, `aob_scan`, `disassemble`, etc.) are safe.

### Userscript can't find the input/send button on a new site

Open the browser console (F12) and run:

```
ceMCP.auto.inspect()
```

You'll see what the userscript matched for input, latest AI message, send button, and current busy/cooldown state. You can override the CSS selectors at runtime:

```
ceMCP.auto.setSelectors({
    input: ['div.MyChatInputClass[contenteditable="true"]'],
    aiMessage: ['div.MyAssistantMessageClass']
})
```

Once you've found selectors that work, you can hardcode them in the userscript at the `selectors` object inside the AutoBridge module.

---

## Capabilities

The bridge ships with a substantial set of tools. The AI gets a full reference automatically via the Bootstrap message; the categories are:

* **Process / modules** - `ping`, `get_process_info`, `enum_modules`, `list_processes`, `attach_process`, `get_thread_list`, `get_symbol_address`, `get_address_info`, `get_rtti_classname`, `get_region_info`.
* **Read** - `read_integer`, `read_memory` (alias `read_bytes`), `read_string`, `read_pointer`, `read_pointer_chain`.
* **Write** - `write_integer`, `write_memory`, `write_string`, `nop_instruction`.
* **Scan** - `scan_all`, `next_scan`, `get_scan_results`, `aob_scan` (alias `pattern_scan`), `find_references`, `find_call_references`, `search_string`.
* **Memory regions** - `get_memory_regions`, `enum_memory_regions_full`, `checksum_memory`, `generate_signature`.
* **Analysis** - `disassemble` (x86/x64), `disassemble_ppc` (GameCube/Wii), `disassemble_mips` (PS1/PS2/N64), `get_instruction_info`, `find_function_boundaries`, `analyze_function`, `dissect_structure`.
* **Breakpoints** - `set_breakpoint` (alias `set_execution_breakpoint`), `set_data_breakpoint` (alias `set_write_breakpoint`), `remove_breakpoint`, `list_breakpoints`, `get_breakpoint_hits`, `clear_all_breakpoints`.
* **DBVM hypervisor watches (Ring -1, no thread freeze)** - `get_physical_address`, `start_dbvm_watch` (aliases `find_what_writes_safe`, `find_what_accesses_safe`), `poll_dbvm_watch`, `stop_dbvm_watch` (alias `get_watch_results`). Requires DBVM to be loaded in Cheat Engine.
* **Emulator guest-address translation** - `auto_detect_emulator`, `set_guest_base`, `add_guest_region`, `get_guest_base`, `clear_guest_base`, `translate_address`. Presets for GameCube, Wii, PCSX2 (PS2), PS1, GBA, NDS, N64, SNES.
* **Scripting** - `evaluate_lua` (arbitrary Lua with a pre-installed `mcp.*` helper table), `auto_assemble`.
* **Address list / cheat table** - `list_address_list`, `get_address_entry`, `read_address_entry`, `write_address_entry`, `add_address_entry`, `remove_address_entry`, `set_address_entry_active`.

The complete tool reference is embedded in the userscript and shown to the AI when you click **Bootstrap & Auto**.

---

## Security notes

* The HTTP bridge binds to `127.0.0.1` only by default. Other machines on your network cannot reach it.
* The bridge has no authentication. Anything running on your machine (including browser tabs from any origin) can call it. Don't run untrusted code on the same machine while the bridge is active.
* `evaluate_lua` lets the AI run arbitrary Lua inside Cheat Engine's process. CE's Lua environment can read/write process memory, execute system commands via `os.execute`, and access the filesystem. **Treat any AI conversation that has this bridge enabled as if you were running the AI's suggested code yourself**.
* Cheat Engine attaching to a game is detectable by anti-cheat software. **Do not use this against online competitive games**, only single-player or in-development titles.

---

## License / attribution

Free to use, modify, and share. No warranty. If you redistribute, please keep the original `[CE-MCP]` banner so users can recognize the tooling.

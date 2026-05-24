# Ghidra + GhidraMCP Setup

State of the reverse-engineering toolchain, so future sessions don't have to rediscover this.

## Installed components

| Component | Path |
|-----------|------|
| Ghidra | `F:\ru\myprojects\may\ghidra_12.0.4_PUBLIC` |
| GhidraMCP extension zip | `F:\ru\myprojects\may\ghidra_12.0.4_PUBLIC\Extensions\Ghidra\GhidraMCP-1-4.zip` |
| MCP bridge script | `F:\ru\myprojects\may\ghidra_12.0.4_PUBLIC\bridge_mcp_ghidra.py` |
| Python (for the bridge) | `D:\Installations\Python310\python.exe` (has `mcp` and `requests` installed) |
| GhidraMCP source | https://github.com/LaurieWired/GhidraMCP — release 1.4 |

## How the pieces connect

```
Claude Code <-- stdio --> bridge_mcp_ghidra.py <-- HTTP :8080 --> GhidraMCPPlugin (inside Ghidra CodeBrowser)
```

The HTTP server only runs while Ghidra has the binary open in CodeBrowser and the GhidraMCPPlugin is enabled. Closing CodeBrowser kills the server.

## Claude Code MCP registration

Registered as `ghidra` in `C:\Users\ab\.claude.json` under the project `F:\ru\myprojects\april\calc` with:

```
D:\Installations\Python310\python.exe F:\ru\myprojects\may\ghidra_12.0.4_PUBLIC\bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
```

If you ever need to re-add: `claude mcp add ghidra -- "<python>" "<bridge.py>" --ghidra-server "http://127.0.0.1:8080/"`

**MCP tools only register at Claude Code startup.** Adding the server mid-session is silent — restart Claude Code to pick it up.

## To resume a session

1. Launch Ghidra (`ghidraRun.bat`), open the existing project, double-click `HP39gII.exe` to open in CodeBrowser. Re-analysis is not needed if the project was saved.
2. Confirm the MCP plugin is running: `curl http://127.0.0.1:8080/methods` should return a list of function names. If empty/refused: `File → Configure → Miscellaneous → GhidraMCPPlugin` (enable it).
3. Start Claude Code from this project directory. Verify with the assistant that `mcp__ghidra__*` tools are visible.

## Binary state in Ghidra

- `HP39gII.exe` (10MB, x86 PE) loaded with auto-analysis complete
- MFC / MSVC RTTI applied — classes like `CDialog`, `CAspen_cDlg`, `CVirtualLCD` should be recognized
- Most functions still named `FUN_<addr>`; renaming as we discover purpose is part of the work

## Useful starting addresses (verify with MCP once connected)

| What | VA |
|------|-----|
| Entry point | `0x00971CF8` |
| `StretchDIBits` call (sole framebuffer→screen point) | `0x00948B20` |
| `CVirtualLCD::vfunc1` (paint) | `0x0040AA30` |
| `CVirtualLCD::~CVirtualLCD` (destructor) | `0x0040A8D0` |
| Global calculator state object | `0x00DEC9F8` (BSS, runtime only) |
| Screen region descriptor table | `0x00680DA0` (in `.rdata`) |
| `CVirtualLCD` vtable | `0x00A2F47C` |
| `CAspen_cDlg` vtable | `0x00A2E484` |

See `RESEARCH_NOTES.md` for the full set of findings.

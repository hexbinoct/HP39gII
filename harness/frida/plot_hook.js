// Frida hook for HP39gII.exe — discover the plot eval / variable-X path.
// ASLR is OFF (ImageBase 0x400000) so Ghidra static addrs == runtime addrs.
// We still resolve the module base and rebase, in case Windows ever relocates.
//
// Usage (attach to an already-running calc, recommended for a GUI app):
//     frida HP39gII.exe -l plot_hook.js
// Or spawn it so hooks are live from the very first instruction:
//     frida -f HP39gII.exe -l plot_hook.js          (run from the repo root so it finds its DLLs/skins)
//
// Once attached, drive the GUI: define F1(X)=SIN(X), then press Plot.
// In the frida REPL you can type:   rpc.exports.dump()   to print the tally,
//                                   rpc.exports.reset()   to zero counters before pressing Plot.

'use strict';

const STATIC_BASE = ptr('0x400000');     // Ghidra ImageBase
const mod = Process.findModuleByName('HP39gII.exe');
const RUNTIME_BASE = mod ? mod.base : STATIC_BASE;
const slide = RUNTIME_BASE.sub(STATIC_BASE);

console.log('[*] HP39gII.exe base = ' + RUNTIME_BASE + '  (slide ' + slide + ')');

// Map a Ghidra static address to the live runtime address.
function R(staticAddr) { return ptr(staticAddr).add(slide); }

// The anchor functions we already identified statically.
const ANCHORS = {
    'FUN_004157e0 (timer/UI stepper)':      '0x4157e0',
    'FUN_00444a00 (FunctionGrapher show)':  '0x444a00',
    'FUN_00401730 (main loop body)':        '0x401730',
    'FN_TICK FUN_00944270':                 '0x944270',
};

const counts = {};            // name -> call count
const seenBt = {};            // name -> Set of backtrace signatures already printed
const MAX_BT_PER_ANCHOR = 3;  // print at most this many distinct backtraces per anchor

for (const [name, addr] of Object.entries(ANCHORS)) {
    counts[name] = 0;
    seenBt[name] = {};
    const live = R(addr);
    try {
        Interceptor.attach(live, {
            onEnter: function (args) {
                counts[name]++;
                // Capture a few distinct backtraces (who calls this) — rebased to static addrs.
                const btKeys = Object.keys(seenBt[name]);
                if (btKeys.length < MAX_BT_PER_ANCHOR) {
                    const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(a => {
                            // rebase live -> static so it matches Ghidra
                            const s = a.sub(slide);
                            return s;
                        });
                    const sig = bt.map(p => p.toString()).join(',');
                    if (!(sig in seenBt[name])) {
                        seenBt[name][sig] = true;
                        console.log('\n[BT] ' + name + ' call#' + counts[name]);
                        bt.forEach((p, i) => {
                            const sym = DebugSymbol.fromAddress(p.add(slide));
                            console.log('     #' + i + ' static ' + p +
                                (sym && sym.name ? '  (' + sym.name + ')' : ''));
                        });
                    }
                }
            }
        });
        console.log('[+] hooked ' + name + ' @ ' + live);
    } catch (e) {
        console.log('[!] FAILED to hook ' + name + ' @ ' + live + ' : ' + e.message);
    }
}

function dump() {
    console.log('\n========== CALL TALLY ==========');
    for (const name of Object.keys(counts)) {
        console.log('  ' + counts[name].toString().padStart(8) + '  ' + name);
    }
    console.log('================================\n');
}

function reset() {
    for (const name of Object.keys(counts)) { counts[name] = 0; seenBt[name] = {}; }
    console.log('[*] counters reset — now press Plot.');
}

// Auto-tally every 2s so the user sees activity without typing.
setInterval(dump, 2000);

rpc.exports = { dump, reset };

console.log('[*] hooks installed. Drive the GUI: define F1(X)=SIN(X), press Plot.');
console.log('[*] Type  rpc.exports.reset()  before pressing Plot to isolate plot calls.');

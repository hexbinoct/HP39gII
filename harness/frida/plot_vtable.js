// Frida round 3b for HP39gII.exe — find the grapher's PAINT method. SAFE: plain
// Interceptor code hooks only, NO MemoryAccessMonitor (which crashed the app).
//
// FUN_00444a00 builds a FunctionGrapher whose object vtable = 0xa8c1e4 and whose
// renderer sub-vtable (obj+0x78) = 0xa8ba70 / 0xa8ba90. The curve is drawn by a
// vtable method invoked per paint cycle. We read both vtables at runtime, hook
// every entry, and log call counts during the plot. The per-frame PAINT entry
// (and the curve sampler under it) stands out by frequency.
//
// Usage (from repo root):
//     frida -f HP39gII.exe -l harness/frida/plot_vtable.js -o harness/frida/vtable_out.log
// Then: define F1(X)=SIN(X), press Plot. Counts auto-dump every 2s. Move the trace
// cursor / re-plot to make paint-only methods stand out vs one-shot setup methods.

'use strict';

const STATIC_BASE = ptr('0x400000');
const mod = Process.findModuleByName('HP39gII.exe');
const slide = (mod ? mod.base : STATIC_BASE).sub(STATIC_BASE);
const lo = mod ? mod.base : STATIC_BASE;
const hi = lo.add(mod ? mod.size : 0xc00000);
function R(a) { return ptr(a).add(slide); }
function S(a) { return a.sub(slide); }

const VTABLES = {
    'grapher@0xa8c1e4':  R('0xa8c1e4'),
    'renderer@0xa8ba70': R('0xa8ba70'),
    'renderer@0xa8ba90': R('0xa8ba90'),
};
const N_ENTRIES = 32;

const counts = {};   // "vt[idx] static_fn" -> count

function inImage(p) { return p.compare(lo) >= 0 && p.compare(hi) < 0; }

for (const [name, vt] of Object.entries(VTABLES)) {
    for (let i = 0; i < N_ENTRIES; i++) {
        let fn;
        try { fn = vt.add(i * 4).readPointer(); } catch (e) { break; }
        if (fn.isNull() || !inImage(fn)) continue;
        const label = name + '[' + i + '] -> ' + S(fn);
        counts[label] = 0;
        try {
            Interceptor.attach(fn, {
                onEnter: function () { counts[label]++; }
            });
        } catch (e) { /* duplicate addr across vtables is fine */ }
    }
}
console.log('[*] hooked ' + Object.keys(counts).length + ' vtable entries.');

function dump() {
    const rows = Object.entries(counts).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
    if (rows.length === 0) { console.log('[..] no vtable entries hit yet'); return; }
    console.log('\n===== GRAPHER VTABLE CALLS (nonzero) =====');
    rows.forEach(([label, n]) => console.log('  ' + n.toString().padStart(6) + '  ' + label));
    console.log('==========================================\n');
}
function reset() { for (const k in counts) counts[k] = 0; console.log('[*] reset'); }

setInterval(dump, 2000);
rpc.exports = { dump, reset };
console.log('[*] armed. Drive: F1(X)=SIN(X), Plot. Repeated-paint method = the draw path.');

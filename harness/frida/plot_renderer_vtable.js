// Frida round 4 for HP39gII.exe — hook the REAL renderer vtable 0xc1b3f4.
//
// Headless analysis (probe_plot_dispatch.py, 2026-05-27 #9) found the grapher's
// runtime renderer object uses vtable 0xc1b3f4 (Grapher::Sketch::vftable), NOT the
// 0xa8ba70/90 we hooked in round 3b. So we never saw the real-exe behaviour of the
// renderer's draw slots. The full FUN_0093f310 draw dispatch in headless runs every
// gate + renderer[+0x3c]=FUN_0093cc50 + renderer[+0x40]=FUN_0093ede0, yet emits ZERO
// curve pixels — all those methods are clip/region SETUP. So either a deeper sub-call
// or a separate dirty-flag raster pass actually rasterizes, and our headless skips it.
//
// This script: (1) hooks ALL entries of renderer vtable 0xc1b3f4 for call counts, plus
// the grapher vtable 0xa8c1e4 for reference; (2) on each FUN_0093e730 call dumps the
// decimal clip rect host_bridge+0x5d8..0x5e4 and host_bridge+0x5d4/0x5d5 gate bytes, so
// we can DIFF the real exe vs our headless values. SAFE: plain code hooks only, NO
// MemoryAccessMonitor (which crashed the app in round 3 — see #4).
//
// Usage (from repo root):
//     frida -f HP39gII.exe -l harness/frida/plot_renderer_vtable.js -o harness/frida/rvt_out.log
// Then in the calc: define F1(X)=SIN(X), press Plot. Counts + clip dump auto-print
// every 2s. Call exports.reset() before re-plotting to isolate one plot's calls.

'use strict';

const STATIC_BASE = ptr('0x400000');
const mod = Process.findModuleByName('HP39gII.exe');
const slide = (mod ? mod.base : STATIC_BASE).sub(STATIC_BASE);
const lo = mod ? mod.base : STATIC_BASE;
const hi = lo.add(mod ? mod.size : 0xc00000);
function R(a) { return ptr(a).add(slide); }
function S(a) { return a.sub(slide); }
function inImage(p) { return p.compare(lo) >= 0 && p.compare(hi) < 0; }

const HOST_BRIDGE_PP = R('0x00deca00');   // holds ptr to host_bridge struct
const FN_E730 = R('0x0093e730');          // renderer paint core (dumps clip)
const FN_CC50 = R('0x0093cc50');          // renderer +0x3c clip setup

const VTABLES = {
    'renderer@0xc1b3f4': R('0xc1b3f4'),
    'grapher@0xa8c1e4':  R('0xa8c1e4'),
};
const N_ENTRIES = 48;
const counts = {};

for (const [name, vt] of Object.entries(VTABLES)) {
    for (let i = 0; i < N_ENTRIES; i++) {
        let fn;
        try { fn = vt.add(i * 4).readPointer(); } catch (e) { break; }
        if (fn.isNull() || !inImage(fn)) continue;
        const label = name + '[' + i + '] (+0x' + (i * 4).toString(16) + ') -> ' + S(fn);
        counts[label] = 0;
        try { Interceptor.attach(fn, { onEnter() { counts[label]++; } }); } catch (e) {}
    }
}
console.log('[*] hooked ' + Object.keys(counts).length + ' renderer/grapher vtable entries.');

function hb() {
    try { return HOST_BRIDGE_PP.readPointer(); } catch (e) { return ptr(0); }
}
function hex(p, n) {
    try { return p.readByteArray(n); } catch (e) { return '<read fail>'; }
}

// Dump the decimal clip rect + gate bytes whenever the paint core runs.
let dumped = 0;
Interceptor.attach(FN_E730, {
    onEnter() {
        const b = hb();
        if (b.isNull()) return;
        dumped++;
        console.log('\n[FUN_0093e730 paint-core call #' + dumped + ']  host_bridge=' + b);
        console.log('  +0x5d4 gate=' + b.add(0x5d4).readU8() +
                    '  +0x5d5 defer=' + b.add(0x5d5).readU8() +
                    '  +0x5d0=' + b.add(0x5d0).readU32());
        console.log('  decimal clip rect +0x5d8..0x5e8 (16B):');
        console.log(hexdump(b.add(0x5d8).readByteArray(16), { offset: 0, length: 16, header: false }));
    }
});
Interceptor.attach(FN_CC50, { onEnter() { /* counted via vtable too; presence noted */ } });

function dump() {
    const rows = Object.entries(counts).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
    console.log('\n===== RENDERER/GRAPHER VTABLE CALLS (nonzero) =====');
    if (rows.length === 0) console.log('  (none yet — press Plot)');
    rows.forEach(([label, n]) => console.log('  ' + n.toString().padStart(6) + '  ' + label));
    console.log('===================================================\n');
}
function reset() { for (const k in counts) counts[k] = 0; dumped = 0; console.log('[*] reset'); }

setInterval(dump, 2000);
rpc.exports = { dump, reset };
console.log('[*] armed. Drive: define F1(X)=SIN(X), press Plot. Then compare the clip');
console.log('    rect dump + vtable counts here against the headless probe_plot_dispatch.py.');

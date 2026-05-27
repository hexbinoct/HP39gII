// Option-A confirmation: dump the REAL exe's plot screen-transform coefficients.
// Headless (probe_plot_transform.py) found the transform ctx scale(+0x10) & origin(+0x00)
// are ALL-ZERO/UNDEFINED in our Unicorn boot, so every SIN(X) maps to pixel (0,0).
// FUN_00959400(ctx, value) = decimal->screen-pixel transform. On the real exe these
// coefficients MUST be valid nonzero decimals (the plot draws). Confirm by dumping
// ctx+0x00 / +0x10 / +0x40 for the first few calls during a real plot.
//
// Usage: attach to the already-running calc and re-plot (or just nudge a repaint):
//   frida -n HP39gII.exe -l harness/frida/plot_transform_confirm.js -o harness/frida/xform_out.log
// (the run_transform_confirm.py driver does this and streams to xform_out.log)

'use strict';
const STATIC_BASE = ptr('0x400000');
const mod = Process.findModuleByName('HP39gII.exe');
const slide = (mod ? mod.base : STATIC_BASE).sub(STATIC_BASE);
function R(a) { return ptr(a).add(slide); }

const FN_959400 = R('0x959400');
let n = 0;
const MAX = 8;

function dtag(b) {
    const t = b[3] & 0xff;
    return ({0x00: 'UNDEF', 0x01: '+', 0xff: '-', 0x02: 'NaN+', 0xfe: 'NaN-'})[t] || ('0x' + t.toString(16));
}
function dec16(p) {
    const a = new Uint8Array(p.readByteArray(16));
    let h = ''; for (let i = 0; i < 16; i++) h += a[i].toString(16).padStart(2, '0');
    return dtag(a) + ' ' + h;
}

Interceptor.attach(FN_959400, {
    onEnter(args) {
        if (n >= MAX) return;
        n++;
        const ctx = this.context.ecx;        // __thiscall: ECX = transform ctx
        const valp = args[0];                 // first stack arg = value decimal ptr
        try {
            console.log('[FUN_00959400 #' + n + '] ctx=' + ctx);
            console.log('    ctx+0x00 (origin): ' + dec16(ctx.add(0x00)));
            console.log('    ctx+0x10 (scale):  ' + dec16(ctx.add(0x10)));
            console.log('    ctx+0x40 (clamp):  ' + ctx.add(0x40).readU32());
            console.log('    value in:          ' + dec16(valp));
        } catch (e) { console.log('  read fail: ' + e); }
    }
});
console.log('[*] hooked FUN_00959400. Re-plot F1(X)=SIN(X) (or switch view & back) to fire it.');

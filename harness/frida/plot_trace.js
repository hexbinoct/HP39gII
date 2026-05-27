// Frida round 2 for HP39gII.exe — trace the ONE synchronous FUN_00444a00 call
// that draws the plot, and histogram its callees. The per-sample evaluator shows
// up called ~N times (N = number of X samples); the variable-X store sits near it.
//
// Usage (run from repo root so it finds DLLs/skins):
//     frida -f HP39gII.exe -l harness/frida/plot_trace.js -o harness/frida/trace_out.log
// Then drive the GUI: define F1(X)=SIN(X), press Plot. The summary prints on Plot.

'use strict';

const STATIC_BASE = ptr('0x400000');
const mod = Process.findModuleByName('HP39gII.exe');
const BASE = mod ? mod.base : STATIC_BASE;
const slide = BASE.sub(STATIC_BASE);
const lo = BASE;
const hi = BASE.add(mod ? mod.size : 0xc00000);   // image extent
function R(a) { return ptr(a).add(slide); }
function S(a) { return a.sub(slide); }             // runtime -> static

console.log('[*] base=' + BASE + ' size=' + (mod ? mod.size : '?') + ' slide=' + slide);

const GRAPHER = R('0x444a00');
let tracing = false;

Interceptor.attach(GRAPHER, {
    onEnter: function () {
        if (tracing) return;          // ignore re-entrancy
        tracing = true;
        console.log('\n[>] FUN_00444a00 ENTER — following with Stalker...');
        this.followed = Process.getCurrentThreadId();
        Stalker.follow(this.followed, {
            events: { call: true },   // record call events only -> cheap-ish
            onCallSummary: function (summary) {
                // summary: { targetAddr(string) -> count }
                const rows = [];
                for (const addr in summary) {
                    const a = ptr(addr);
                    if (a.compare(lo) >= 0 && a.compare(hi) < 0) {   // in-image only
                        rows.push([S(a), summary[addr]]);
                    }
                }
                rows.sort((x, y) => y[1] - x[1]);
                console.log('\n========== FUN_00444a00 CALLEE HISTOGRAM (top 40, in-image) ==========');
                rows.slice(0, 40).forEach(r => {
                    console.log('  ' + r[1].toString().padStart(7) + '  static ' + r[0]);
                });
                console.log('  ... (' + rows.length + ' distinct in-image targets total)');
                console.log('======================================================================\n');
            }
        });
    },
    onLeave: function () {
        if (this.followed) {
            Stalker.unfollow(this.followed);
            Stalker.flush();          // force onCallSummary to fire
            console.log('[<] FUN_00444a00 LEAVE — Stalker unfollowed.');
            this.followed = null;
            tracing = false;
        }
    }
});

console.log('[*] armed on FUN_00444a00. Drive the GUI: F1(X)=SIN(X), press Plot.');

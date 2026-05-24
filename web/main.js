// Entry point. Phase A: load the EXE, parse PE, populate the keypad.
// Phase B will plug Unicorn-WASM in for the actual boot.

import { parsePE, parseImports } from "./pe-loader.js";
import { boot } from "./loader.js";

const $status = document.getElementById("status");
const $keypad = document.getElementById("keypad");
const $screen = document.getElementById("screen");

function log(msg, cls = "") {
  const line = document.createElement("div");
  if (cls) line.className = cls;
  line.textContent = msg;
  $status.appendChild(line);
  $status.scrollTop = $status.scrollHeight;
}

// 51-key skin map ported from RESEARCH_NOTES.md. Layout chosen to match the
// physical 39gII: 6 columns, soft-menu row at top, navigation cluster, then
// the apps row, then the numeric/operator block.
const KEYS = [
  // row 1: soft menu F1..F6
  { kc: 0,  label: "F1" }, { kc: 1, label: "F2" }, { kc: 2, label: "F3" },
  { kc: 3,  label: "F4" }, { kc: 4, label: "F5" }, { kc: 5, label: "F6" },
  // row 2: apps + arrows
  { kc: 6,  label: "Sym"  }, { kc: 7, label: "Plot" }, { kc: 8, label: "Num" },
  { kc: 9,  label: "↑"     }, { kc: 10, label: "→"   }, { kc: 11, label: "Home" },
  // row 3
  { kc: 12, label: "Apps" }, { kc: 13, label: "View"  }, { kc: 14, label: "←" },
  { kc: 15, label: "↓"    }, { kc: 16, label: "Vars"  }, { kc: 17, label: "Math" },
  // row 4
  { kc: 18, label: "abc"  }, { kc: 19, label: "MENU"  }, { kc: 20, label: "DEL" },
  { kc: 21, label: "Shift" }, { kc: 22, label: "Alpha"  }, { kc: 23, label: "X,T,θ,N" },
  // row 5
  { kc: 24, label: "(" }, { kc: 25, label: ")" }, { kc: 26, label: "," },
  { kc: 27, label: "=" }, { kc: 28, label: "÷" }, { kc: 29, label: "x²" },
  // row 6
  { kc: 30, label: "/", num: true }, { kc: 31, label: "7", num: true },
  { kc: 32, label: "8", num: true }, { kc: 33, label: "9", num: true },
  { kc: 34, label: "×", num: true }, { kc: 35, label: "sin" },
  // row 7
  { kc: 36, label: "Tab" }, { kc: 37, label: "4", num: true }, { kc: 38, label: "5", num: true },
  { kc: 39, label: "6", num: true }, { kc: 40, label: "−", num: true }, { kc: 41, label: "cos" },
  // row 8
  { kc: 42, label: "1", num: true }, { kc: 43, label: "2", num: true }, { kc: 44, label: "3", num: true },
  { kc: 45, label: "+", num: true }, { kc: 46, label: "ON/Esc" }, { kc: 47, label: "0", num: true },
  // row 9
  { kc: 48, label: "(-)" }, { kc: 49, label: ".", num: true }, { kc: 50, label: "ENTER", num: true },
];

function buildKeypad(onKey) {
  $keypad.textContent = "";
  for (const k of KEYS) {
    const b = document.createElement("button");
    b.className = "k" + (k.num ? " num" : "");
    b.textContent = k.label;
    b.dataset.kc = String(k.kc);
    b.disabled = true; // enabled when Unicorn is ready
    b.addEventListener("click", () => onKey(k.kc, k.label));
    $keypad.appendChild(b);
  }
}

function setKeysEnabled(enabled) {
  for (const b of $keypad.querySelectorAll("button.k")) b.disabled = !enabled;
}

async function fetchExe() {
  log("fetching HP39gII.exe ...");
  const res = await fetch("../HP39gII.exe");
  if (!res.ok) throw new Error(`fetch failed: HTTP ${res.status}`);
  const buf = await res.arrayBuffer();
  log(`  ok, ${(buf.byteLength / 1024 / 1024).toFixed(2)} MB`, "ok");
  return buf;
}

async function main() {
  buildKeypad((kc, label) => {
    log(`(key not wired yet) ${label} = ${kc}`, "dim");
  });

  try {
    const buf = await fetchExe();
    log("parsing PE ...");
    const pe = parsePE(buf);
    log(`  image base 0x${pe.imageBase.toString(16)}, size ${(pe.sizeOfImage / 1024).toFixed(0)} KB`, "ok");
    log(`  ${pe.numberOfSections} sections:`);
    for (const s of pe.sections) {
      log(`    ${s.name.padEnd(8)} vaddr 0x${s.virtualAddress.toString(16)}  vsize 0x${s.virtualSize.toString(16)}  rawsize 0x${s.sizeOfRawData.toString(16)}`, "dim");
    }

    log("parsing imports ...");
    const imports = parseImports(pe);
    let total = 0;
    for (const dll of imports) total += dll.imports.length;
    log(`  ${total} imports across ${imports.length} DLLs:`, "ok");
    for (const dll of imports) {
      log(`    ${dll.dll.padEnd(20)} ${dll.imports.length} funcs`, "dim");
    }

    log("");
    log("Phase A complete.", "ok");
    paintPlaceholder();

    log("");
    log("Phase B: booting under Unicorn ...");
    if (typeof uc === "undefined") {
      log("  ERROR: uc global missing. Did unicorn-x86.min.js + unicorn-wrapper.js load?", "err");
      return;
    }
    log(`  Unicorn version ${uc.version ? uc.version() : "(unknown)"}`, "dim");
    const emu = new uc.Unicorn(uc.ARCH_X86, uc.MODE_32);
    const t0 = performance.now();
    try {
      const { shim, finalEip } = boot(emu, new Uint8Array(buf));
      const dt = performance.now() - t0;
      log(`  reached main loop in ${dt.toFixed(0)} ms. EIP=0x${finalEip.toString(16)}`, "ok");
      log(`  heap used: ${(shim.heapPtr - 0x10000000).toLocaleString()} bytes`, "dim");
      log(`  events logged: ${shim.log.length}`, "dim");

      // stash for next phase
      window.__calc = { emu, shim };
      log("");
      log("Phase B complete: calc booted, ready for key injection.", "ok");
    } catch (e) {
      const dt = performance.now() - t0;
      log(`  boot failed after ${dt.toFixed(0)} ms: ${e.message}`, "err");
      console.error(e);
    }
  } catch (e) {
    log("ERROR: " + e.message, "err");
    console.error(e);
  }
}

function paintPlaceholder() {
  const ctx = $screen.getContext("2d");
  const img = ctx.createImageData(256, 127);
  // light-gray HP-LCD background
  for (let i = 0; i < img.data.length; i += 4) {
    img.data[i + 0] = 0x9e;
    img.data[i + 1] = 0xa4;
    img.data[i + 2] = 0x95;
    img.data[i + 3] = 0xff;
  }
  // tiny "loading" text drawn pixel by pixel — just to show the canvas works
  ctx.putImageData(img, 0, 0);
  ctx.fillStyle = "#000";
  ctx.font = "12px monospace";
  ctx.fillText("(headless calc — not booted yet)", 12, 70);
}

main();

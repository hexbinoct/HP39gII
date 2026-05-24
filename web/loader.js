// Port of harness/headless/load.py — orchestrates the Unicorn-side boot.
// Calls into shim.js for handler implementations.

import { parsePE, parseImports, rvaToFileOffset } from "./pe-loader.js";
import { Shim, HANDLERS, HANDLER_ARGC, STDCALL_ARGC, INTERNAL_HOOKS } from "./shim.js";

// --- target binary
export const IMAGE_BASE     = 0x00400000;
export const EXE_PATH_FAKE  = "C:\\fake\\HP39gII.exe";
export const CALC_THREAD_VA = 0x00406430;
export const MAIN_LOOP_VA   = 0x00401730;

// --- sandbox memory layout (matches load.py)
const PAGE       = 0x1000;
export const STACK_BASE   = 0x00100000;
export const STACK_SIZE   = 0x00040000;        // 256 KB
const TIB_BASE   = 0x00200000;
const TIB_SIZE   = PAGE;
const GDT_BASE   = 0x00300000;
const GDT_SIZE   = PAGE;
export const HEAP_BASE    = 0x10000000;
const HEAP_SIZE  = 0x00300000;                 // 3 MB
const TRAMP_BASE = 0x20000000;
const TRAMP_SIZE = 0x00010000;
const SLOTS_BASE = 0x21000000;
const SLOTS_SIZE = 0x00004000;
const INT_TRAMP_BASE = 0x22000000;             // internal-hook trampolines
const INT_TRAMP_SIZE = 0x00001000;
const SENTINEL_PAGE = 0x23000000;
export const SENTINEL_BOOT = 0xDEADBEEF;
export const SENTINEL_HOST_RET = 0x23000000;

// All x86 regs are 4 bytes here
const R = {
  CS: uc.X86_REG_CS, DS: uc.X86_REG_DS, ES: uc.X86_REG_ES,
  SS: uc.X86_REG_SS, FS: uc.X86_REG_FS, GS: uc.X86_REG_GS,
  EAX: uc.X86_REG_EAX, EBX: uc.X86_REG_EBX, ECX: uc.X86_REG_ECX,
  EDX: uc.X86_REG_EDX, ESI: uc.X86_REG_ESI, EDI: uc.X86_REG_EDI,
  EBP: uc.X86_REG_EBP, ESP: uc.X86_REG_ESP, EIP: uc.X86_REG_EIP,
  GDTR: uc.X86_REG_GDTR,
};

// --- helpers: convert numbers <-> Uint8Array of bytes (little-endian) for reg ops
function u32ToBytes(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}
function bytesToU32(b) {
  return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true);
}

export function regWriteU32(emu, regId, val) { emu.reg_write(regId, u32ToBytes(val)); }
export function regReadU32(emu, regId) { return bytesToU32(emu.reg_read(regId, 4)); }

// mem helpers
export function readU32(emu, addr) { return bytesToU32(emu.mem_read(addr, 4)); }
export function writeU32(emu, addr, val) { emu.mem_write(addr, u32ToBytes(val)); }
export function writeU64(emu, addr, big /* BigInt */) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, big), true);
  emu.mem_write(addr, b);
}

// --- GDT entry packing (same as load.py:_gdt_entry)
function gdtEntryBytes(base, limit, access, flags) {
  const b = new Uint8Array(8);
  const dv = new DataView(b.buffer);
  // little-endian:
  dv.setUint16(0, limit & 0xFFFF, true);
  dv.setUint16(2, base & 0xFFFF, true);
  dv.setUint8(4, (base >>> 16) & 0xFF);
  dv.setUint8(5, access & 0xFF);
  dv.setUint8(6, ((limit >>> 16) & 0x0F) | ((flags & 0x0F) << 4));
  dv.setUint8(7, (base >>> 24) & 0xFF);
  return b;
}

export function setupFsSegment(emu) {
  emu.mem_map(TIB_BASE, TIB_SIZE, 7);  // r/w/x
  writeU32(emu, TIB_BASE + 0x00, 0xFFFFFFFF);
  writeU32(emu, TIB_BASE + 0x04, STACK_BASE + STACK_SIZE);
  writeU32(emu, TIB_BASE + 0x08, STACK_BASE);
  writeU32(emu, TIB_BASE + 0x18, TIB_BASE);

  emu.mem_map(GDT_BASE, GDT_SIZE, 7);
  const entries = [
    new Uint8Array(8), // null
    gdtEntryBytes(0, 0xFFFFF, 0x9A, 0xC),       // code, ring0
    gdtEntryBytes(0, 0xFFFFF, 0x92, 0xC),       // data, ring0
    gdtEntryBytes(TIB_BASE, TIB_SIZE - 1, 0x92, 0x4), // fs at TIB
  ];
  for (let i = 0; i < entries.length; i++) {
    emu.mem_write(GDT_BASE + i * 8, entries[i]);
  }

  // uc_x86_mmr layout with natural alignment (24 bytes):
  //   u16 selector at 0; pad to 8; u64 base at 8; u32 limit at 16; u32 flags at 20.
  const gdtr = new Uint8Array(24);
  const dv = new DataView(gdtr.buffer);
  dv.setUint16(0, 0, true);                    // selector
  dv.setBigUint64(8, BigInt(GDT_BASE), true);  // base
  dv.setUint32(16, entries.length * 8 - 1, true); // limit
  dv.setUint32(20, 0, true);                   // flags
  console.log("[gdt] writing GDTR (24 bytes)");
  emu.reg_write(R.GDTR, gdtr);
  console.log("[gdt] GDTR written ok");

  const selCode = 1 << 3;
  const selData = 2 << 3;
  const selFs   = 3 << 3;
  regWriteU32(emu, R.CS, selCode);
  regWriteU32(emu, R.SS, selData);
  regWriteU32(emu, R.DS, selData);
  regWriteU32(emu, R.ES, selData);
  regWriteU32(emu, R.GS, selData);
  regWriteU32(emu, R.FS, selFs);
}

// --- PE load: map image, patch IAT slots with trampoline addresses
export function loadPeIntoEmu(emu, exeBytes) {
  const pe = parsePE(exeBytes.buffer.byteLength === exeBytes.byteLength
    ? exeBytes.buffer
    : exeBytes.buffer.slice(exeBytes.byteOffset, exeBytes.byteOffset + exeBytes.byteLength));

  // map one big chunk covering the whole image (rounded up to a page)
  const imageSize = (pe.sizeOfImage + PAGE - 1) & ~(PAGE - 1);
  emu.mem_map(IMAGE_BASE, imageSize, 7);
  // headers (so anything reading DOS/NT header doesn't fault)
  const headerEnd = pe.sections[0].pointerToRawData;
  emu.mem_write(IMAGE_BASE, new Uint8Array(pe.raw, 0, headerEnd));

  for (const s of pe.sections) {
    const va = IMAGE_BASE + s.virtualAddress;
    const rawSize = Math.min(s.sizeOfRawData, pe.raw.byteLength - s.pointerToRawData);
    if (rawSize > 0) {
      emu.mem_write(va, new Uint8Array(pe.raw, s.pointerToRawData, rawSize));
    }
  }

  // --- IAT trampolines ---
  // Each imported function gets a 16-byte trampoline slot and a 4-byte
  // return-value slot. The trampoline is real x86 code:
  //
  //   MOV EAX, [slot]      (5 bytes: A1 ss ss ss ss)
  //   RET                  (1 byte:  C3)                    -- cdecl
  //  or RET imm16          (3 bytes: C2 nn nn)              -- stdcall
  //
  // When the calc's `CALL [iat_slot]` transfers control here, the code-hook
  // fires at the MOV, computes the return value, writes it to the slot,
  // and returns. The engine then executes MOV EAX, [slot] (reads our value)
  // and the RET. This avoids `reg_write` from inside hooks, which is
  // unreliable in Unicorn 1.x asm.js.
  emu.mem_map(TRAMP_BASE, TRAMP_SIZE, 7);
  emu.mem_map(SLOTS_BASE, SLOTS_SIZE, 7);
  const trampMeta = new Map();   // trampVA -> { name, slotVa, argc }
  const dlls = parseImports(pe);
  let trampNext = TRAMP_BASE;
  let slotNext  = SLOTS_BASE;
  for (const dll of dlls) {
    for (const imp of dll.imports) {
      const name = imp.name || `ord${imp.ordinal}`;
      const slotVa = slotNext; slotNext += 4;
      // Argc: prefer the implemented handler's argc, then the fallback table.
      const argc = HANDLER_ARGC[name] ?? STDCALL_ARGC[name] ?? 0;
      trampMeta.set(trampNext, { name, slotVa, argc });

      // Pre-zero the slot
      writeU32(emu, slotVa, 0);
      // Patch the calc's IAT entry to point at our trampoline
      writeU32(emu, imp.iatVa, trampNext);
      // Emit the trampoline code
      const stub = makeTrampolineStub(slotVa, argc);
      emu.mem_write(trampNext, stub);

      trampNext += 0x10;
    }
  }
  console.log(`[load] ${trampMeta.size} IAT trampolines emitted, ${slotNext - SLOTS_BASE} bytes of slots`);

  // --- Sentinel page for call_emu host returns ---
  emu.mem_map(SENTINEL_PAGE, PAGE, 7);
  emu.mem_write(SENTINEL_HOST_RET, new Uint8Array([0xC3])); // safety RET

  return { pe, trampMeta, dlls };
}

// Build the bytes for an IAT/internal trampoline that loads its return value
// from `slotVa` and returns. For stdcall functions (argc > 0), the RET is
// `RET imm16` which also pops the args.
function makeTrampolineStub(slotVa, argc) {
  const bytes = [
    0xA1,                                                       // MOV EAX, [slot]
    slotVa & 0xff, (slotVa >>> 8) & 0xff, (slotVa >>> 16) & 0xff, (slotVa >>> 24) & 0xff,
  ];
  if (argc > 0) {
    const pop = argc * 4;
    bytes.push(0xC2, pop & 0xff, (pop >>> 8) & 0xff);   // RET imm16
  } else {
    bytes.push(0xC3);                                          // RET
  }
  return new Uint8Array(bytes);
}

// --- Wire up the unified code hook: trampolines, internal hooks, sentinels.
// The hook NEVER touches registers — it only writes return values into the
// pre-allocated memory slot that the trampoline's `MOV EAX, [slot]` reads.
export function installDispatcher(emu, shim, trampMeta, internalMeta, onHaltMainLoop) {
  let hookFireCount = 0;
  globalThis.__hookFireCount = () => hookFireCount;

  emu.hook_add(uc.HOOK_CODE, (handle, addrLo, addrHi, size, _ud) => {
    const address = addrLo >>> 0;
    hookFireCount++;

    if (address === SENTINEL_BOOT || address === SENTINEL_HOST_RET) {
      emu.emu_stop();
      return;
    }
    if (address === MAIN_LOOP_VA) {
      if (onHaltMainLoop) onHaltMainLoop();
      emu.emu_stop();
      return;
    }

    // Internal calc-side hook (cdecl)
    const internal = internalMeta.get(address);
    if (internal) {
      const esp = regReadU32(emu, R.ESP);
      const args = [];
      for (let i = 0; i < 8; i++) args.push(readU32(emu, esp + 4 + i * 4));
      const retVal = internal.fn(shim, args) >>> 0;
      writeU32(emu, internal.slotVa, retVal);
      const verify = readU32(emu, internal.slotVa);
      shim.trace(`  [internal] ${internal.name}([${args.slice(0,2).join(",")}]) -> 0x${retVal.toString(16)} (slot 0x${internal.slotVa.toString(16)} = 0x${verify.toString(16)})`, internal.name);
      return;
    }

    // IAT trampoline (stdcall — RET imm16 cleans args)
    const meta = trampMeta.get(address);
    if (meta !== undefined) {
      const esp = regReadU32(emu, R.ESP);
      const args = [];
      for (let i = 0; i < 8; i++) args.push(readU32(emu, esp + 4 + i * 4));

      let retVal = 0;
      const handler = HANDLERS[meta.name];
      if (handler) {
        const [hRet, hArgc] = handler(shim, args);
        retVal = hRet;
        if (hArgc !== meta.argc) {
          // The trampoline was emitted with STDCALL_ARGC's argc; if the
          // handler disagrees, the stack will be off by 4*(diff) bytes
          // after this call. Surface it loudly.
          shim.trace(`  [WARN] argc mismatch for ${meta.name}: trampoline=${meta.argc} handler=${hArgc}`, meta.name);
        }
      } else {
        retVal = 0;
        shim.trace(`  ?? ${meta.name}(args~=[${args.slice(0,4).join(",")}]) -> 0  argc=${meta.argc}`, meta.name);
      }
      writeU32(emu, meta.slotVa, retVal);
    }
  }, {}, 1, 0);

  // Fault logger — return false so Unicorn raises the error
  emu.hook_add(
    uc.HOOK_MEM_READ_UNMAPPED | uc.HOOK_MEM_WRITE_UNMAPPED | uc.HOOK_MEM_FETCH_UNMAPPED,
    (handle, type, addrLo, addrHi, size, valLo, valHi, _ud) => {
      const eip = regReadU32(emu, R.EIP);
      const eax = regReadU32(emu, R.EAX);
      const ebx = regReadU32(emu, R.EBX);
      const ecx = regReadU32(emu, R.ECX);
      const esp = regReadU32(emu, R.ESP);
      shim.trace(`[fault] type=${type} addr=0x${addrLo.toString(16)} size=${size} EIP=0x${eip.toString(16)} EAX=0x${eax.toString(16)} EBX=0x${ebx.toString(16)} ECX=0x${ecx.toString(16)} ESP=0x${esp.toString(16)}`);
      return false;
    },
    {}, 1, 0
  );
}

// --- The boot driver: replicates load.py:main() + M2/M3 fixups.
export function boot(emu, exeBytes) {
  console.log("[boot] mapping stack/heap ...");
  emu.mem_map(STACK_BASE, STACK_SIZE, 7);
  emu.mem_map(HEAP_BASE, HEAP_SIZE, 7);

  console.log("[boot] loading PE ...");
  const { trampMeta } = loadPeIntoEmu(emu, exeBytes);
  console.log("[boot] setting up FS segment ...");
  setupFsSegment(emu);

  // Set up internal hooks. Unicorn 1.x asm.js caches/won't honor instruction
  // bytes overwritten inside the loaded PE image — even simple `MOV EAX, imm32`
  // there reads back as 0 from the engine's POV. Workaround: place the
  // actual trampoline code in a fresh, separately-mapped region, and write
  // only a 5-byte `JMP rel32` at the calc-image hook site. The JMP itself
  // we cross our fingers that *control transfer* works even if the bytes
  // were rewritten — and empirically it does.
  emu.mem_map(INT_TRAMP_BASE, INT_TRAMP_SIZE, 7);
  const internalMeta = new Map();
  let intSlot = SLOTS_BASE + 0x2000;
  let intTramp = INT_TRAMP_BASE;
  for (const vaKey of Object.keys(INTERNAL_HOOKS)) {
    const va = Number(vaKey);
    const slotVa = intSlot; intSlot += 4;
    const trampVa = intTramp; intTramp += 0x10;
    const meta = { ...INTERNAL_HOOKS[va], slotVa, trampVa };
    internalMeta.set(va, meta);  // hook key is the CALC-SIDE JMP address —
    // we want the hook to fire BEFORE the trampoline runs, so the engine's
    // execution of MOV EAX, [slot] inside the trampoline isn't sandwiched
    // between hook callbacks (which seems to break register sync in 1.x asm.js).
    writeU32(emu, slotVa, 0);
    // Trampoline in fresh region: MOV EAX, [slot]; RET
    emu.mem_write(trampVa, makeTrampolineStub(slotVa, 0));
    // Patch the calc-side function entry with JMP rel32 to the trampoline
    const disp = trampVa - (va + 5);
    const jmp = new Uint8Array([0xE9, disp & 0xff, (disp>>>8)&0xff, (disp>>>16)&0xff, (disp>>>24)&0xff]);
    emu.mem_write(va, jmp);
    console.log(`  hook ${meta.name} @ 0x${va.toString(16)} -> JMP 0x${trampVa.toString(16)}, slot=0x${slotVa.toString(16)}`);
  }
  console.log(`[boot] ${internalMeta.size} internal hooks installed`);

  console.log("[boot] creating shim ...");
  const shim = new Shim(emu);
  let reachedMainLoop = false;
  console.log("[boot] installing dispatcher ...");
  installDispatcher(emu, shim, trampMeta, internalMeta, () => { reachedMainLoop = true; });

  console.log("[boot] M2 fixups ...");
  const dummyDlg = shim.malloc(0x400);
  writeU32(emu, 0x00DEB7E4, dummyDlg);
  writeU64(emu, 0x00DFDCA8, 1n);
  console.log("[boot] M2 fixups done");

  // Set up the thread call: push arg=NULL, push sentinel return addr
  let esp = STACK_BASE + STACK_SIZE - 0x100;
  esp -= 4; writeU32(emu, esp, 0);
  esp -= 4; writeU32(emu, esp, SENTINEL_BOOT);
  regWriteU32(emu, R.ESP, esp);
  regWriteU32(emu, R.EBP, 0);

  // Run. Generous instruction budget — boot was ~4M in Python.
  // Emscripten 1.x asm.js emulates setjmp/longjmp by throwing the string
  // "longjmp". Calling emu_stop() from inside a hook triggers it — that's
  // our normal halt path, not an error, so swallow it.
  console.log("[boot] starting emu ...");
  // With the mem-write trampoline strategy, the engine doesn't get stopped
  // mid-flight by EIP modifications — emu_start runs straight through until
  // it reaches MAIN_LOOP_VA (where the hook calls emu_stop) or faults.
  try {
    emu.emu_start(CALC_THREAD_VA, 0, 0, 0);
  } catch (e) {
    if (e === "longjmp" || e?.message === "longjmp") {
      // Normal halt: emu_stop from a hook throws "longjmp" via emscripten's
      // setjmp/longjmp emulation.
    } else if (typeof e === "string" && e.includes("uc_emu_start failed")) {
      const eip = regReadU32(emu, R.EIP);
      console.log(`[boot] FAULT EIP=0x${eip.toString(16)}: ${e.split("\\n")[1] || e}`);
      for (const l of shim.log.slice(-10)) console.log("  " + l);
      // Inspect the mutex handle storage to see if CreateMutexW's EAX reached it
      const mutexHandle = readU32(emu, 0x00DEB828);
      console.log(`  [diag] DEB828 (CreateMutexW handle) = 0x${mutexHandle.toString(16)} (expected 0x80000001)`);
      throw new Error(`emu fault at EIP=0x${eip.toString(16)}`);
    } else throw e;
  }

  console.log("[boot] reading final EIP ...");
  const finalEip = regReadU32(emu, R.EIP);
  console.log("[boot] finalEip =", "0x" + finalEip.toString(16),
              "reachedMainLoop =", reachedMainLoop,
              "instructions =", globalThis.__hookFireCount?.());
  if (!reachedMainLoop) {
    throw new Error(`boot did not reach main loop. final EIP=0x${finalEip.toString(16)}`);
  }

  // Post-boot fixup for M3: font count
  const bridge = readU32(emu, 0x00DECA00);
  writeU32(emu, bridge + 0x584, 1);

  return { shim, finalEip };
}

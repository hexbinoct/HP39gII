// Minimal PE parser — just enough for the headless calc port.
// Mirrors the subset of pefile.py we used in harness/headless/load.py.

const DOS_E_LFANEW = 0x3c;

export function parsePE(buf) {
  const dv = new DataView(buf);
  if (dv.getUint16(0, true) !== 0x5a4d) {
    throw new Error("not a PE: MZ signature missing");
  }
  const peOff = dv.getUint32(DOS_E_LFANEW, true);
  if (dv.getUint32(peOff, true) !== 0x00004550) {
    throw new Error("not a PE: PE\\0\\0 signature missing");
  }

  // COFF header (20 bytes) at peOff+4
  const coff = peOff + 4;
  const machine          = dv.getUint16(coff + 0, true);
  const numberOfSections = dv.getUint16(coff + 2, true);
  const sizeOfOptional   = dv.getUint16(coff + 16, true);

  // Optional header
  const opt = coff + 20;
  const magic = dv.getUint16(opt, true);
  if (magic !== 0x010b) {
    throw new Error(`expected PE32 (magic 0x10b), got 0x${magic.toString(16)}`);
  }
  const sizeOfImage = dv.getUint32(opt + 56, true);
  const imageBase   = dv.getUint32(opt + 28, true);

  // Data directories start at opt + 96 (for PE32). DIRECTORY_ENTRY_IMPORT is index 1.
  const importDirRva  = dv.getUint32(opt + 96 + 1 * 8, true);
  const importDirSize = dv.getUint32(opt + 96 + 1 * 8 + 4, true);

  // Section table follows the optional header.
  const sectionTable = opt + sizeOfOptional;
  const sections = [];
  for (let i = 0; i < numberOfSections; i++) {
    const e = sectionTable + i * 40;
    const nameBytes = new Uint8Array(buf, e, 8);
    let name = "";
    for (const b of nameBytes) { if (b === 0) break; name += String.fromCharCode(b); }
    sections.push({
      name,
      virtualSize:    dv.getUint32(e + 8,  true),
      virtualAddress: dv.getUint32(e + 12, true),
      sizeOfRawData:  dv.getUint32(e + 16, true),
      pointerToRawData: dv.getUint32(e + 20, true),
      characteristics: dv.getUint32(e + 36, true),
    });
  }

  return {
    raw: buf,
    machine, numberOfSections, sizeOfImage, imageBase,
    sections,
    importDirRva, importDirSize,
  };
}

// Translate a relative VA (offset from imageBase) to a raw file offset.
export function rvaToFileOffset(pe, rva) {
  for (const s of pe.sections) {
    if (rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.sizeOfRawData)) {
      return s.pointerToRawData + (rva - s.virtualAddress);
    }
  }
  return null;
}

// Read a null-terminated ASCII string at file offset.
function cstr(buf, off, max = 256) {
  const u8 = new Uint8Array(buf, off, Math.min(max, buf.byteLength - off));
  let s = "";
  for (const b of u8) { if (b === 0) break; s += String.fromCharCode(b); }
  return s;
}

// Walk the import directory table. Returns array of
//   { dll: "KERNEL32.dll", imports: [ { name, ordinal, iatVa }... ] }
export function parseImports(pe) {
  if (pe.importDirRva === 0) return [];
  const dv = new DataView(pe.raw);
  let cursor = rvaToFileOffset(pe, pe.importDirRva);
  const dlls = [];

  while (true) {
    const oftRva    = dv.getUint32(cursor + 0, true);  // OriginalFirstThunk
    const nameRva   = dv.getUint32(cursor + 12, true);
    const firstThunkRva = dv.getUint32(cursor + 16, true);  // FirstThunk = IAT
    if (nameRva === 0 && firstThunkRva === 0) break;

    const dllName = cstr(pe.raw, rvaToFileOffset(pe, nameRva));
    const imports = [];

    // Walk both INT (OFT) and IAT in parallel. INT tells us if it's ordinal
    // or by-name; IAT is where the loader writes the resolved address (and
    // where we need to write our trampoline).
    let intOff = oftRva ? rvaToFileOffset(pe, oftRva) : rvaToFileOffset(pe, firstThunkRva);
    const iatBase = pe.imageBase + firstThunkRva;
    let slot = 0;
    while (true) {
      const entry = dv.getUint32(intOff, true);
      if (entry === 0) break;
      const iatVa = iatBase + slot * 4;
      if (entry & 0x80000000) {
        imports.push({ name: null, ordinal: entry & 0xffff, iatVa });
      } else {
        // by-name: entry is RVA to a hint+name (Hint:WORD, Name:ASCIIZ)
        const hintOff = rvaToFileOffset(pe, entry);
        imports.push({ name: cstr(pe.raw, hintOff + 2), ordinal: null, iatVa });
      }
      intOff += 4;
      slot++;
    }

    dlls.push({ dll: dllName, imports });
    cursor += 20; // IMAGE_IMPORT_DESCRIPTOR size
  }
  return dlls;
}

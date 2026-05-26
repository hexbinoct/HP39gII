#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

// Calculator display geometry (decoded grayscale).
constexpr int HP39_FB_W = 256;
constexpr int HP39_FB_H = 127;

// Boot the HP39gII calc core under Unicorn from an in-memory copy of the PE.
// Mirrors harness/headless/load.py: maps the image, shims Win32, drives
// FUN_00406430 to the main-loop entry FUN_00401730, then leaves the VM live so
// keys can be injected. Returns a boot log (ends with "calc booted" on success).
// data_dir is a writable directory (the app's filesDir) that backs the guest
// filesystem so the calc can create/read its per-aplet state files.
std::string hp39_boot(const uint8_t *exe, size_t len, const char *data_dir);

// True once the calc has booted and the VM is ready for key injection.
bool hp39_booted();

// Inject one keypress (HP keycode 0..50) and repaint, mirroring
// m3_one_plus_one.py: enqueue_event -> press_key -> drain+tick ->
// release_key -> drain+tick.
void hp39_inject_key(int keycode);

// Fill `out` (>= HP39_FB_W * HP39_FB_H bytes) with the current framebuffer as
// 8-bit grayscale (0/85/170/255). Returns false if not booted.
bool hp39_get_framebuffer(uint8_t *out);

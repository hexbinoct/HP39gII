#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

// Boot the HP39gII calc core under Unicorn from an in-memory copy of the PE.
// Mirrors harness/headless/load.py: maps the image, shims Win32, drives
// FUN_00406430 until it reaches the main-loop entry FUN_00401730. Returns a
// human-readable boot log (ends with "calc booted" on success).
std::string hp39_boot(const uint8_t *exe, size_t len);

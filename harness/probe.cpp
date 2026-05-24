// probe.dll — injected into HP39gII.exe to drive calc input by VA and dump framebuffer.
// Validates the input/state/output journey discovered via Ghidra (see ../RESEARCH_NOTES.md).

#include <windows.h>
#include <cstdio>
#include <cstdint>

// VAs from Ghidra (image base 0x00400000). Translated at runtime through the actual base.
static constexpr uintptr_t VA_BASE           = 0x00400000;
static constexpr uintptr_t VA_PRESS_KEY      = 0x0043BE90;
static constexpr uintptr_t VA_RELEASE_KEY    = 0x0043BED0;
static constexpr uintptr_t VA_ENQUEUE_EVENT  = 0x00941210;  // __thiscall(EventQueue*, evt_type, payload8)
static constexpr uintptr_t VA_CALC_STATE_PTR = 0x00DEC9F8;  // global slot holding the CDesktop* state pointer
static constexpr uintptr_t VA_KEYMASK_LO     = 0x00DFDC88;  // 64-bit keyboard bitmask low
static constexpr uintptr_t VA_KEYMASK_HI     = 0x00DFDC8C;  // ... high
static constexpr uintptr_t VA_EVENT_QUEUE_PTR = 0x00DECA08; // *0xDECA08 = EventQueue* (alloc'd in FUN_00406430 size 0x88)

static FILE* g_log = nullptr;

template <typename T>
static T at(uintptr_t va) {
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    return reinterpret_cast<T>(base + (va - VA_BASE));
}

// press_key / release_key are __cdecl — keycode loaded from [ESP+4], plain RET.
typedef void (__cdecl* fn_key_t)(int keycode);
// enqueue_event is __thiscall — this in ECX, 2 dword args on stack, callee cleans (RET 0x8).
typedef int (__thiscall* fn_enqueue_t)(void* this_, uint32_t event_type, const void* payload8);

static void log_msg(const char* fmt, ...) {
    if (!g_log) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fflush(g_log);
}

static void dump_framebuffer(const char* tag) {
    uintptr_t* state_loc = at<uintptr_t*>(VA_CALC_STATE_PTR);
    uintptr_t state = *state_loc;
    if (!state) {
        log_msg("[%s] calc state pointer is NULL — init thread not done yet\n", tag);
        return;
    }
    int width  = *reinterpret_cast<int*>(state + 0x0C);
    int height = *reinterpret_cast<int*>(state + 0x10);
    uint8_t* fb14 = *reinterpret_cast<uint8_t**>(state + 0x14);
    uint8_t* fb5c = *reinterpret_cast<uint8_t**>(state + 0x5C);
    int pitch  = *reinterpret_cast<int*>(state + 0x28);
    uint32_t keymask_lo = *at<uint32_t*>(VA_KEYMASK_LO);
    uint32_t keymask_hi = *at<uint32_t*>(VA_KEYMASK_HI);
    log_msg("[%s] state=0x%p w=%d h=%d pitch=%d fb@+0x14=0x%p fb@+0x5C=0x%p keymask=0x%08X%08X same=%d\n",
            tag, reinterpret_cast<void*>(state), width, height, pitch,
            reinterpret_cast<void*>(fb14), reinterpret_cast<void*>(fb5c),
            keymask_hi, keymask_lo, fb14 == fb5c);
    if (!fb14 || width <= 0 || height <= 0 || pitch <= 0) return;

    // Write BOTH potential framebuffers to disk for comparison.
    char fname[64];
    snprintf(fname, sizeof(fname), "fb14_%s.bin", tag);
    if (FILE* f = fopen(fname, "wb")) {
        fwrite(fb14, 1, static_cast<size_t>(height) * pitch, f);
        fclose(f);
    }
    if (fb5c && fb5c != fb14) {
        snprintf(fname, sizeof(fname), "fb5c_%s.bin", tag);
        if (FILE* f = fopen(fname, "wb")) {
            fwrite(fb5c, 1, static_cast<size_t>(height) * pitch, f);
            fclose(f);
        }
    }
    uint8_t* fb = fb14;  // continue ASCII dump on +0x14 (will switch if proven wrong)

    // Tentative ASCII dump assuming 2 bits/pixel, 3 pixels packed per byte,
    // bit layout AABBCC?? (high bits first). We'll iterate this if the picture comes out wrong.
    static const char shades[] = " .oO";
    log_msg("[%s] ASCII dump (layout guess: bits AABBCC.., shades \" .oO\"):\n", tag);
    for (int y = 0; y < height; y++) {
        log_msg("|");
        for (int b = 0; b < pitch; b++) {
            uint8_t byte = fb[y * pitch + b];
            int p0 = (byte >> 6) & 3;
            int p1 = (byte >> 4) & 3;
            int p2 = (byte >> 2) & 3;
            fputc(shades[p0], g_log);
            fputc(shades[p1], g_log);
            fputc(shades[p2], g_log);
        }
        log_msg("|\n");
    }
    log_msg("\n");
}

static void press_release(fn_enqueue_t enqueue, fn_key_t press, fn_key_t release,
                          int keycode, const char* label) {
    log_msg("=== press/release keycode %d (%s) ===\n", keycode, label);
    uint32_t* km_lo = at<uint32_t*>(VA_KEYMASK_LO);
    uint32_t* km_hi = at<uint32_t*>(VA_KEYMASK_HI);

    // Mirror the dialog wrapper FUN_00401C40 exactly:
    //   ECX = *(0x00DECA08)
    //   payload[0..3] = 1, payload[4] = keycode  (rest 0)
    //   enqueue(queue, 0, payload)
    //   press_key(keycode)
    void* queue = *at<void**>(VA_EVENT_QUEUE_PTR);
    uint8_t payload[8] = {0};
    payload[0] = 1;
    payload[4] = static_cast<uint8_t>(keycode);
    log_msg("  enqueue queue=%p event_type=0 payload=01 00 00 00 %02X 00 00 00\n", queue, keycode);
    int enq_rc = enqueue(queue, 0, payload);
    log_msg("  enqueue returned %d (1=ok, 0=queue full)\n", enq_rc);

    log_msg("  pre-press keymask=0x%08X%08X\n", *km_hi, *km_lo);
    press(keycode);
    log_msg("  post-press keymask=0x%08X%08X\n", *km_hi, *km_lo);
    Sleep(400);
    log_msg("  after 400ms     keymask=0x%08X%08X\n", *km_hi, *km_lo);
    release(keycode);
    log_msg("  post-release keymask=0x%08X%08X\n", *km_hi, *km_lo);
    Sleep(600);
    char tag[32];
    snprintf(tag, sizeof(tag), "after_%s", label);
    dump_framebuffer(tag);
}

static DWORD WINAPI worker(LPVOID) {
    // Open log in the working directory (same place HP39gII.exe was launched from).
    fopen_s(&g_log, "probe.log", "w");
    if (!g_log) return 1;

    log_msg("=== probe.dll worker started, sleeping 3s for calc init ===\n");
    Sleep(3000);

    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    log_msg("HP39gII.exe image base = 0x%p (preferred 0x%p, delta 0x%X)\n",
            reinterpret_cast<void*>(base), reinterpret_cast<void*>(VA_BASE),
            static_cast<unsigned>(base - VA_BASE));

    dump_framebuffer("initial");

    auto press   = at<fn_key_t>(VA_PRESS_KEY);
    auto release = at<fn_key_t>(VA_RELEASE_KEY);
    auto enqueue = at<fn_enqueue_t>(VA_ENQUEUE_EVENT);
    log_msg("press_key=%p release_key=%p enqueue=%p queue=%p\n",
            press, release, enqueue, *at<void**>(VA_EVENT_QUEUE_PTR));

    press_release(enqueue, press, release, 42, "key_1");
    press_release(enqueue, press, release, 45, "key_plus");
    press_release(enqueue, press, release, 42, "key_1_again");
    press_release(enqueue, press, release, 50, "key_enter");

    log_msg("=== probe done — keep HP39gII window open to compare visually ===\n");
    fclose(g_log);
    g_log = nullptr;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Spawn from DllMain — keep this thread's work minimal to avoid loader lock issues.
        CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    }
    return TRUE;
}

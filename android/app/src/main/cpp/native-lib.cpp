#include <jni.h>
#include <string>
#include <vector>
#include <unicorn/unicorn.h>
#include "emu.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_hexbinoct_hp39gii_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

// Phase A self-test: spin up a Unicorn x86 (32-bit) VM, run a tiny program,
// and read back a register. Proves the engine is linked AND executes guest
// code on this device's CPU. Returns a human-readable status string.
extern "C" JNIEXPORT jstring JNICALL
Java_com_hexbinoct_hp39gii_MainActivity_unicornSelfTest(
        JNIEnv* env,
        jobject /* this */) {
    const uint64_t ADDR = 0x1000;
    // mov eax, 0x29 ; inc eax  -> eax should become 0x2a (42)
    const uint8_t CODE[] = { 0xb8, 0x29, 0x00, 0x00, 0x00, 0x40 };

    uc_engine *uc = nullptr;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
        std::string s = "uc_open failed: ";
        s += uc_strerror(err);
        return env->NewStringUTF(s.c_str());
    }

    char buf[160];
    unsigned int major = 0, minor = 0;
    uc_version(&major, &minor);

    uc_mem_map(uc, ADDR, 0x1000, UC_PROT_ALL);
    uc_mem_write(uc, ADDR, CODE, sizeof(CODE));

    err = uc_emu_start(uc, ADDR, ADDR + sizeof(CODE), 0, 0);
    if (err != UC_ERR_OK) {
        snprintf(buf, sizeof(buf), "Unicorn %d.%d: emu_start failed: %s",
                 major, minor, uc_strerror(err));
        uc_close(uc);
        return env->NewStringUTF(buf);
    }

    int eax = 0;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_close(uc);

    snprintf(buf, sizeof(buf),
             "Unicorn %u.%u OK\nRan x86: 0x29 + inc -> EAX = 0x%x (%d)\n%s",
             major, minor, eax, eax, (eax == 0x2a) ? "PASS" : "FAIL");
    return env->NewStringUTF(buf);
}

// Phase B: load HP39gII.exe (passed as a byte[]) and boot the calc core
// headless under Unicorn, returning the boot log.
extern "C" JNIEXPORT jstring JNICALL
Java_com_hexbinoct_hp39gii_MainActivity_nativeBoot(
        JNIEnv* env,
        jobject /* this */,
        jbyteArray exe) {
    jsize len = env->GetArrayLength(exe);
    std::vector<uint8_t> buf(len);
    env->GetByteArrayRegion(exe, 0, len, reinterpret_cast<jbyte*>(buf.data()));
    std::string out = hp39_boot(buf.data(), (size_t)len);
    return env->NewStringUTF(out.c_str());
}

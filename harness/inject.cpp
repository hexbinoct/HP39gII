// inject.exe — launches HP39gII.exe and injects probe.dll via CreateRemoteThread(LoadLibraryA).
// Both this and probe.dll must be built 32-bit (HP39gII.exe is 32-bit x86).

#include <windows.h>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    const char* exe = "HP39gII.exe";
    const char* dll = "probe.dll";
    if (argc >= 2) exe = argv[1];
    if (argc >= 3) dll = argv[2];

    char dll_abs[MAX_PATH];
    if (!GetFullPathNameA(dll, MAX_PATH, dll_abs, nullptr)) {
        fprintf(stderr, "GetFullPathName(%s) failed: %lu\n", dll, GetLastError());
        return 1;
    }
    char exe_abs[MAX_PATH];
    if (!GetFullPathNameA(exe, MAX_PATH, exe_abs, nullptr)) {
        fprintf(stderr, "GetFullPathName(%s) failed: %lu\n", exe, GetLastError());
        return 1;
    }
    // Working directory = exe's directory, so the calc can find its skins next to itself.
    char workdir[MAX_PATH];
    strncpy(workdir, exe_abs, MAX_PATH);
    workdir[MAX_PATH - 1] = '\0';
    char* slash = strrchr(workdir, '\\');
    if (slash) *slash = '\0';

    printf("exe : %s\n", exe_abs);
    printf("dll : %s\n", dll_abs);
    printf("cwd : %s\n", workdir);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(exe_abs, nullptr, nullptr, nullptr, FALSE,
                        0, nullptr, workdir, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("launched pid=%lu, sleeping 500ms so kernel32 is mapped...\n", pi.dwProcessId);
    Sleep(500);

    size_t pathlen = strlen(dll_abs) + 1;
    LPVOID remote_path = VirtualAllocEx(pi.hProcess, nullptr, pathlen,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_path) {
        fprintf(stderr, "VirtualAllocEx failed: %lu\n", GetLastError());
        return 1;
    }
    if (!WriteProcessMemory(pi.hProcess, remote_path, dll_abs, pathlen, nullptr)) {
        fprintf(stderr, "WriteProcessMemory failed: %lu\n", GetLastError());
        return 1;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLL = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(k32, "LoadLibraryA"));
    HANDLE th = CreateRemoteThread(pi.hProcess, nullptr, 0, pLL, remote_path, 0, nullptr);
    if (!th) {
        fprintf(stderr, "CreateRemoteThread failed: %lu\n", GetLastError());
        return 1;
    }
    printf("injection thread started, waiting for LoadLibrary to return...\n");
    WaitForSingleObject(th, 5000);
    DWORD exitcode = 0;
    GetExitCodeThread(th, &exitcode);
    printf("LoadLibrary returned 0x%lX (0 = failed, otherwise = HMODULE in target)\n", exitcode);
    CloseHandle(th);
    VirtualFreeEx(pi.hProcess, remote_path, 0, MEM_RELEASE);

    printf("\nHP39gII.exe pid %lu is now running. inject.exe exiting; manage the calc's lifetime externally.\n",
           pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

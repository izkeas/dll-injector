// ConsoleApplication2.cpp : Este arquivo contém a função 'main'. A execução do programa começa e termina ali.
// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

using namespace std;

DWORD getProcId(const char* procName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // tirar uma snapshot de todos os processos do sistema

    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry); // iniciar dwsize

        if (Process32First(hSnap, &procEntry)) { // pegar o primeiro processo

            while (Process32Next(hSnap, &procEntry)) { // loopar por todos os processos
                if (_stricmp(procEntry.szExeFile, procName) == 0) { // se o nome do processo for igual ao procname
                    CloseHandle(hSnap);
                    return procEntry.th32ProcessID;
                    break;
                }
            }
        }
    }

    return NULL;
}


int main(int argc, char* argv[])
{
    const char* process_name = argv[1];
    const char* dll = argv[2];
    char dllpath[MAX_PATH] = { 0 };

    DWORD procId = getProcId(process_name);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, procId);

    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        printf("[-] Error Can't find process: %s\n", process_name);
        exit(1);
    }
    printf("[*] Process Found %s id: %d\n",process_name, procId);

    if (GetFullPathNameA(dll, MAX_PATH, dllpath, NULL) == 0) {
        printf("[-] Error Can't find dll.\n");
        exit(1);
    }
    printf("[*] Dll %s successfully loaded\n", dllpath);

    // Alloc dll into process
    LPVOID loc = VirtualAllocEx(hProcess, NULL, strlen(dllpath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (loc == NULL) {
        printf("[-] Error can't alocate dll\n");
        exit(1);
    }

    // Write dll into process
    WriteProcessMemory(hProcess, loc, dllpath, strlen(dllpath) + 1, NULL);
    void* loadLibrary = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"); // Get loadLibraryA inside kernel32 that is inside the process

    printf("[*] Virtual dll memory alocated on adress %p of process %s\n", loc, process_name);

    // Execute loadlibraryA inside the process with param loc
    HANDLE remoteThreadHandler = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary, loc, 0, NULL);
    if (remoteThreadHandler == NULL) {
        printf("[-] Cant create remote thread in process %d\n", procId);
        exit(1);
    }
    printf("[*] Remote thread created!\n");
    printf("[*] Done.\n");

    WaitForSingleObject(remoteThreadHandler, INFINITE);
    CloseHandle(remoteThreadHandler);
    VirtualFreeEx(hProcess, loc, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

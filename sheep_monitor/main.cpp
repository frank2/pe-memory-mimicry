#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cassert>
#include <optional>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#define VA_TO_RVA(base, va) (((std::uintptr_t)va) - ((std::uintptr_t)base))

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _LDR_DATA_TABLE_ENTRY_EX {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY_EX, * PLDR_DATA_TABLE_ENTRY_EX;

typedef struct _PEB_LDR_DATA_EX {
   ULONG                   Length;
   ULONG                   Initialized;
   PVOID                   SsHandle;
   LIST_ENTRY              InLoadOrderModuleList;
   LIST_ENTRY              InMemoryOrderModuleList;
   LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA_EX, * PPEB_LDR_DATA_EX;

typedef struct _PEB_EX {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA_EX        LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB_EX, * PPEB_EX;

void exit_thread(void) {
   ExitThread(0);
}

PIMAGE_NT_HEADERS64 get_nt_headers(std::uint8_t *base) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
   return (PIMAGE_NT_HEADERS64)&base[dos_header->e_lfanew];
}

struct SheepConfig {
   std::uintptr_t image_base;
   std::size_t max_sheep;
};

SheepConfig *GLOBAL_CONFIG = nullptr;

std::uint8_t *get_proc_address(std::uint8_t *module, const char *func) {
   PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(module);
   PIMAGE_DATA_DIRECTORY export_dir_info = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
   PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)&image_base[export_dir_info->VirtualAddress];

   DWORD *functions = (DWORD *)&image_base[export_dir->AddressOfFunctions];
   DWORD *names = (DWORD *)&image_base[export_dir->AddressOfNames];
   WORD *name_ordinals = (WORD *)&image_base[export_dir->AddressOfNameOrdinals];

   for (std::size_t i=0; i<export_dir->NumberOfNames; ++i) {
      const char *target_func = (const char *)&image_base[names[i]];
      const char *func_copy = func;
      bool found = true;

      while (*func_copy != 0 || *target_func != 0) {
         if (*func_copy == 0 && *target_func != 0 || *target_func == 0 && *func_copy != 0) {
            found = false;
            break;
         }

         std::int8_t diff = *target_func - *func_copy;

         if (diff != 0) {
            found = false;
            break;
         }

         ++target_func;
         ++func_copy;
      }

      if (found == false)
         continue;
         
      return &module[functions[name_ordinals[i]]];
   }

   return NULL;
}
   
extern "C" __declspec(dllexport) DWORD WINAPI load_image(SheepConfig *config) {
   PPEB_EX peb_ex = ((PPEB_EX)__readgsqword(0x60));
   PPEB_LDR_DATA_EX ldr_ex = (PPEB_LDR_DATA_EX)peb_ex->LoaderData;
   PLDR_DATA_TABLE_ENTRY_EX list_entry = (PLDR_DATA_TABLE_ENTRY_EX)ldr_ex->InLoadOrderModuleList.Flink;
   PLDR_DATA_TABLE_ENTRY_EX ntdll_entry = (PLDR_DATA_TABLE_ENTRY_EX)list_entry->InLoadOrderLinks.Flink;
   PLDR_DATA_TABLE_ENTRY_EX kernel32_entry = (PLDR_DATA_TABLE_ENTRY_EX)ntdll_entry->InLoadOrderLinks.Flink;

   std::uint8_t * (*load_library)(const char *) = (std::uint8_t * (*)(const char *))get_proc_address((std::uint8_t *)kernel32_entry->DllBase, "LoadLibraryA");
   BOOL (*virtual_protect)(LPVOID, SIZE_T, DWORD, PDWORD) = (BOOL (*)(LPVOID, SIZE_T, DWORD, PDWORD))get_proc_address((std::uint8_t *)kernel32_entry->DllBase, "VirtualProtect");
   
   GLOBAL_CONFIG = config;
   std::uint8_t *base_u8 = (std::uint8_t *)GLOBAL_CONFIG->image_base;
   PIMAGE_NT_HEADERS64 base_nt = get_nt_headers(base_u8);
   
   DWORD import_rva = base_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

   if (import_rva != 0) {
      PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)&base_u8[import_rva];

      while (import_table->OriginalFirstThunk != 0) {
         std::uint8_t *module = load_library((const char *)&base_u8[import_table->Name]);
         std::uintptr_t *original_thunks = (std::uintptr_t *)&base_u8[import_table->OriginalFirstThunk];
         std::uintptr_t *import_addrs = (std::uintptr_t *)&base_u8[import_table->FirstThunk];
         std::uintptr_t *old_base = import_addrs;
         DWORD old_protect;
         DWORD new_protect = PAGE_READWRITE;
         virtual_protect(import_addrs, 1024, new_protect, &old_protect);

         while (*original_thunks != 0) {
            if (*original_thunks & 0x8000000000000000)
               *import_addrs = (std::uintptr_t)get_proc_address(module, MAKEINTRESOURCE(*original_thunks & 0xFFFF));
            else {
               PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)&base_u8[*original_thunks];
               *import_addrs = (std::uintptr_t)get_proc_address(module, import_by_name->Name);
            }
            ++import_addrs;
            ++original_thunks;
         }

         virtual_protect(old_base, 1024, old_protect, &new_protect);

         ++import_table;
      }
   }

   /* initialize the tls callbacks */
   DWORD tls_rva = base_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

   if (tls_rva != 0) {
      PIMAGE_TLS_DIRECTORY64 tls_dir = (PIMAGE_TLS_DIRECTORY64)&base_u8[tls_rva];
      void (**callbacks)(PVOID, DWORD, PVOID) = (void (**)(PVOID, DWORD, PVOID))tls_dir->AddressOfCallBacks;

      while (*callbacks != NULL) {
         (*callbacks)(base_u8, DLL_PROCESS_ATTACH, nullptr);
         ++callbacks;
      }
   }

   return 0;
}

bool download_url(const wchar_t *domain, const wchar_t *url, const char *filename) {
   HINTERNET session = WinHttpOpen(L"Amethyst Labs/1.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS,
                                   0);

   if (session == nullptr)
      return false;

   HINTERNET connection = WinHttpConnect(session,
                                         domain,
                                         INTERNET_DEFAULT_HTTPS_PORT,
                                         0);

   if (connection == nullptr)
      return false;

   HINTERNET request = WinHttpOpenRequest(connection,
                                          L"GET",
                                          url,
                                          nullptr,
                                          WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);

   if (request == nullptr)
      return false;

   bool results = WinHttpSendRequest(request,
                                     WINHTTP_NO_ADDITIONAL_HEADERS,
                                     0,
                                     WINHTTP_NO_REQUEST_DATA,
                                     0,
                                     0,
                                     0);

   if (!results)
      return false;

   results = WinHttpReceiveResponse(request, nullptr);

   if (!results)
      return false;

   std::size_t out_size = 0;
   std::uint32_t chunk = 0;
   std::vector<std::uint8_t> out_buff;
   std::uint32_t downloaded = 0;

   if (!WinHttpQueryDataAvailable(request, (LPDWORD)&chunk))
      return false;

   while (chunk > 0) {
      if (out_size == 0)
         out_buff.resize(chunk, 0);
      else
         out_buff.resize(out_size+chunk, 0);

      std::memset(&out_buff[out_size], 0, chunk);

      if (!WinHttpReadData(request, &out_buff[out_size], chunk, (LPDWORD)&downloaded))
         return false;

      out_size += chunk;

      if (!WinHttpQueryDataAvailable(request, (LPDWORD)&chunk))
         return false;
   }

   HANDLE sheep_handle = CreateFileA(filename,
                                     GENERIC_WRITE,
                                     0,
                                     nullptr,
                                     CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL,
                                     nullptr);

   if (sheep_handle == INVALID_HANDLE_VALUE)
      return false;

   DWORD bytes_written;

   if (!WriteFile(sheep_handle, &out_buff[0], out_buff.size(), &bytes_written, nullptr)) {
      CloseHandle(sheep_handle);
      return false;
   }

   CloseHandle(sheep_handle);

   return true;
}

bool spawn_sheep(LPPROCESS_INFORMATION proc_info) {
   STARTUPINFOA startup_info;
   memset(&startup_info, 0, sizeof(STARTUPINFOA));
   startup_info.cb = sizeof(STARTUPINFOA);

   // processes spawned with explorer.exe have the following process attributes:
   // CREATE_DEFAULT_ERROR_MODE | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE | CREATE_SUSPENDED
   
   return (bool)CreateProcessA("C:\\ProgramData\\sheep.exe",
                               "sheep",
                               nullptr,
                               nullptr,
                               FALSE,
                               CREATE_NEW_CONSOLE,
                               nullptr,
                               "C:\\ProgramData",
                               &startup_info,
                               proc_info);
}

bool clear_inactive_sheep(std::vector<PROCESS_INFORMATION> &sheep_pool) {
   for (auto iter=sheep_pool.begin(); iter!=sheep_pool.end(); ++iter) {
      DWORD exit_code;
      
      if (!GetExitCodeProcess(iter->hProcess, &exit_code) || exit_code == STILL_ACTIVE)
         continue;

      sheep_pool.erase(iter);
      return true;
   }

   return false;
}

void russian_roulette(std::vector<PROCESS_INFORMATION> &sheep_pool) {
   std::size_t chambers = 6;
   
   for (auto iter=sheep_pool.begin(); iter!=sheep_pool.end(); ++iter) {
      if (chambers == 0)
         chambers = 6;
      
      if ((std::rand() % (chambers--)) != 0)
         continue;

      TerminateProcess(iter->hProcess, 0);
      chambers = 6;
   }
}

int WinMain(HINSTANCE instance, HINSTANCE prev_instance, LPSTR cmdline, int showcmd) {
   if (GLOBAL_CONFIG == nullptr)
      return 1;
   
   atexit(exit_thread);

   std::srand(std::time(0));

   /* let's talk about the sheep monitor! this silly little demo basically does the following:
    * create a vector of sheep processes
    * poll every minute
    * if C:\ProgramData\sheep.exe does not exist, download it from amethyst.systems/sheep.exe
    * if sheep_pool is at the limit, check if any sheep has died and clear them from the list
    * if number of sheep does not meet the limit, spawn a sheep process
    * if the number of sheep is at the limit, one sheep plays Russian Roulette
    * if they lose, they die */

   std::vector<PROCESS_INFORMATION> sheep_pool;

   while (GetFileAttributes("C:\\ProgramData\\sheep.exe") != INVALID_FILE_ATTRIBUTES || download_url(L"amethyst.systems", L"/sheep.exe", "C:\\ProgramData\\sheep.exe")) {
      if (sheep_pool.size() > 0)
         while (clear_inactive_sheep(sheep_pool));

      if (sheep_pool.size() < GLOBAL_CONFIG->max_sheep) {
         PROCESS_INFORMATION new_sheep;
            
         if (spawn_sheep(&new_sheep))
            sheep_pool.push_back(new_sheep);
      }
      else
         russian_roulette(sheep_pool);

      Sleep(60000);
   }
      
   return 0;
}

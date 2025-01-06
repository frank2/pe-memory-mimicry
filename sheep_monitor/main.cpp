#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cassert>
#include <optional>
#include <vector>
#include <windows.h>
#include <psapi.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#define VA_TO_RVA(base, va) (((std::uintptr_t)va) - ((std::uintptr_t)base))

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

__declspec(dllexport) extern "C" DWORD WINAPI load_image(SheepConfig *config) {
   GLOBAL_CONFIG = config;
   std::uint8_t *base_u8 = (std::uint8_t *)GLOBAL_CONFIG->image_base;
   PIMAGE_NT_HEADERS64 base_nt = get_nt_headers(base_u8);
   
   DWORD import_rva = base_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

   if (import_rva != 0) {
      PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)&base_u8[import_rva];

      while (import_table->OriginalFirstThunk != 0) {
         HMODULE module = LoadLibraryA((const char *)&base_u8[import_table->Name]);
         std::uintptr_t *original_thunks = (std::uintptr_t *)&base_u8[import_table->OriginalFirstThunk];
         std::uintptr_t *import_addrs = (std::uintptr_t *)&base_u8[import_table->FirstThunk];

         while (*original_thunks != 0) {
            if (*original_thunks & 0x8000000000000000)
               *import_addrs = (std::uintptr_t)GetProcAddress(module, MAKEINTRESOURCE(*original_thunks & 0xFFFF));
            else {
               PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)&base_u8[*original_thunks];
               *import_addrs = (std::uintptr_t)GetProcAddress(module, import_by_name->Name);
            }

            ++import_addrs;
            ++original_thunks;
         }

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

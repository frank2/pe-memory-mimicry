#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <windows.h>

#define VA_TO_RVA(base, va) (((std::uintptr_t)va) - ((std::uintptr_t)base))

uint8_t FRESH_IMAGE = NULL;
bool VALLOC_STATE = false;

void exit_thread(void) {
   ExitThread(0);
}

PIMAGE_NT_HEADERS64 get_nt_headers(uint8_t *base) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
   return (PIMAGE_NT_HEADERS64)&base[dos_header->e_lfanew];
}

VOID WINAPI get_fresh_image(PVOID instance, DWORD reason, PVOID reserved) {
   if (reason != DLL_PROCESS_ATTACH)
      return;

   uint8_t *self_u8 = (uint8_t *)instance;
   PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(self_u8);
   FRESH_IMAGE = (uint8_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nt_headers->OptionalHeader.SizeOfImage);
   memcpy(FRESH_IMAGE, self_u8, nt_headers->OptionalHeader.SizeOfImage);
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback")
#pragma const_seg(push)
#pragma const_seg(".CRT$XLAAA")
extern "C" const PIMAGE_TLS_CALLBACK tls_callback = get_fresh_image;
#pragma const_seg(pop)

void relocate_image(uint8_t *image, uintptr_t from, uintptr_t to) {
   PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(image);
   DWORD reloc_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

   if (reloc_rva == 0)
      return;

   uintptr_t base_delta = to - from;
   uint8_t *base_reloc = &image[reloc_rva];

   while (((PIMAGE_BASE_RELOCATION)base_reloc)->VirtualAddress != 0) {
      PIMAGE_BASE_RELOCATION base_reloc_block = (PIMAGE_BASE_RELOCATION)base_reloc;
      WORD *entry_table = (WORD *)&base_reloc[sizeof(IMAGE_BASE_RELOCATION)];
      size_t entries = (base_reloc_block->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);

      for (std::size_t i=0; i<entries; ++i) {
         DWORD reloc_rva = base_reloc_block->VirtualAddress + (entry_table[i] & 0xFFF);
         uintptr_t *reloc_ptr = (uintptr_t *)&image[reloc_rva];
               
         if ((entry_table[i] >> 12) == IMAGE_REL_BASED_DIR64)
            *reloc_ptr += base_delta;
      }
            
      base_reloc += base_reloc_block->SizeOfBlock;
   }

   // the loader assigns OptionalHeader.ImageBase after relocation
   nt_headers->OptionalHeader.ImageBase = (ULONGLONG)to;
}

void load_image(uint8_t *base_u8) {
   PIMAGE_NT_HEADERS64 base_nt = get_nt_headers(base_u8);
   
   DWORD import_rva = base_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

   if (import_rva != 0) {
      PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)&base_u8[import_rva];

      while (import_table->OriginalFirstThunk != 0) {
         HMODULE module = LoadLibraryA((const char *)&base_u8[import_table->Name]);
         uintptr_t *original_thunks = (uintptr_t *)&base_u8[import_table->OriginalFirstThunk];
         uintptr_t *import_addrs = (uintptr_t *)&base_u8[import_table->FirstThunk];

         while (*original_thunks != 0) {
            if (*original_thunks & 0x8000000000000000)
               *import_addrs = (uintptr_t)GetProcAddress(module, MAKEINTRESOURCE(*original_thunks & 0xFFFF));
            else {
               PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)&base_u8[*original_thunks];
               *import_addrs = (uintptr_t)GetProcAddress(module, import_by_name->Name);
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
}

int main(int argc, char *argv[]) {
   if (VALLOC_STATE) {
      atexit(exit_thread);
      puts("* valloc main");
      return 0;
   }

   uint8_t *base_u8 = FRESH_IMAGE;
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_u8;
   PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(base_u8);
   PIMAGE_SECTION_HEADER section_table = (PIMAGE_SECTION_HEADER)&base_u8[dos_header->e_lfanew+sizeof(DWORD)+sizeof(PIMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader];

   uintptr_t valloc_base = (uintptr_t)VirtualAlloc(NULL, nt_headers->OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_READWRITE);
   assert(valloc_base != NULL);

   uint8_t *valloc_headers = (uint8_t *)VirtualAlloc((LPVOID)valloc_base, nt_headers->OptionalHeader.SizeOfHeaders, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
   assert(valloc_headers != NULL);
   memcpy(valloc_headers, base_u8, nt_headers->OptionalHeader.SizeOfHeaders);

   for (size_t i=0; i<nt_headers->FileHeader.NumberOfSections; ++i) {
      PIMAGE_SECTION_HEADER section = &section_table[i];
      DWORD sect_protect;

      if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
         sect_protect = PAGE_EXECUTE;

         if ((section->Characteristics & IMAGE_SCN_READ) != 0) {
            sect_protect = PAGE_EXECUTE_READ;

            if ((section->Characteristics & IMAGE_SCN_WRITE) != 0) {
               sect_protect = PAGE_EXECUTE_READWRITE;
            }
         }
      }
      else if (section->Characteristics & IMAGE_SCN_MEM_READ != 0) {
         sect_protect = PAGE_READONLY;

         if (section->Characteristics & IMAGE_SCN_MEM_WRITE)
            sect_protect = PAGE_READWRITE;
      }
         
      uint8_t *valloc_section = (uint8_t *)VirtualAlloc((LPVOID)(valloc_base+section->VirtualAddress), section->Misc.VirtualSize, MEM_COMMIT | MEM_RESERVE, sect_protect);
      assert(valloc_section != NULL);
      memcpy(valloc_section, &base_u8[section->VirtualAddress], section->Misc.VirtualSize);
   }

   return 0;
}

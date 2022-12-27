#include "protect.h"



void test_func() {
	printf("HELLO FROM .text func!\n");
}

#pragma optimize("", off) //Disable it so it doesn't get inlined
#pragma section(".ghc", execute, read, write) //Write so we can erase encryption func
#pragma comment(linker,"/SECTION:.ghc,ERW")
#pragma code_seg(push, ".ghc")

uint8_t encryption_key;

PIMAGE_SECTION_HEADER get_section_by_name(const char* name)
{
	uint32_t modulebase = (uint32_t)GetModuleHandleA(0);
	if (modulebase == 0) {
		printf("Failed to get module base\n");
		return NULL;
	}

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)modulebase;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Invalid DOS signature\n");
		return NULL;
	}

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(modulebase + dos_header->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		printf("Invalid NT signature\n");
		return NULL;
	}

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
		if (!_stricmp((char*)section->Name, name))
		{
			printf("Found section with name %s\n", name);
			return section;
		}
	}
	printf("Failed to find section with name %s\n", name);
	return NULL;
}
void encrypt_section(PIMAGE_SECTION_HEADER section)
{
	printf("Encrypting section %s...\n", section->Name);

	uint32_t modulebase = (uint32_t)GetModuleHandleA(0);
	if (modulebase == 0) {
		printf("Error: Failed to retrieve module handle. Last error: %d\n", GetLastError());
		return;
	}

	int valid_page_count = (section->Misc.VirtualSize + 0xFFF) / 0x1000;

	if (valid_page_count == 0) {
		printf("Section is smaller than a page size, skipping encryption\n");
		return;
	}
	printf("Encrypting %d pages...\n", valid_page_count);
	for (int page_idx = 0; page_idx < valid_page_count; page_idx++)
	{
		uintptr_t address = modulebase + section->VirtualAddress + page_idx * 0x1000;
		printf("Encrypting page at address %p\n", address);
		DWORD old;
		if (VirtualProtect((LPVOID)address, 0x1000, PAGE_EXECUTE_READWRITE, &old) == 0) {
			printf("Error: Failed to change protection on memory page. Last error: %d\n", GetLastError());
			return;
		}
		for (int off = 0; off < 0x1000; off += 0x1) 
		{
			*(BYTE*)(address + off) = _rotr8((*(BYTE*)(address + off) + 0x10) ^ encryption_key, 69);
		}
		if (VirtualProtect((LPVOID)address, 0x1000, PAGE_NOACCESS, &old) == 0) {
			printf("Error: Failed to change protection on memory page. Last error: %d\n", GetLastError());
			return;
		}
		printf("Finished encrypting page at address %p\n", address);
	}
	printf("Finished encrypting section %s\n", section->Name);
}
bool eip_in_legit_module(uint32_t rip) {
	PPEB peb = (PPEB)__readfsdword(0x30);
	PPEB_LDR_DATA ldr = peb->Ldr;
	PLDR_DATA_TABLE_ENTRY module = NULL;
	PLIST_ENTRY list = ldr->InMemoryOrderModuleList.Flink;
	while (list != NULL && list != &ldr->InMemoryOrderModuleList) {
		module = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (module == NULL) {
			printf("Error: module is NULL\n");
			return false;
		}
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uint32_t)module->DllBase + ((PIMAGE_DOS_HEADER)module->DllBase)->e_lfanew);
		if ((rip >= (uint32_t)module->DllBase) && (rip <= (uint32_t)module->DllBase + nt->OptionalHeader.SizeOfImage))
		{
			return true;
		}
		list = list->Flink;
	}
	if (list == NULL) {
		printf("Error: list is NULL\n");
	}
	return false;
}

LONG WINAPI handler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		DWORD old;
		//ExceptionInformation[1] holds the invalid referenced memory address
		uint32_t page_start = (uint32_t)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
		page_start = page_start - (page_start % 0x1000);
		//Before we decrypt our page we want to verify the RIP that caused the violation. If it's not valid someone trys to forcefully decrypt the pages
		if (!eip_in_legit_module(ExceptionInfo->ContextRecord->Eip))
			return EXCEPTION_CONTINUE_SEARCH; //Force crash the program

		// Add error checking for VirtualProtect
		if (!VirtualProtect((LPVOID)page_start, 0x1000, PAGE_READWRITE, &old)) {
			printf("Error: VirtualProtect failed with error code %d\n", GetLastError());
			return EXCEPTION_CONTINUE_SEARCH;
		}
		for (int off = 0; off < 0x1000; off += 0x1) {
			*(BYTE*)(page_start + off) = (_rotl8(*(BYTE*)(page_start + off), 69) ^ encryption_key) - 0x10;
		}
		// Add error checking for VirtualProtect
		if (!VirtualProtect((LPVOID)page_start, 0x1000, PAGE_EXECUTE_READ, &old)) {
			printf("Error: VirtualProtect failed with error code %d\n", GetLastError());
			return EXCEPTION_CONTINUE_SEARCH;
		}
		printf("Decrypted %p rip %p\n", page_start, ExceptionInfo->ContextRecord->Eip);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
void protect::initialize() 
{
	srand(time(NULL));
	encryption_key = rand() % 255 + 1; 
	PVOID vectored_handle = AddVectoredExceptionHandler(1, handler);
	if (vectored_handle == NULL) {
		DWORD error_code = GetLastError();
		
		printf("Error: AddVectoredExceptionHandler failed with error code %d\n", error_code);
	}
	PIMAGE_SECTION_HEADER section = get_section_by_name(".text");
	if (section == NULL) {
		printf("Error: Failed to find section with name '.text'\n");
		return;
	}

	encrypt_section(section);
	for (int i = 0; i < (uint64_t)eip_in_legit_module - (uint64_t)encrypt_section; i += 0x1) {
		*(uint8_t*)((uint64_t)encrypt_section + i) = 0;
	}
	test_func();
}
#pragma code_seg(pop, ".ghc")
#pragma optimize("", on)







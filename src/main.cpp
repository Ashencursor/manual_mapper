#include <Windows.h>
#include <chrono>
#include <cstdint>
#include <libloaderapi.h>
#include <limits>
#include <memoryapi.h>
#include <rpcndr.h>
#include <string>
#include <winnt.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <array>
#include "../include/utils.h"
#include <vector>
#include <ntstatus.h>
#include <winternl.h>
#include "../include/windefs.h"
#include <iostream>

// TODO: Look at flags for VirtualAlloxEx(confirm knowledge, recall)


bool resolve_imports(std::vector<std::uint8_t>& dll_bytes, void* hproc, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	auto descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(descriptor->Name != 0){
		std::string dll_name = reinterpret_cast<const char*>(local_dll_base + descriptor->Name);
		auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(local_dll_base + descriptor->FirstThunk);
		auto original_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(local_dll_base + descriptor->OriginalFirstThunk);
		uintptr_t remote_module = utils::get_module_addr(hproc, dll_name.c_str());
		std::cout << "[DLL] :" << dll_name << '\n';
		
		while(thunk->u1.AddressOfData != 0){
			if(original_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG){
				utils::log("[-] ordinal used");

			}
			else {
				auto name_table = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(local_dll_base + original_thunk->u1.AddressOfData);

				std::string import_name = name_table->Name;
				uintptr_t import_addr = reinterpret_cast<uintptr_t>(
						GetProcAddress(GetModuleHandleA(dll_name.data()), import_name.data())
						);
				std::cout << "import: " << import_name << " addr:  " << import_addr << '\n';

				uintptr_t import_rva = import_addr - remote_module;
				thunk->u1.Function = remote_module + import_rva;
			}
			thunk++;
			original_thunk++;
		}

		descriptor++;
	}

	return true;
}
bool resolve_iat(void* hproc, std::vector<std::uint8_t>& dll_bytes, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	NtQueryInformationProcess_t my_NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess"));

	auto iat_table = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(dll_bytes.data() + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	PROCESS_BASIC_INFORMATION pi;
	std::size_t pi_size {};
	NTSTATUS status = my_NtQueryInformationProcess(
			hproc,
			ProcessBasicInformation, 
			&pi, 
			sizeof(PROCESS_BASIC_INFORMATION), 
			reinterpret_cast<PULONG>(&pi_size));

	if(status != STATUS_SUCCESS){
		utils::log("[-] Failed to gret ProcessBasicInformation");
		return false;
	}

	std::size_t bytes_read {};
	PPEB peb = pi.PebBaseAddress;
	
	int i {};
	while(true){
		std::cout << "iteration: " << i << '\n';
		
		i++;
	}
	return true;
}
// wprintf(L"The string is: [%.*ls]\n", data_table_b.FullDllName.Length / sizeof(WCHAR), data_table_b.FullDllName.Buffer);


union RelocInfo { 
	struct {
		std::uint16_t type : 4;
		std::uint16_t offset : 12;
	};
	std::uint16_t info;
};

bool relocate_table(uintptr_t proc_addr, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	if(local_dll_base == nt->OptionalHeader.ImageBase){ return 0; }
	auto reloc_start = reinterpret_cast<PIMAGE_BASE_RELOCATION>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	auto reloc_block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	uintptr_t base_offset = proc_addr - nt->OptionalHeader.ImageBase;
	
	while(true){
		std::size_t block_size {};
		if((reloc_block == nullptr) || !(block_size = reloc_block->SizeOfBlock)){
			break;
		}
		std::size_t entry_count = (block_size - 2*sizeof(DWORD)) / sizeof(WORD);
		for(int i = 0; i < entry_count; ++i){
			RelocInfo* entry = reinterpret_cast<RelocInfo*>(local_dll_base + reloc_block->VirtualAddress + sizeof(IMAGE_BASE_RELOCATION) + i*sizeof(WORD));
			uintptr_t data = *reinterpret_cast<uintptr_t*>(local_dll_base + reloc_block->VirtualAddress + entry->offset) + base_offset;

			memcpy(reinterpret_cast<void*>(local_dll_base + reloc_block->VirtualAddress  + entry->offset),
					reinterpret_cast<void*>(&data),
					sizeof(WORD));
		}
		reloc_block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uintptr_t>(reloc_block) + block_size);
	}
	return true;
}

bool load_sections(std::vector<std::uint8_t>& dll_bytes, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	std::size_t section_num = nt->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt);
	for(std::size_t i = 0; i < section_num; ++i){
		memcpy(reinterpret_cast<void*>(local_dll_base + section_header->VirtualAddress),
				reinterpret_cast<void*>(dll_bytes.data() + section_header->PointerToRawData),
				section_header->SizeOfRawData);
		section_header++;
	}
	return true;
}

int main() {
	void* hproc = utils::get_proc_handle("Notepad.exe");
	if(hproc == nullptr){
		utils::log("[-] Failed to get process handle");		
		return 0; 
	}

	uintptr_t proc_addr = utils::get_module_addr(hproc, "notepad.exe");
	if(proc_addr == 0) {
		utils::log("[-] Failed to get proc addr");
		return 0;
	}
	
	std::vector<std::uint8_t> dll_bytes;
	if(!utils::load_bytes("C:\\Users\\ashen\\Desktop\\projects\\bo4\\build\\bo4.dll", dll_bytes)){
		utils::log("[-] Failed to load dll bytes");
		return 0;
	}
	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(dll_bytes.data());
	if(dos->e_magic != IMAGE_DOS_SIGNATURE) {
		utils::log("[-] Failed to get dos header");
		return 0;
	}
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(dll_bytes.data() + dos->e_lfanew);
	if(nt->Signature != IMAGE_NT_SIGNATURE){
		utils::log("[-] Failed to get nt header");
		return 0;
	}

	auto preferred_base = reinterpret_cast<uintptr_t>(nt->OptionalHeader.ImageBase);
	auto image_size = nt->OptionalHeader.SizeOfImage;

	// Find where in target to write to
	void* remote_dll_base = VirtualAllocEx(hproc, reinterpret_cast<LPVOID>(preferred_base), image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(reinterpret_cast<uintptr_t>(remote_dll_base) != preferred_base){
		utils::log("[-] Dll couldn't load at preferred base");
		remote_dll_base = VirtualAllocEx(hproc, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(!remote_dll_base){
			utils::log("[-] Failed to allocate memory for the dll");
			return 0;
		}
	}
	void* local_dll_base = VirtualAlloc(nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	// 1. Must write headers and sections to local_dll_base 
	memcpy(local_dll_base, dll_bytes.data(), nt->OptionalHeader.SizeOfHeaders);
	// 2. write sections to be aligned with virtual address space
	if(!load_sections(dll_bytes, reinterpret_cast<uintptr_t>(local_dll_base), nt)){
		utils::log("[-] Failed to write headers");
		return 0;
	}	
	if(!relocate_table(proc_addr, reinterpret_cast<uintptr_t>(local_dll_base), nt)){
		utils::log("[-] Failed to relocate base");
		return 0;
	}
	if(!resolve_imports(dll_bytes, hproc, reinterpret_cast<uintptr_t>(local_dll_base), nt)){
		utils::log("[-] Failed to resolve imports");
		return 0;
	}
	utils::log("[+] Exiting program");
	return 0;
}

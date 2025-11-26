#include <iostream>
#include "../include/pe.h"
#include "../include/utils.h"

bool PE::resolve_imports(std::vector<std::uint8_t>& dll_bytes, void* hproc, uintptr_t proc_addr, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	auto descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(descriptor->Name != 0){
		std::string dll_name = reinterpret_cast<const char*>(local_dll_base + descriptor->Name);
		auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(local_dll_base + descriptor->FirstThunk);
		auto original_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(local_dll_base + descriptor->OriginalFirstThunk);
		uintptr_t local_module = utils::get_module_addr(GetModuleHandleA(nullptr), dll_name.c_str());
		uintptr_t remote_module = utils::get_module_addr(hproc, dll_name.c_str());

		std::cout << "[DLL] :" << dll_name << '\n';
	
		// Issue on crash could be here, not populating all functions only some
		while(thunk->u1.AddressOfData != 0){
			if(original_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG){
				utils::log("[-] ordinal used");
				uintptr_t import_addr = reinterpret_cast<uintptr_t>(
						GetProcAddress(
							GetModuleHandleA(dll_name.c_str()), 
							reinterpret_cast<LPCSTR>(original_thunk->u1.Ordinal)));

				uintptr_t import_rva = import_addr - local_module;
				thunk->u1.Function = local_module + import_rva;
			}
			else {
				auto name_table = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(local_dll_base + original_thunk->u1.AddressOfData);

				std::string import_name = name_table->Name;
				uintptr_t import_addr = reinterpret_cast<uintptr_t>(
						GetProcAddress(GetModuleHandleA(dll_name.c_str()), import_name.c_str())
						);
				std::cout << "import: " << import_name << " addr:  " << std::hex << import_addr << '\n';

				uintptr_t import_rva = import_addr - local_module;
				thunk->u1.Function = remote_module + import_rva;
			}
			thunk++;
			original_thunk++;
		}
		descriptor++;
	}
	return true;
}

/*
bool PE::resolve_iat(std::vector<std::uint8_t>& dll_bytes, void* hproc, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
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
*/

bool PE::relocate_table(uintptr_t proc_addr, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	if(local_dll_base == nt->OptionalHeader.ImageBase){ return true; }
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

bool PE::load_sections(std::vector<std::uint8_t>& dll_bytes, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
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



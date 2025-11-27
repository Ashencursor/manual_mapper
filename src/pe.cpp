#include <algorithm>
#include <cstdint>
#include <iostream>
//#include <minwinbase.h>
#include <unordered_map>
#include <algorithm>

#include "../include/windefs.h"
#include "../include/pe.h"
#include "../include/utils.h"
#include <print>


// TODO: Make function to get the offset of an import within a module


bool PE::resolve_imports(std::vector<std::uint8_t>& dll_bytes, void* hproc, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	auto descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if(descriptor == nullptr) { return false; }

	//std::println("[+] getting module names");
	std::vector<std::string> module_names = utils::get_module_names(hproc);	
	std::for_each(module_names.begin(), module_names.end(), [](std::string& str){
		utils::to_lower(str);
			});
	void* local_hproc = utils::get_proc_handle("manual_mapper.exe");
	auto local_module_addr = utils::get_module_addr(local_hproc, "kernel32.dll");
	
	uintptr_t local_proc_addr = utils::get_module_addr(local_hproc, "manual_mapper.exe");// Cant do GetModuleHandleA(nullptr), GetModuleHandleA("manual_mapper.exe")

	uintptr_t loadlib_addr = reinterpret_cast<uintptr_t>(
			GetProcAddress(
				reinterpret_cast<HMODULE>(local_module_addr), 
				"LoadLibraryA")
			);

	if(!loadlib_addr){
		utils::log("[-] Failed to get loadlib");
		return 0;
	}
	uintptr_t loadlib_rva = loadlib_addr - utils::get_module_addr(local_hproc, "kernel32.dll");
	uintptr_t loadlib_remote_addr = utils::get_module_addr(hproc, "kernel32.dll") + loadlib_rva;
	std::println("load lib rva {:X}", loadlib_rva);	
	std::println("remote loadlib addr: {:X}", loadlib_remote_addr);

	while(descriptor->Name != 0){
		std::string dll_name = reinterpret_cast<const char*>(local_dll_base + descriptor->Name);
		
		auto it = std::find(module_names.begin(), module_names.end(), utils::to_lowero(dll_name));
		if(it == module_names.end()){
			std::cout << "[-] Target doesnt contain dll: " << dll_name << '\n';
			std::cout << "[-] loading dll into mem...\n";
			CreateRemoteThread(hproc, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadlib_remote_addr), reinterpret_cast<LPVOID>(dll_name.data()), 0, 0);
		}

		auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(local_dll_base + descriptor->FirstThunk);
		auto original_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(local_dll_base + descriptor->OriginalFirstThunk);
		uintptr_t local_module = utils::get_module_addr(local_hproc, dll_name.data());
		std::cout << "!@DDSDSDSD\n";  // TEST
		uintptr_t remote_module = utils::get_module_addr(hproc, dll_name.c_str());

		std::cout << "[DLL] : " << dll_name << ", remote addr: " << std::hex << remote_module  << '\n';

		while(thunk->u1.AddressOfData != 0){
			std::println("[+] Checking whether its by ordinal or name");

			if(original_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				utils::log("[-] ordinal used");
				uintptr_t import_addr = reinterpret_cast<uintptr_t>(
						GetProcAddress(
							GetModuleHandleA(dll_name.c_str()), 
							reinterpret_cast<LPCSTR>(original_thunk->u1.Ordinal)));

				uintptr_t import_rva = import_addr - local_module;
				thunk->u1.Function = remote_module + import_rva;
			}
			else 
			{
				std::println("[+] Name");
				auto name_table = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(local_dll_base + original_thunk->u1.AddressOfData);
				std::println("[+] getting import name");

				std::string import_name = name_table->Name;
				uintptr_t import_addr = reinterpret_cast<uintptr_t>(
						GetProcAddress(
							reinterpret_cast<HMODULE>(utils::get_module_addr(local_hproc, dll_name.c_str())),
							import_name.c_str())
						);

				std::cout << "import: " << import_name << " addr:  " << std::hex << import_addr << '\n';

				uintptr_t import_rva = import_addr - local_module;
				thunk->u1.Function = remote_module + import_rva;
			}
			std::println("[+] Going to next import");
			thunk++;
			original_thunk++;
		}
		std::println("[+] Going to next dll");
		descriptor++;
	}
	return true;
}

std::unordered_map<std::string, uintptr_t> get_module_info(std::vector<std::uint8_t>& dll_bytes, void* hproc, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
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
		return {};
	}

	std::size_t bytes_read {};
	PPEB peb = pi.PebBaseAddress;
	
	int i {};
	while(true){
		std::cout << "iteration: " << i << '\n';
		
		i++;
	}
	return {};
}

bool PE::relocate_table(uintptr_t proc_addr, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	if(local_dll_base == nt->OptionalHeader.ImageBase){ return true; }

	auto reloc_block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	//auto reloc_dir_size = reinterpret_cast<std::size_t>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	//auto reloc_end = reinterpret_cast<uintptr_t>(reloc_block->VirtualAddress + reloc_dir_size);

	uintptr_t base_offset = proc_addr - nt->OptionalHeader.ImageBase;
	
	while(reloc_block->VirtualAddress != 0){
		std::size_t block_size {};
		if((reloc_block == nullptr) || !(block_size = reloc_block->SizeOfBlock)){
			break;
		}
		std::println("block size: {}", block_size);

		std::size_t entry_count = (block_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for(int i = 0; i < entry_count; ++i){
			RelocInfo* entry = reinterpret_cast<RelocInfo*>(local_dll_base + reloc_block->VirtualAddress + sizeof(IMAGE_BASE_RELOCATION) + i*sizeof(WORD));
			if(entry->type == IMAGE_REL_BASED_ABSOLUTE){
				continue;
			}

			uintptr_t data = *reinterpret_cast<uintptr_t*>(local_dll_base + reloc_block->VirtualAddress + entry->offset) + base_offset;
			//*data += base_offset;
	
			memcpy(reinterpret_cast<void*>(local_dll_base + reloc_block->VirtualAddress  + entry->offset),
					reinterpret_cast<void*>(&data),
					sizeof(uintptr_t));
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



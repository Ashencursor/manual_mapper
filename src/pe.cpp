#include <algorithm>
#include <cstdint>
#include <iostream>
//#include <minwinbase.h>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <print>
#include <vector>
#include <string_view>

#include "../include/windefs.h"
#include "../include/pe.h"
#include "../include/utils.h"



// WORKS
uintptr_t get_local_module_addr(std::string_view name){
	void* hmod = GetModuleHandleA(name.data());
	if(!hmod){
		hmod = LoadLibraryA(name.data());
		if(!hmod){
			return 0;
		}	
	}
	return reinterpret_cast<uintptr_t>(hmod);
}

// WORKS
uintptr_t get_remote_module_addr(void* hproc, std::string name, uintptr_t remote_loadlibrarya){
	std::size_t bytes_written {};
	void* str_addr = VirtualAllocEx(hproc, nullptr, name.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	bool written = WriteProcessMemory(hproc, str_addr, name.c_str(), name.size(), &bytes_written);	
	if(!written){
		std::println("[-] Failed to write string to target mem");
		return false;
	}
	CreateRemoteThread(hproc, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_loadlibrarya), reinterpret_cast<LPVOID>(str_addr), 0, nullptr);
	return utils::get_module_addr(hproc, name.c_str());
}

bool PE::resolve_imports(std::vector<std::uint8_t>& dll_bytes, void* hproc, uintptr_t proc_addr, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	auto descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	void* local_hproc = utils::get_proc_handle(L"manual_mapper.exe");

	uintptr_t local_kernel32 = get_local_module_addr("kernel32.dll");
	uintptr_t remote_kernel32 = utils::get_module_addr(hproc, "kernel32.dll");

	uintptr_t local_loadliba = reinterpret_cast<uintptr_t>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
	uintptr_t loadlibraryrva = local_loadliba - local_kernel32;

	uintptr_t remote_loadlibrarya = remote_kernel32 + loadlibraryrva;
	
	IMAGE_DOS_HEADER dos_remote = {};
	ReadProcessMemory(hproc, reinterpret_cast<void*>(proc_addr), &dos_remote, sizeof(dos_remote), nullptr);

	IMAGE_NT_HEADERS nt_remote = {};
	ReadProcessMemory(hproc,
                  reinterpret_cast<void*>(proc_addr + dos_remote.e_lfanew),
                  &nt_remote,
                  sizeof(nt_remote),
                  nullptr);
	DWORD image_size = nt_remote.OptionalHeader.SizeOfImage;

	while(descriptor->Name != 0){
		std::string dll_name = reinterpret_cast<const char*>(local_dll_base + descriptor->Name);
		//std::cout << "printing dll name: \n";
		std::cout << "[DLL]: " << dll_name << '\n';

		auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(local_dll_base + descriptor->FirstThunk);
		auto original_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(local_dll_base + descriptor->OriginalFirstThunk);

		uintptr_t local_module = get_local_module_addr(dll_name.c_str());

		if(!local_module){
			//utils::log("[-] Failed to load/get the address of the module");
		}
		else {
			//utils::log("[+] Successfully loaaded/got the address of the module");
		}
		
		uintptr_t remote_module = utils::get_module_addr(hproc, dll_name.c_str());
		if(!remote_module){
			std::println("[-] Failed to get remote module addr\n[-] Attempting to loadlibrarya it into the target");
			remote_module = get_remote_module_addr(hproc, dll_name, remote_loadlibrarya);
		}

		while(thunk->u1.AddressOfData != 0){

			if(original_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG){
				utils::log("[-] ordinal used");
				
				uintptr_t local_module_addr = reinterpret_cast<uintptr_t>(GetProcAddress(
							reinterpret_cast<HMODULE>(local_module),
							MAKEINTRESOURCEA(original_thunk->u1.Ordinal & 0xFFFF)
							));
							
			}
			else {
				auto name_table = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(local_dll_base + original_thunk->u1.AddressOfData);
				if(!name_table){
					utils::log("[-] Invalid name_table or name");
					continue;
				}

				auto import_name = reinterpret_cast<const char*>(name_table->Name);				
				std::cout << import_name << '\n';
				uintptr_t import_addr = reinterpret_cast<uintptr_t>(
						GetProcAddress(GetModuleHandleA(dll_name.data()), import_name)
						);
				std::cout << "import: " << import_name << " addr:  " << import_addr << '\n';

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

std::unordered_map<std::string, uintptr_t> get_module_info(std::vector<std::uint8_t>& dll_bytes, void* hproc, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	NtQueryInformationProcess_t my_NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

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

bool PE::relocate_table(uintptr_t remote_dll_base, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt){
	if(local_dll_base == nt->OptionalHeader.ImageBase){ return true; }

	auto reloc_block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	//auto reloc_dir_size = reinterpret_cast<std::size_t>(local_dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	//auto reloc_end = reinterpret_cast<uintptr_t>(reloc_block->VirtualAddress + reloc_dir_size);

	uintptr_t base_offset = remote_dll_base - nt->OptionalHeader.ImageBase;
	
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



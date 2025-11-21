#include <Windows.h>
#include <cstdint>
#include <limits>
#include <memoryapi.h>
#include <winnt.h>
#include <TlHelp32.h>
#include <iostream>
#include <psapi.h>
#include <array>
#include "../include/utils.h"
#include <vector>

// 1. Get targetproc addr
// 2. parse target PE 
// 3. relocate image
// 4. 

// TODO: Look at flags for VirtualAlloxEx(confirm knowledge, recall)

PIMAGE_DOS_HEADER get_dos_header(void* hproc, uintptr_t proc_addr, std::array<std::uint8_t, sizeof(IMAGE_DOS_HEADER)>& buffer, size_t* bytes_read){
	utils::read_proc_mem(hproc, proc_addr, buffer.data(), buffer.size(), bytes_read);
	if(reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data())->e_magic != IMAGE_DOS_SIGNATURE) {
		utils::log("[-] Failed to get dos header");
		return 0;
	}
	return reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
}


union reloc_info { 
	struct {
		std::uint16_t type : 4;
		std::uint16_t offset : 12;
	};
	std::uint16_t info;
};

bool relocate_table(uintptr_t proc_addr, uintptr_t dll_base, PIMAGE_NT_HEADERS nt){
	if(dll_base == nt->OptionalHeader.ImageBase){ return 0; }
	uintptr_t reloc_start = dll_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	size_t bytes_read {};

	uintptr_t base_offset = proc_addr - nt->OptionalHeader.ImageBase;
	
	std::size_t total_size{};
	//while(true){
		//std::size_t curr_block_size {};
		
	//}
	return false;
}

bool load_section(void* hproc){
	
	return false;
}

int main() {
	void* hproc = utils::get_proc_handle("Notepad.exe");
	if(hproc == nullptr){
		utils::log("[-] Failed to get process handle");		
		return 0; 
	}

	uintptr_t proc_addr = utils::get_proc_addr(hproc, "notepad.exe");
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
	void* dll_base = VirtualAllocEx(hproc, reinterpret_cast<LPVOID>(preferred_base), image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(reinterpret_cast<uintptr_t>(dll_base) != preferred_base){
		utils::log("[-] Dll couldn't load at preferred base");
		dll_base = VirtualAllocEx(hproc, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(!dll_base){
			utils::log("[-] Failed to allocate memory for the dll");
			return 0;
		}
	}
	void* local_dll_base = VirtualAlloc(nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


	// 1. Must write headers and sections to local_dll_base 
	memcpy(local_dll_base, dll_bytes.data(), nt->OptionalHeader.SizeOfHeaders);
	// 2. write sections to be aligned with virtual address space
	std::size_t section_num = nt->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt);
	for(std::size_t i = 0; i < section_num; ++i){
		memcpy(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(local_dll_base) + section_header->VirtualAddress),
				reinterpret_cast<void*>(dll_bytes.data() + section_header->PointerToRawData),
				section_header->SizeOfRawData);
		section_header++;
	}
	if(!relocate_table(proc_addr, reinterpret_cast<uintptr_t>(local_dll_base), nt)){
		utils::log("[-] Failed to relocate base");
		return 0;
	}
	utils::log("[+] Exiting program");
	return 0;
}

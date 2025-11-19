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

bool relocate_table(void* hproc, uintptr_t proc_addr, uintptr_t dll_base, PIMAGE_NT_HEADERS nt){
	if(dll_base == nt->OptionalHeader.ImageBase){ return 0; }
	//Parse NT headers
	// VitualAddress is located in target
	auto reloc_entries = reinterpret_cast<PIMAGE_BASE_RELOCATION>(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	std::array<std::uint8_t, 16> reloc_buffer; // TODO: Check the size and type
	size_t bytes_read {};
	utils::read_proc_mem(hproc, proc_addr + reinterpret_cast<uintptr_t>(reloc_entries), reloc_buffer.data(), reloc_buffer.size(), &bytes_read);

	auto reloc_blocks = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reloc_buffer.data());
	uintptr_t base_offset = proc_addr - nt->OptionalHeader.ImageBase;

	std::size_t bytes = reloc_blocks->SizeOfBlock;
	// 1. Check if block is valid
	// 2. loop through reloc entries
	// 3. add to the offset the base_offset to reloc_block offset
	// 4. go to next block until end and then next entry
	//
	//return true; // WORKS, exits program
	for(int i = 0; i < bytes; ++i){
		std::uint32_t reloc_block = reloc_blocks->VirtualAddress;
		
		//reloc_blocks++; // Go to next block(crashes i think)
	}
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
	
	std::array<std::uint8_t, sizeof(IMAGE_DOS_HEADER)> dos_buffer;
	size_t bytes_read {};
	auto dos = get_dos_header(hproc, proc_addr, dos_buffer, &bytes_read);	

	std::array<std::uint8_t, sizeof(IMAGE_NT_HEADERS)> nt_buffer;
	utils::read_proc_mem(hproc, (proc_addr + dos->e_lfanew), nt_buffer.data(), nt_buffer.size(), &bytes_read);
	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(nt_buffer.data());
	if(nt->Signature != IMAGE_NT_SIGNATURE){
		utils::log("[-] Failed to get nt header");
		return 0;
	}

	auto preferred_base = reinterpret_cast<uintptr_t>(nt->OptionalHeader.ImageBase);
	auto image_size = nt->OptionalHeader.SizeOfImage;

	// 1. Alloc place for dll
	// 2. Compare to preferred_base

	void* dll_base = VirtualAllocEx(hproc, reinterpret_cast<LPVOID>(preferred_base), image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(reinterpret_cast<uintptr_t>(dll_base) != preferred_base){
		utils::log("[] Dll couldn't load at preferred base");
		dll_base = VirtualAllocEx(hproc, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(!dll_base){
			utils::log("[-] Failed to allocate memory for the dll");
			return 0;
		}
	}
	// reloc_table(func call crashes if it doesnt ret a val, why?)
	if(!relocate_table(hproc, proc_addr, reinterpret_cast<uintptr_t>(dll_base), nt)){
		utils::log("[-] Failed to reloc");
		return 0;
	}
	//auto data_dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(nt->OptionalHeader.DataDirectory);
	//auto reloc_table = reinterpret_cast<PIMAGE_RELOCATION>(data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	utils::log("[+] Exiting program");
	return 0;
}

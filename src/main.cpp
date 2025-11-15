#include <Windows.h>
#include <limits>
#include <memoryapi.h>
#include <winnt.h>
#include <TlHelp32.h>
#include <iostream>
#include <psapi.h>
#include <vector>
#include "../include/utils.h"

// 1. Get targetproc addr
// 2. parse target PE 
// 3. relocate image
// 4. 

// TODO: Look at flags for VirtualAlloxEx(confirm knowledge, recall)



bool reloc_dll(){
		
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
	
	std::vector<std::uint8_t> dos_buffer(sizeof(IMAGE_DOS_HEADER));
	size_t bytes_read {};
	// TODO: remove magic number
	utils::read_proc_mem(hproc, proc_addr, dos_buffer.data(), dos_buffer.size(), &bytes_read);
	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(dos_buffer.data());
	if(dos->e_magic != IMAGE_DOS_SIGNATURE) {
		utils::log("[-] Failed to get dos header");
		return 0;
	}

	std::vector<std::uint8_t> nt_buffer(sizeof(IMAGE_NT_HEADERS));
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
		dll_base = VirtualAllocEx(hproc, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if(!dll_base){
			utils::log("[-] Failed to allocate memory for the dll");
			return 0;
		}
	}
	// reloc_table

	//auto data_dir = reinterpret_cast<PIMAGE_DATA_DIRECTORY>(nt->OptionalHeader.DataDirectory);
	//auto reloc_table = reinterpret_cast<PIMAGE_RELOCATION>(data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	utils::log("[+] Exiting program");
	std::cout << "NIGGA\n";
	return 0;
}

#include <Windows.h>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memoryapi.h>
#include <winnt.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <array>
#include "../include/utils.h"
#include <vector>
#include <ntstatus.h>
#include <winternl.h>

// TODO: Look at flags for VirtualAlloxEx(confirm knowledge, recall)

PIMAGE_DOS_HEADER get_dos_header(void* hproc, uintptr_t proc_addr, std::array<std::uint8_t, sizeof(IMAGE_DOS_HEADER)>& buffer, size_t* bytes_read){
	utils::read_proc_mem(hproc, proc_addr, buffer.data(), buffer.size(), bytes_read);
	if(reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data())->e_magic != IMAGE_DOS_SIGNATURE) {
		utils::log("[-] Failed to get dos header");
		return 0;
	}
	return reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
}

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
  [in]            HANDLE           ProcessHandle,
  [in]            PROCESSINFOCLASS ProcessInformationClass,
  [out]           PVOID            ProcessInformation,
  [in]            ULONG            ProcessInformationLength,
  [out, optional] PULONG           ReturnLength
);

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
	PEB peb = *pi.PebBaseAddress;
	PPEB_LDR_DATA lrd = peb.Ldr; 
	PLIST_ENTRY list = &lrd->InMemoryOrderModuleList;

	while(true){
		if((list == nullptr) || (list->Flink == nullptr)){
			break;
		}
		PLDR_DATA_TABLE_ENTRY data_table = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(list->Flink);

		list = data_table->InMemoryOrderLinks.Flink;
	}
	return true;
}

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
			if (entry->offset) {

			}
			uintptr_t data = *reinterpret_cast<uintptr_t*>(local_dll_base + reloc_block->VirtualAddress + entry->offset) + base_offset;
			memcpy(reinterpret_cast<void*>(local_dll_base + reloc_block->VirtualAddress  + entry->offset),
					reinterpret_cast<void*>(&data),
					sizeof(WORD)
					);
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
	if(!resolve_iat(hproc, dll_bytes, reinterpret_cast<uintptr_t>(local_dll_base), nt)){
		utils::log("[-] Failed to resolve imports");
		return 0;
	}
	utils::log("[+] Exiting program");
	return 0;
}

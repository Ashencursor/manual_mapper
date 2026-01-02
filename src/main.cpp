#include <Windows.h>
#include <cstdint>
#include <minwinbase.h>
#include <minwindef.h>
#include <vector>
#include <winnt.h>
#include "../include/utils.h"
#include "../include/pe.h"

struct ShellParams {
	uintptr_t remote_base; // used for hMod in DllMain
	uintptr_t entry;       // address of DllMain
};

unsigned char stub[] = {
	0x0
};


void shellcode(ShellParams params){
	using dllmain_t = int(__stdcall*)(HINSTANCE hmod, DWORD reason, LPVOID reserved);
	dllmain_t dllmain = reinterpret_cast<dllmain_t>(params.entry);
	dllmain(reinterpret_cast<HINSTANCE>(params.remote_base), DLL_PROCESS_ATTACH, nullptr);
	return;
}

int main() {
	void* hproc = utils::get_proc_handle(L"Notepad.exe");
	if(hproc == nullptr){
		utils::log("[-] Failed to get process handle");		
		return 0; 
	}

	uintptr_t proc_addr = utils::get_module_addr(hproc, "Notepad.exe");
	if(proc_addr == 0) {
		utils::log("[-] Failed to get proc addr");
		return 0;
	}
	
	std::vector<std::uint8_t> dll_bytes;
	if(!utils::load_bytes("C:\\Users\\osawi\\source\\repos\\dll test\\x64\\Release\\dll_test.dll", dll_bytes)){
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

	auto preferred_base = nt->OptionalHeader.ImageBase;
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
	if(!PE::load_sections(dll_bytes, reinterpret_cast<uintptr_t>(local_dll_base), nt)){
		utils::log("[-] Failed to write headers");
		return 0;
	}	
	if(!PE::relocate_table(reinterpret_cast<uintptr_t>(remote_dll_base), reinterpret_cast<uintptr_t>(local_dll_base), nt)){
		utils::log("[-] Failed to relocate base");
		return 0;
	}
	if(!PE::resolve_imports(dll_bytes, hproc, proc_addr, reinterpret_cast<uintptr_t>(local_dll_base), nt)){
		utils::log("[-] Failed to resolve imports");
		return 0;
	}
	// Write prepared dll to target
	if (!WriteProcessMemory(hproc, remote_dll_base, local_dll_base, image_size, nullptr)) {
    utils::log("[-] Failed to write mapped image into remote process");
    return 0;
	}
 
	// TESTING

	


		HANDLE h_thread = CreateRemoteThread(
			hproc, 
			nullptr,
			0, 
			reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<uintptr_t>(remote_dll_base) + nt->OptionalHeader.AddressOfEntryPoint),
			0, 
			0,
			nullptr);
	if(!h_thread){
		utils::log("[-] CreateRemoteThread Failed");
		return 0;
	}
	utils::log("[+] Exiting program");
	return 0;
}

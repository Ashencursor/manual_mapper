#include "../include/utils.h"
#include <algorithm>
#include <atomic>
#include <clocale>
#include <cwctype>
#include <vector>
#include <fstream>
#include <filesystem>

static constexpr DWORD max_path = 260; // 256 for characters, 1 for null terminator, 2 for C:, 1 for back slash

// TODO: Should i do char* or char str[]...
void utils::log(const char* str){
		std::cout << str << '\n';
		std::cin.get();
	}
void* utils::get_proc_handle(std::string_view name){
	auto handle_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);// List of proc entries
	if(handle_snapshot == INVALID_HANDLE_VALUE){ 
		log("[-] Failed to get the snapshot");
		return nullptr;
	} // -1, snapshot fail, ret -1
	PROCESSENTRY32 pe32{};
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if(!Process32First(handle_snapshot, &pe32)){
		log("[-] Failed to  retrieve info about the first process");
		return nullptr;
	}

	//void* handle = nullptr;
	while(Process32Next(handle_snapshot, &pe32)){
		// Iterate proc entries
		std::cout << pe32.szExeFile << '\n';
		if(name == pe32.szExeFile){ 
			log("[+] Got proc ID, returning handle");
			std::cout << pe32.th32ProcessID << '\n';
			return OpenProcess(PROCESS_ALL_ACCESS, false, pe32.th32ProcessID); 
		}
	}
	return nullptr;
}
uintptr_t utils::get_proc_addr(void* hproc, const char* module_name){
	uintptr_t addr {};
	HMODULE module_arr[1024]; // Same as void* arr[1024]
	DWORD cb_needed {};

	if(EnumProcessModulesEx(hproc, module_arr, sizeof(module_arr), &cb_needed, LIST_MODULES_ALL)){
	int count = cb_needed / sizeof(HMODULE);
		for(int i = 0; i < count; ++i){
			std::string name(max_path, '\0');
			DWORD length = GetModuleBaseNameA(hproc, module_arr[i], name.data(), max_path);
			if(length > 0){
				name.resize(length);
			}
			if(_stricmp(name.c_str(), module_name) == 0){
				std::cout << "[+] Notepad.exe Base: " << module_arr[i] << '\n';
				return reinterpret_cast<uintptr_t>(module_arr[i]);
			}
		}
	}
	return 0;
}

void utils::read_proc_mem(void* hproc, uintptr_t base_address, void* buffer, size_t size, size_t* num_bytes_read){
	if(!ReadProcessMemory(
				reinterpret_cast<HANDLE>(hproc),
				reinterpret_cast<LPCVOID>(base_address), 
				reinterpret_cast<LPVOID>(buffer), 
				size,
				num_bytes_read)
			)
	{
		log("[-] Failed to read_proc_mem");
	}
}
void utils::write_proc_mem(void *hproc, uintptr_t base_addr, void *buffer, size_t size, size_t *num_bytes_read){
	if(!WriteProcessMemory(hproc,
				reinterpret_cast<void*>(base_addr),
				reinterpret_cast<void*>(buffer),
				size,
				num_bytes_read))
			{
				log("[-] Failed to write_proc_mem");
			}
}

bool utils::load_bytes(const char* file_path, std::vector<std::uint8_t>& dll_bytes)
{
	
	if(!std::filesystem::path(file_path).extension().string().ends_with(".dll")){
		log("[-] invalid file path");
		return false;
	}	
	std::ifstream file(file_path, std::ios::binary);
	if(!file.good()){
		log("[-] failed to load file");
		return false;
	}

	dll_bytes.resize(std::filesystem::file_size(file_path));
	if(!file.read(reinterpret_cast<char*>(dll_bytes.data()), dll_bytes.size())){
		log("[-] Failed to read data to file");
		return false;
	}
	return true;
}



template<typename T>
void utils::to_lower(T& str){
	if constexpr (std::same_as<T, std::string>){
		std::transform(str.begin(), str.end(), str.begin(), [](char c){
				return std::tolower(c);
				});
	} else if constexpr (std::same_as<T, std::wstring>){
		std::transform(str.begin(), str.end(), str.begin(), [](wchar_t c){
				return std::towlower(c);
				});
	} else{
		log("[-] Failed to_lower()");
	}
}

template<typename T>
T utils::to_lowero(T str){
	T result = str;
	if constexpr (std::same_as<T, std::string>){
		std::transform(str.begin(), str.end(), result.begin(), [](char c){
				return std::tolower(c);
				});
	} else if constexpr (std::same_as<T, std::wstring>){
		std::transform(str.begin(), str.end(), result.begin(), [](wchar_t c){
				return std::towlower(c);
				});
	} else{
		log("[-] Failed to_lower()");
	}
	return result;
}

// Define template types so linker can find definitions to use
template void utils::to_lower<std::string>(std::string& s);
template void utils::to_lower<std::wstring>(std::wstring& s);

template std::string utils::to_lowero<std::string>(std::string str);
template std::wstring utils::to_lowero<std::wstring>(std::wstring str);

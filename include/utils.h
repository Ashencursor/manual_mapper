#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <string_view>
#include <string>

namespace utils {
	void log(const char* str);
	void* get_proc_handle(std::wstring_view name);
	uintptr_t get_module_addr(void* hproc, const char* module_name);
	std::vector<std::string> get_module_names(void* hproc);

	bool read_proc_mem(void* hproc, uintptr_t base_addr, void* buffer, size_t size, size_t* num_bytes_read);
	bool write_proc_mem(void* hproc, uintptr_t base_addr, void* buffer, size_t size, size_t* num_bytes_read);
	bool load_bytes(const char* file_path, std::vector<std::uint8_t>& dll_bytes);

	template<typename T>
	void to_lower(T& str);

	template<typename T>
	T to_lowero(T str);
}

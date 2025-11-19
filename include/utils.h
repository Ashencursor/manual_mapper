#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>
#include <type_traits>

namespace utils {
	void log(const char* str);
	void* get_proc_handle(std::string_view name);
	uintptr_t get_proc_addr(void* hproc, const char* module_name);

	void read_proc_mem(void* hproc, uintptr_t base_addr, void* buffer, size_t size, size_t* num_bytes_read);
	void write_proc_mem(void* hproc, uintptr_t base_addr, void* buffer, size_t size, size_t* num_bytes_read);

	template<typename T>
	void to_lower(T& str);

	template<typename T>
	T to_lowero(T str);
}

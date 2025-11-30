#pragma once
#include <Windows.h>
#include <vector>

namespace PE{
	bool resolve_imports(std::vector<std::uint8_t>& dll_bytes, void* hproc, uintptr_t proc_addr, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt);
	bool relocate_table(uintptr_t proc_addr, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt);
	bool load_sections(std::vector<std::uint8_t>& dll_bytes, uintptr_t local_dll_base, PIMAGE_NT_HEADERS nt);

	union RelocInfo { 
		struct {
			std::uint16_t type : 4;
			std::uint16_t offset : 12;
		};
		std::uint16_t info;
	};
}

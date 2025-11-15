#pragma once
#include <fstream>
#include <format>
#include <string_view>


class CLOG{
	public:
	std::ofstream file;
	// By defualt "will place the position bit at the beginning erasing all contents"(https://stackoverflow.com/questions/17032970/clear-data-inside-text-file-in-c)
	CLOG(const char* name) : file(name,std::ios::out)
	{
		if(!file.good()){
			this->~CLOG();
			return;
		}
		file << "[+] SUCCESS2.0\n";
	}
	template<typename... Args>
	void write(std::string_view fmt, Args&&... args){
		file << std::vformat(fmt, std::make_format_args(std::forward<Args>(args)...)) << '\n';
		file.flush();
	}
	
	~CLOG(){
		file.flush();
		file.close();
	}
};

// TODO: Create some func to get directories to current file and use that as base 
// then use chill_logger.txt as the file to write to

inline CLOG LOG("C:\\Users\\ashen\\Desktop\\projects\\manual_mapper\\chill_logger.txt");




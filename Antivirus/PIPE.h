#pragma once

#include "service.h"

enum APP_MESSAGES {
	EXIT,
	SCAN_FILE,
	SCAN_FOLDER,
	SCAN_OK,
	FIND_NOTHING
};

class PIPE {
public:
	~PIPE();
	void CreateConn(HANDLE, DWORD);
	bool Read(uint8_t*, uint64_t, DWORD&);
	bool Write(uint8_t*, uint64_t);
	void InitConn(PROCESS_INFORMATION);
private:
	HANDLE hPipe;
	std::wstring pipeName;
	std::wstring pipeSddl;
};


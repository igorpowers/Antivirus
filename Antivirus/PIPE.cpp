#include "PIPE.h"


void PIPE::CreateConn(HANDLE userToken, DWORD sessionId) {
    pipeSddl = std::format(L"O:SYG:SYD:(A;OICI;GA;;;{})", //25
        GetUserSid(userToken));
    SECURITY_ATTRIBUTES npsa = GetSecurityAttributes(pipeSddl);
    pipeName = std::format(L"\\\\.\\pipe\\newbiepipe_{}", sessionId); //23
    WriteLog(std::format("Create new pipe with name {}", sessionId));
    hPipe = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE |
        PIPE_WAIT,
        1, //24
        512,
        512,
        0,
        &npsa);
    if (hPipe == INVALID_HANDLE_VALUE) {
        WriteLog("Failed to create named pipe. Error code: " + GetLastError());
        return;
    }
}

PIPE::~PIPE() {
    CloseHandle(hPipe);
    hPipe = INVALID_HANDLE_VALUE;
}

void PIPE::InitConn(PROCESS_INFORMATION pi) {
    //WriteLog("InitConn отработал");
    while (true) {
        BOOL fConnected = ConnectNamedPipe(hPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (fConnected) {
            //WriteLog("fConnected отработал");
            ULONG clientProcessId;
            if (GetNamedPipeClientProcessId(hPipe, &clientProcessId)) {
                if (clientProcessId == pi.dwProcessId) {
                    WriteLog("Клиент успешно подключен");
                    break;
                }
            }
            DisconnectNamedPipe(hPipe);
        }
        else {
            if (GetLastError() != ERROR_PIPE_CONNECTED) {
                WriteLog("ConnectNamedPipe выдал ошибку " + GetLastError());
                return;
            }
        }
    }
}

bool PIPE::Read(uint8_t* data, uint64_t length, DWORD& bytesRead) {
    //WriteLog("Read отработал");
    BOOL fSuccess = ReadFile(
        hPipe,
        data,
        length,
        &bytesRead,
        NULL
    );
    if (!fSuccess || bytesRead == 0)
        return false;
    return true;
}

bool PIPE::Write(uint8_t* data, uint64_t length) {
    //WriteLog("Write отработал");
    DWORD cbWritten = 0;
    BOOL fSuccess = WriteFile(
        hPipe,
        data,
        length,
        &cbWritten,
        NULL
    );
    if (!fSuccess || length != cbWritten)
        return false;
    return true;
}
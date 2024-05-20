#include "PIPE.h"

int _tmain(int argc, TCHAR* argv[]) {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
            {const_cast<LPWSTR>(SERVICE_NAME), (LPSERVICE_MAIN_FUNCTION)ServiceMain},
            {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
        WriteLog("Main: StartServiceCtrlDispatcher returned error");
        return GetLastError();
    }

    WriteLog("Exit from service");
    return 0;
}

std::wstring GetUserSid(HANDLE userToken) {
    std::wstring userSid;
    DWORD err = 0;
    LPVOID pvInfo = NULL;
    DWORD cbSize = 0;
    if (!GetTokenInformation(userToken, TokenUser, NULL, 0, &cbSize)) {
        err = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == err) {
            err = 0;
            pvInfo = LocalAlloc(LPTR, cbSize);
            if (!pvInfo)
                err = ERROR_OUTOFMEMORY;
            else if (!GetTokenInformation(userToken, TokenUser, pvInfo, cbSize, &cbSize))
                err = GetLastError();
            else {
                err = 0;
                const TOKEN_USER* pUser = (const TOKEN_USER*)pvInfo;
                LPWSTR userSidBuf;
                ConvertSidToStringSidW(pUser->User.Sid, &userSidBuf);
                userSid.assign(userSidBuf);
                LocalFree(userSidBuf);
            }
        }
    }
    return userSid;
}

void WriteLog(const std::string& data) {
    if (!errorLog.is_open())
        errorLog.open("C:\\Users\\power\\source\\repos\\Antivirus\\x64\\Debug\\antimalware.log", std::ios::app);
    errorLog << data << std::endl;
}

SECURITY_ATTRIBUTES GetSecurityAttributes(const std::wstring& sddl) {
    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.bInheritHandle = TRUE;
    PSECURITY_DESCRIPTOR psd = nullptr;

    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &psd, nullptr)) {
        securityAttributes.lpSecurityDescriptor = psd;
    }
    else {
        DWORD error = GetLastError();
        WriteLog("SDDL parse error, code: " + std::to_string(error));
    }

    return securityAttributes;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    //GetModuleFileNameA(NULL,  ); вместо setcurrentdirectory, чтобы путь к exe получить, а после 
    SetCurrentDirectory(L"C:\\Users\\power\\source\\repos\\Antivirus\\x64\\Debug");
    
    WriteLog("ServiceMain: Entry");
    g_StatusHandle = RegisterServiceCtrlHandlerEx(SERVICE_NAME, reinterpret_cast<LPHANDLER_FUNCTION_EX>(ServiceCtrlHandler), NULL);
    if (g_StatusHandle == NULL)
    {
        WriteLog("ServiceMain: RegisterServiceCtrlHandler returned error");
        return;
    }
    WriteLog("ServiceMain: Exit");

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN || SERVICE_ACCEPT_SESSIONCHANGE || SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
        WriteLog("ServiceMain: SetServiceStatus returned error");

    SECURITY_ATTRIBUTES jsa = GetSecurityAttributes(L"O:SYG:SYD:");

    PWTS_SESSION_INFO wtsSessions = NULL;
    DWORD sessionCount = 0;
    if (!WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &wtsSessions, &sessionCount)) {
        WriteLog(&"ServiceMain: Troubles with WTSEnumerateSessions"[GetLastError()]);
    }
    else
    {
        for (DWORD i = 0; i < sessionCount; ++i)
        {
            StartProcessInSession(wtsSessions[i].SessionId);
        }
    }
}

DWORD WINAPI ServiceCtrlHandler(DWORD CtrlCode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    WriteLog("ServiceCtrlHandler: Entry");
    DWORD result = ERROR_CALL_NOT_IMPLEMENTED;

    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        WriteLog("ServiceCtrlHandler: SERVICE_CONTROL_STOP Request");
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        result = NO_ERROR;
        break;

    case SERVICE_CONTROL_SHUTDOWN:
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        result = NO_ERROR;
        break;

    case SERVICE_CONTROL_INTERROGATE:
        result = NO_ERROR;
        break;

    case SERVICE_CONTROL_SESSIONCHANGE:
        if (dwEventType == WTS_SESSION_LOGON) {
            WTSSESSION_NOTIFICATION* sessionNotification = reinterpret_cast<WTSSESSION_NOTIFICATION*>(lpEventData);
            StartProcessInSession(sessionNotification->dwSessionId);
        }
        break;
    }

    WriteLog("ServiceCtrlHandler: Exit");
    return result;
}

void PrintResultsToFile(std::ofstream& file, const std::vector<std::string>& data) {
    for (size_t i = 0; i < data.size(); ++i) {
        file << std::format("\t{}: {}", i, data.at(i)) << std::endl;
    }
}

void TerminateAllUiProcesses() {
    for (auto p : processSessions)
        TerminateProcess(p.hProcess, 0);
}

void WriteFolderScanResultsToFile(std::string foldername, const std::map<std::string, std::vector<std::string>>& cont) {
    std::ofstream resultFile(foldername);
    if (!resultFile.is_open())
        WriteLog("Cannot open file to write result of scan");
    else {
        resultFile << "Найденные сигнатуры по файлам:" << std::endl;
        for (const auto& file : cont) {
            resultFile << std::format("{}:", file.first) << std::endl;
            PrintResultsToFile(resultFile, file.second);
        }
    }
    resultFile.close();
}

void WriteFileScanResultsToFile(std::string filename, const std::vector<std::string>& cont) {
    std::ofstream resultFile(filename);
    if (!resultFile.is_open())
        WriteLog("Cannot open file to write result of scan");
    else {
        resultFile << "Найденные сигнатуры:" << std::endl;
        PrintResultsToFile(resultFile, cont);
    }
}

void StartProcessInSession(DWORD sessionId) {
    std::thread clientThread([sessionId]() {
        WriteLog(std::format("StartUIProcessInSession sessionId = {}", sessionId));
        HANDLE hUserToken = NULL;
        if (WTSQueryUserToken(sessionId, &hUserToken)) {
            WCHAR commandLine[] = GUI_PATH_L;
            WCHAR sdCommandLine[] = SD_GUI_PATH_L;
            std::wstring processSddl = std::format(L"O:SYG:SYD:(D;OICI;0x{:08X};;;WD)(A;OICI;0x{:08X};;;WD)",
                PROCESS_TERMINATE, PROCESS_ALL_ACCESS);
            std::wstring threadSddl = std::format(L"O:SYG:SYD:(D;OICI;0x{:08X};;;WD)(A;OICI;0x{:08X};;;WD)",
                THREAD_TERMINATE, THREAD_ALL_ACCESS);

            STARTUPINFO si{};
            PROCESS_INFORMATION pi{};
            SECURITY_ATTRIBUTES psa = GetSecurityAttributes(processSddl);
            SECURITY_ATTRIBUTES tsa = GetSecurityAttributes(threadSddl);
            WriteLog(std::format("Create pipe for sessionId = {}", sessionId));
            if (psa.lpSecurityDescriptor != nullptr &&
                tsa.lpSecurityDescriptor != nullptr) {
                PIPE pp;
                pp.CreateConn(hUserToken, sessionId);
                WriteLog(std::format("Start UI process for sessionId = {}", sessionId));
                if (CreateProcessAsUserW(
                    hUserToken, NULL, commandLine, &psa, &tsa, FALSE,
                    0, NULL, NULL, &si, &pi))
                {
                    processSessions.push_back(pi);
                    WriteLog(std::format("Process created for sessionId = {}", sessionId));
                    pp.InitConn(pi);
                    WriteLog(std::format("Connection from client with sessionId = {}", sessionId));
                    FileSystemScanner sc("C:\\Users\\power\\source\\repos\\Antivirus\\Antivirus\\base.bin");
                    uint8_t fileOrFolderName[MAX_PATH];
                    uint8_t fileToWrite[MAX_PATH];
                    int* signal = 0;
                    DWORD bytesRead = 0;
                    WriteLog("ПЕРЕД WHILE");
                    while (true) {
                        WriteLog("Waiting for data from pipe...");
                        if (!pp.Read(reinterpret_cast<uint8_t*>(&signal), sizeof(int), bytesRead)) {
                            WriteLog("Failed to read data from pipe");
                            break;
                        }
                        WriteLog(std::format("Received signal: {}", *signal));
                        switch (*signal) {
                        case EXIT:
                        {
                            PROCESS_INFORMATION sdpi{};
                            STARTUPINFO sdsi{};
                            if (CreateProcessAsUserW(
                                hUserToken,
                                NULL,
                                sdCommandLine,
                                &psa, &tsa,
                                FALSE, 0,
                                NULL, NULL,
                                &sdsi, &sdpi
                            )) {
                                if (WAIT_OBJECT_0 == WaitForSingleObject(sdpi.hProcess, INFINITE))
                                {
                                    TerminateAllUiProcesses();
                                    return;
                                }
                            }
                            break;
                        }
                        case SCAN_FILE: {
                            WriteLog("Пайп со сканом прилетел");
                            pp.Read(fileOrFolderName, MAX_PATH, bytesRead);
                            pp.Read(fileToWrite, MAX_PATH, bytesRead);
                            std::string filename = reinterpret_cast<char*>(fileOrFolderName);
                            std::vector<std::string> res;
                            if (sc.scanFile(filename, res))
                            {
                                filename = reinterpret_cast<const char*>(fileToWrite);
                                WriteFileScanResultsToFile(filename, res);
                                pp.Write(reinterpret_cast<uint8_t*>(SCAN_OK), sizeof(int));
                            }
                            else
                                pp.Write(reinterpret_cast<uint8_t*>(FIND_NOTHING), sizeof(int));
                            break;
                        }
                        case SCAN_FOLDER:
                        {
                            pp.Read(fileOrFolderName, MAX_PATH, bytesRead);
                            pp.Read(fileToWrite, MAX_PATH, bytesRead);
                            std::string foldername = reinterpret_cast<char*>(fileOrFolderName);
                            std::map<std::string, std::vector<std::string>> res;
                            if (sc.scanFolder(foldername, res)) {
                                foldername = reinterpret_cast<const char*>(fileToWrite);
                                WriteFolderScanResultsToFile(foldername, res);
                                pp.Write(reinterpret_cast<uint8_t*>(SCAN_OK), sizeof(int));
                            }
                            else pp.Write(reinterpret_cast<uint8_t*>(FIND_NOTHING), sizeof(int));
                            break;
                        }
                        }
                    }
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }   
                else WriteLog(std::format("Can\'t parse security descriptor for sessionId = {}: {}", sessionId, GetLastError()));

                auto sd = tsa.lpSecurityDescriptor;
                tsa.lpSecurityDescriptor = nullptr;
                LocalFree(sd);

                sd = psa.lpSecurityDescriptor;
                psa.lpSecurityDescriptor = nullptr;
                LocalFree(sd);
            }

        }
        CloseHandle(hUserToken);
        });
    clientThread.detach();
}

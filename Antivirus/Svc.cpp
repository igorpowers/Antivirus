#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include "../sample.h"
#include <iostream>
#include <Windows.h>
#include <Wtsapi32.h>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")

#define SVCNAME TEXT("Antivirus")

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;
HANDLE                  ghSvcStopEvent = NULL;

VOID SvcInstall(void);
DWORD WINAPI SvcCtrlHandlerEx(DWORD, DWORD, LPVOID, LPVOID);
VOID WINAPI SvcMain(DWORD, LPSTR*);
VOID SvcInit(DWORD, LPSTR*);
BOOL CustomCreateProcess(DWORD, DWORD&);
char* GetUsernameFromSId(DWORD, DWORD&);
void ServiceReportStatus(DWORD, DWORD, DWORD);

VOID SvcInstall() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    DWORD dwModuleFileName = 0;
    TCHAR szPath[MAX_PATH];
    dwModuleFileName = GetModuleFileName(NULL, szPath, MAX_PATH);
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    hService = CreateService(
        hSCManager,
        SVCNAME,
        SVCNAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        szPath,
        NULL, NULL, NULL, NULL, NULL
    );

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}

int __cdecl _tmain(int argc, TCHAR* argv[]) {
    if (lstrcmpi(argv[1], TEXT("install")) == 0) {
        SvcInstall();
        return 0;
    }
    SERVICE_TABLE_ENTRY DispatchTable[] = {
        {(LPWSTR)SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain},
        {NULL, NULL}
    };
    StartServiceCtrlDispatcher(DispatchTable);
}

BOOL CustomCreateProcess(DWORD wtsSession, DWORD& dwBytes) {
    HANDLE userToken;
    PROCESS_INFORMATION pi{};
    STARTUPINFO si{};
    WCHAR path[] = L"C:\\Windows\\System32\\notepad.exe";
    WTSQueryUserToken(wtsSession, &userToken);
    CreateProcessAsUser(userToken, NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    char* pcUserName = GetUsernameFromSId(wtsSession, dwBytes);
    delete[] pcUserName;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

VOID WINAPI SvcMain(DWORD dwArgc, LPSTR* lpArgv) {
    gSvcStatusHandle = RegisterServiceCtrlHandlerEx(SVCNAME, (LPHANDLER_FUNCTION_EX)SvcCtrlHandlerEx, NULL);
    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
    gSvcStatus.dwServiceSpecificExitCode = 0;
    ServiceReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    PWTS_SESSION_INFO wtsSessions = NULL;
    PROCESS_INFORMATION processInfo{};
    DWORD sessionCount = NULL, dwBytes = NULL;

    WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &wtsSessions, &sessionCount);

    for (auto i = 1; i < sessionCount; ++i)
        CustomCreateProcess(wtsSessions[i].SessionId, dwBytes);
    SvcInit(dwArgc, lpArgv);
    while (gSvcStatus.dwCurrentState != SERVICE_STOPPED) {
        if (WaitForSingleObject(ghSvcStopEvent, 60000) != WAIT_TIMEOUT)
            ServiceReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
    }
}

DWORD WINAPI SvcCtrlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    DWORD errorCode = NO_ERROR, dwBytes = NULL;

    switch (dwControl)
    {
    case SERVICE_CONTROL_INTERROGATE:
        break;
    case SERVICE_CONTROL_SESSIONCHANGE: {
        WTSSESSION_NOTIFICATION* sessionNotification = static_cast<WTSSESSION_NOTIFICATION*>(lpEventData);
        char* pcUserName = GetUsernameFromSId(sessionNotification->dwSessionId, dwBytes);
        if (dwEventType == WTS_SESSION_LOGOFF)
            break;
        else if (dwEventType == WTS_SESSION_LOGON)
            CustomCreateProcess(sessionNotification->dwSessionId, dwBytes);
        delete[] pcUserName;
    }
        break;
    case SERVICE_CONTROL_STOP:
        gSvcStatus.dwCurrentState = SERVICE_STOPPED;
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        gSvcStatus.dwCurrentState = SERVICE_STOPPED;
        break;
    default:
        errorCode = ERROR_CALL_NOT_IMPLEMENTED;
        break;
    }

    ServiceReportStatus(gSvcStatus.dwCurrentState, errorCode, 0);
    return errorCode;
}

void ServiceReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    static DWORD dwCheckPoint = 1;
    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;
    if (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED)
        gSvcStatus.dwCheckPoint = 0;
    else
        gSvcStatus.dwCheckPoint = dwCheckPoint++;
    SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

VOID SvcInit(DWORD dwArgc, LPSTR* lpArgv)
{
    ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ghSvcStopEvent == NULL) {
        ServiceReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
    else
        ServiceReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
}

char* GetUsernameFromSId(DWORD sId, DWORD& dwBytes) {
    char* pcUserName = new char[105];
    LPWSTR buff;
    WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sId, WTSUserName, &buff, &dwBytes);
    WideCharToMultiByte(CP_UTF8, 0, buff, -1, pcUserName, 105, 0, 0);
    WTSFreeMemory(buff);
    return pcUserName;
}
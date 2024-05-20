#pragma once


#include <iostream>
#include <fstream>
#include <sstream>
#include <tchar.h>
#include <Windows.h>
#include <WTSApi32.h>
#include <sddl.h>
#include <thread>
#include <format>
#include <vector>
#include <type_traits>
#include "PIPE.h"
#include "FileSystemScanner.h"
#include "log.h"

static SERVICE_STATUS        g_ServiceStatus = { 0 };
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
static std::vector<PROCESS_INFORMATION> processSessions;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
DWORD WINAPI ServiceCtrlHandler(DWORD CtrlCode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContent);
void StartProcessInSession(DWORD sessionId);
SECURITY_ATTRIBUTES GetSecurityAttributes(const std::wstring& sddl);
std::wstring GetUserSid(HANDLE userToken);
void PrintResultsToFile(std::ofstream&, std::vector<std::string> const& name);
void TerminateAllUiProcesses();
void WriteLog(const std::string& data);

#define SERVICE_NAME  _T("Antivirus")
#define GUI_PATH_L L"GUI.exe"
#define SD_GUI_PATH_L L"GUI.exe --secure-desktop"


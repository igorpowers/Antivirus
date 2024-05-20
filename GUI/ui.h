#pragma once

#include <Windows.h>
#include "resource.h"
#include <shlobj.h>
#include <format>
#include <thread>
#include <iostream>
#include <fstream>
#include <sstream>

class __declspec(uuid("9D0B8B92-4E1C-488e-A1E1-2331AFCE2CB5")) PrinterIcon;

#define BUFSIZE 256

enum ANTIVIRUS_MESSAGES {
	EXIT,
	SCAN_FILE,
	SCAN_FOLDER,
	CHOOSE_FILE,
	CHOOSE_FOLDER,
	CHOOSE_WRITE_FILE,
	CANCEL
};

struct GUI {
	HMENU hScanMenu;
	HWND hWelcomeLabel;
	HWND hScanFileBtn;
	HWND hScanFolderBtn;
	HWND hScanFileLabel;
	HWND hScanFolderLabel;
	HWND hChooseFileToWriteBtn;
	HWND hChooseFileToWriteLabel;
	HWND hChooseFileToScan;
	HWND hChooseFolderToScan;
};

UINT const WMAPP_NOTIFYCALLBACK = WM_APP + 1;

HINSTANCE hInst;
HWND hMainWindow;
GUI gui;
OPENFILENAMEW ofn;
TCHAR g_szFolderPath[MAX_PATH];
HANDLE pipe;
wchar_t selectedFilePathToWrite[MAX_PATH];
wchar_t selectedScanFilePath[MAX_PATH];
static std::ofstream errorLog;


LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
WNDCLASS NewWindowClass(HBRUSH, HCURSOR, HINSTANCE, HICON, LPCWSTR, WNDPROC);
void InitWindow(HWND);
void PrepareFileScanMenu(HWND hWnd);
void PrepareFolderScanMenu(HWND hWnd);
void SetOpenFileParams(HWND, LPCTSTR, wchar_t*);
BOOL SelectFolderDialog(HWND);
BOOL AddNotificationIcon(HWND);
void SetMainMenuWindowPos(HWND hWnd);
void ShowContextMenu(HWND, POINT);
void InitializeConnection(HWND);
bool Read(HANDLE, uint8_t*, uint64_t, DWORD&);
bool Write(HANDLE, uint8_t*, uint64_t);
std::wstring GetUserSid(HANDLE);
std::wstring GetCurrentUserSid();
SECURITY_ATTRIBUTES GetSecurityAttributes(const std::wstring&);
void WriteLog(const std::string&);
#include "PacketLogger.h"

using namespace std;

LPWSTR GetCurrentDir() {
	wchar_t lpAppDir[MAX_PATH];
	GetModuleFileName(NULL, lpAppDir, MAX_PATH);
	wchar_t* t = wcsrchr(lpAppDir, L'\\');
	*t = 0;
	return t;
}

void SetConsoleStyle() {
	SetConsoleOutputCP(437);
	CONSOLE_FONT_INFOEX Info;
	ZeroMemory(&Info, sizeof(CONSOLE_FONT_INFOEX));
	Info.cbSize = sizeof(CONSOLE_FONT_INFOEX);
	Info.nFont = 0;
	Info.dwFontSize = COORD{ 8,16 };
	Info.FontFamily = TMPF_TRUETYPE;
	Info.FontWeight = FW_NORMAL;
	lstrcpy(Info.FaceName, L"Consolas");
	SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &Info);
}

int main()
{
	SetConsoleStyle();
	LPWSTR lpDir = L"D:\\Development\\BDS\\";
	wchar_t lpExecutable[MAX_PATH] = { 0 };
	wcscat(lpExecutable, lpDir);
	wcscat(lpExecutable, L"bedrock_server.exe");

	printf("[>] creating BDS process...\n");

	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	PROCESS_INFORMATION pi = { 0 };

	if (!CreateProcess(NULL, lpExecutable, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("[<] failed to create process, error: %d\n", GetLastError());
		return -1;
	}
	HANDLE hProcess = pi.hProcess;

	printf("[>] allocating memory for dll...\n");
	wchar_t lpDllName[MAX_PATH] = { 0 };
	wcscat(lpDllName, GetCurrentDir());
	wcscat(lpDllName, L"HookDll.dll");

	LPVOID lpDllBaseAddress = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!lpDllBaseAddress) {
		printf("[<] failed to allocate memory, error: %d\n", GetLastError());
		return -1;
	}

	if (!WriteProcessMemory(hProcess, lpDllBaseAddress, lpDllName, sizeof(lpDllName), NULL)) {
		printf("[<] failed to write LoadLibrary entry, error: %d\n", GetLastError());
		return -1;
	}

	printf("[>] invoking LoadLibrary...\n");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibrary, lpDllBaseAddress, CREATE_SUSPENDED, NULL);

	printf("[>] resuming suspended threads...\n");
	ResumeThread(pi.hThread);
	if (hThread)
	{
		ResumeThread(hThread);
		WaitForSingleObject(hThread, INFINITE);
	}

	return 0;
}

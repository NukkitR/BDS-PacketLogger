#include <Windows.h>
#include <wincon.h>
#include <Psapi.h>
#include <stdio.h>
#include "minhook/include/MinHook.h"
#include <cstdint>
#include "offset.h"
#include "helper.h"
#include <time.h>

typedef VOID(__stdcall* PACKET_READ_EXTENDED)
(PVOID, PVOID, PVOID);

typedef PVOID(__stdcall* NETWORK_HANDLER_SEND_INTERNAL)
(PVOID, PVOID, PVOID, PVOID);

typedef PVOID(__stdcall* PACKET_GET_NAME)
(PVOID, PVOID);

typedef INT64(__stdcall* PACKET_GET_ID)
(PVOID);

const int BUFFER_MAX = 20 * 1024 * 1024; // Allocate a 20MB buffer

PVOID lpBaseAddress;
PACKET_READ_EXTENDED originalPacketReadExtended = NULL;
NETWORK_HANDLER_SEND_INTERNAL originalNetworkHandlerSendInternal = NULL;
HANDLE hConsole;
PVOID lpStrBuffer;
FILE* fpLog;
int packetCounter = 0;

VOID log(const char* format ...) {
	va_list va;
	va_start(va, format);
	printf("[PacketLogger] ");
	vprintf(format, va);
	fprintf(fpLog, "[PacketLogger] ");
	vfprintf(fpLog, format, va);
}

VOID HookPacketReadExtended(PVOID packet, PVOID ret, PVOID stream) {
	packetCounter++;

	memset(lpStrBuffer, 0, 32);

	PVOID vTable = helper::getVTable(packet);
	PACKET_GET_ID fnPacketGetId = *reinterpret_cast<PACKET_GET_ID*>((uint64_t)vTable + 8);
	PACKET_GET_NAME fnPacketGetName = *reinterpret_cast<PACKET_GET_NAME*>((uint64_t)vTable + 16);

	PVOID buffer = *reinterpret_cast<PVOID*>((uint64_t)stream + 56);
	int readerIndex = *reinterpret_cast<int*>((uint64_t)stream + 8);
	int readableBytes = *reinterpret_cast<int*>((uint64_t)buffer + 16);

	SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	// Get packet Id
	int packetId = fnPacketGetId(packet) & 0x3ff;

	// Get packet Name
	fnPacketGetName(NULL, lpStrBuffer);
	PVOID ptr = lpStrBuffer;
	int strlen = *reinterpret_cast<int*>((uint64_t)lpStrBuffer + 16);
	if (strlen > 16) {
		ptr = *reinterpret_cast<PVOID*>((uint64_t)lpStrBuffer);
	}
	log("[C -> S] PacketId: %d - %s\n", packetId, ptr);

	// Write hex dump to log file
	PVOID data = *reinterpret_cast<PVOID*>((uint64_t)buffer);
	helper::prettyHexDump(data, readerIndex, readableBytes, static_cast<char*>(lpStrBuffer));
	printf("%s\n", lpStrBuffer);
	fprintf(fpLog, "%s\n\n", lpStrBuffer);
	if (packetCounter % 10 == 0) {
		fflush(fpLog); // flush every 10 packets
	}

	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);

	return originalPacketReadExtended(packet, ret, stream);
}

PVOID HookNetworkHandlerSendInternal(PVOID handler, PVOID networkId, PVOID packet, PVOID lpBuffer) {
	packetCounter++;
	memset(lpStrBuffer, 0, 32);

	PVOID vTable = helper::getVTable(packet);
	PACKET_GET_ID fnPacketGetId = *reinterpret_cast<PACKET_GET_ID*>((uint64_t)vTable + 8);
	PACKET_GET_NAME fnPacketGetName = *reinterpret_cast<PACKET_GET_NAME*>((uint64_t)vTable + 16);

	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	// Get packet Id
	int packetId = fnPacketGetId(packet) & 0x3ff;

	// Get packet Name
	PVOID ptr;
	int strlen;
	fnPacketGetName(NULL, lpStrBuffer);
	ptr = lpStrBuffer;
	strlen = *reinterpret_cast<int*>((uint64_t)ptr + 16);
	// NOTE: it's pretty odd here that sometimes the address points to a pointer even when strlen < 16.
	//       therefore we need to check both ptr and *ptr and see where is the packet name in the memory.
	if (!helper::isString(ptr, strlen)) {
		ptr = *reinterpret_cast<PVOID*>((uint64_t)ptr);
	}
	if (!helper::isString(ptr, strlen)) {
		log("[S -> C] PacketId: %d - Packet::getName() FAILED!\n", packetId);
	}
	else {
		log("[S -> C] PacketId: %d - %s\n", packetId, ptr);
	}

	// Write hex dump to log file
	ptr = lpBuffer;
	strlen = *reinterpret_cast<int*>((uint64_t)ptr + 16);
	ptr = *reinterpret_cast<PVOID*>((uint64_t)ptr);
	int readerIndex;
	if (packetId > 0x7f) {
		readerIndex = 2;
	}
	else {
		readerIndex = 1;

	}
	helper::prettyHexDump(ptr, readerIndex, strlen - readerIndex, static_cast<char*>(lpStrBuffer));
	printf("%s\n", lpStrBuffer);
	fprintf(fpLog, "%s\n\n", lpStrBuffer);
	if (packetCounter % 10 == 0) {
		fflush(fpLog);  // flush every 10 packets
	}

	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);

	return originalNetworkHandlerSendInternal(handler, networkId, packet, lpBuffer);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		if (hModule) {
			DisableThreadLibraryCalls(hModule);
		}

		// Get the base address of bedrock_server.exe
		HMODULE hModule = GetModuleHandle(NULL);
		if (!hModule) return FALSE;
		MODULEINFO mi = { 0 };
		if (!GetModuleInformation(GetCurrentProcess(), hModule, &mi, sizeof(mi))) return FALSE;
		lpBaseAddress = mi.lpBaseOfDll;

		// Create log files
		LPCWSTR lpDirName = L"packet_logs\\";
		CreateDirectory(lpDirName, NULL);
		wchar_t lpLogName[MAX_PATH];
		time_t t;
		struct tm* timeinfo;
		time(&t);
		timeinfo = localtime(&t);
		wcsftime(lpLogName, sizeof(lpLogName), L"%Y-%m-%d %H-%M-%S.log", timeinfo);
		wchar_t lpFilePath[MAX_PATH];
		wsprintf(lpFilePath, L"%s%s", lpDirName, lpLogName);
		wprintf(L"%s\n", lpFilePath);
		fpLog = _wfopen(lpFilePath, L"a");
		if (!fpLog) {
			MessageBox(NULL, L"Failed to create log file", L"No good...", NULL);
			return FALSE;
		}
		log("Log file created: %ws\n", lpFilePath);

		// Allocate memory for string buffer
		lpStrBuffer = VirtualAllocEx(GetCurrentProcess(), NULL, BUFFER_MAX, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		// Initialize Minhook
		if (MH_Initialize() != MH_OK) {
			MessageBox(NULL, L"Failed to initialise hook", L"No good...", NULL);
			return FALSE;
		}

		// Start Hooking
		PVOID fpPacketReadExtended = (PVOID)((uint64_t)lpBaseAddress + offset::fn_Packet_ReadExtended);
		PVOID fpNetworkHandlerSendInternal = (PVOID)((uint64_t)lpBaseAddress + offset::fn_NetworkHandler_SendInternal);

		if (
			MH_CreateHook(fpPacketReadExtended, HookPacketReadExtended, reinterpret_cast<LPVOID*>(&originalPacketReadExtended))
			!= MH_OK) {
			MessageBox(NULL, L"Failed to create hook for Packet::ReadExternal", L"No good...", NULL);
			return FALSE;
		}

		if (
			MH_CreateHook(fpNetworkHandlerSendInternal, HookNetworkHandlerSendInternal, reinterpret_cast<LPVOID*>(&originalNetworkHandlerSendInternal))
			!= MH_OK) {
			MessageBox(NULL, L"Failed to create hook for NetworkHandler::_sendInternal", L"No good...", NULL);
			return FALSE;
		}

		if (
			MH_EnableHook(fpPacketReadExtended)
			!= MH_OK) {
			MessageBox(NULL, L"Failed to enable hook for Packet::ReadExternal", L"No good...", NULL);
			return FALSE;
		}

		if (
			MH_EnableHook(fpNetworkHandlerSendInternal)
			!= MH_OK) {
			MessageBox(NULL, L"Failed to enable hook for NetworkHandler::_sendInternal", L"No good...", NULL);
			return FALSE;
		}

		hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(hConsole, BACKGROUND_GREEN);
		log("Hooks are enabled successfully.\n");
		SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		if (fpLog != 0) {
			fclose(fpLog);
		}
		break;
	}

	return TRUE;
}
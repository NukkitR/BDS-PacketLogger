#include <Windows.h>
#include <wincon.h>
#include <Psapi.h>
#include <stdio.h>
#include "minhook/include/MinHook.h"
#include <cstdint>
#include "offset.h"
#include "helper.h"

typedef VOID(__stdcall* PACKET_READ_EXTENDED)
(PVOID, PVOID, PVOID);

typedef PVOID(__stdcall* NETWORK_HANDLER_SEND_INTERNAL)
(PVOID, PVOID, PVOID, PVOID);

typedef PVOID(__stdcall* PACKET_GET_NAME)
(PVOID, PVOID);

typedef INT64(__stdcall* PACKET_GET_ID)
(PVOID);

PVOID lpBaseAddress;
PACKET_READ_EXTENDED originalPacketReadExtended = NULL;
NETWORK_HANDLER_SEND_INTERNAL originalNetworkHandlerSendInternal = NULL;
HANDLE hConsole;
PVOID lpStrBuffer;

VOID log(const char* format ...) {
	va_list va;
	va_start(va, format);
	printf("[PacketLogger] ");
	vprintf(format, va);
}

VOID HookPacketReadExtended(PVOID packet, PVOID ret, PVOID stream) {
	memset(lpStrBuffer, 0, 32);

	PVOID vTable = helper::getVTable(packet);
	PACKET_GET_ID fnPacketGetId = *reinterpret_cast<PACKET_GET_ID*>((uint64_t)vTable + 8);
	PACKET_GET_NAME fnPacketGetName = *reinterpret_cast<PACKET_GET_NAME*>((uint64_t)vTable + 16);

	PVOID buffer = *reinterpret_cast<PVOID*>((uint64_t)stream + 56);
	int readerIndex = *reinterpret_cast<int*>((uint64_t)stream + 8);
	int readableBytes = *reinterpret_cast<int*>((uint64_t)buffer + 16);

	SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	int packetId = fnPacketGetId(packet) & 0x3ff;
	log("[C -> S] PacketId: %d - ", packetId);

	fnPacketGetName(NULL, lpStrBuffer);
	PVOID ptr = lpStrBuffer;
	int strlen = *reinterpret_cast<int*>((uint64_t)lpStrBuffer + 16);
	if (strlen > 16) {
		ptr = *reinterpret_cast<PVOID*>((uint64_t)lpStrBuffer);
	}
	for (int i = 0; i < strlen; i++) {
		CHAR c = *reinterpret_cast<char*>((uint64_t)ptr + i);
		if (c > 31 && c < 127) {
			printf("%c", c);
		}
		else {
			printf(".");
		}
	}
	printf("\n");

	PVOID data = *reinterpret_cast<PVOID*>((uint64_t)buffer);
	helper::printHexDump(data, readerIndex, readableBytes);
	printf("\n");

	SetConsoleTextAttribute(hConsole, FOREGROUND_INTENSITY);
	return originalPacketReadExtended(packet, ret, stream);
}

PVOID HookNetworkHandlerSendInternal(PVOID handler, PVOID networkId, PVOID packet, PVOID lpBuffer) {
	memset(lpStrBuffer, 0, 32);

	PVOID vTable = helper::getVTable(packet);
	PACKET_GET_ID fnPacketGetId = *reinterpret_cast<PACKET_GET_ID*>((uint64_t)vTable + 8);
	PACKET_GET_NAME fnPacketGetName = *reinterpret_cast<PACKET_GET_NAME*>((uint64_t)vTable + 16);

	SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	int packetId = fnPacketGetId(packet) & 0x3ff;
	log("[S -> C] PacketId: %d - ", packetId);

	PVOID ptr;
	int strlen;
	fnPacketGetName(NULL, lpStrBuffer);
	ptr = lpStrBuffer;
	strlen = *reinterpret_cast<int*>((uint64_t)ptr + 16);
	ptr = *reinterpret_cast<PVOID*>((uint64_t)ptr);

	for (int i = 0; i < strlen; i++) {
		CHAR c = *reinterpret_cast<char*>((uint64_t)ptr + i);
		if (c > 31 && c < 127) {
			printf("%c", c);
		}
		else {
			printf(".");
		}
	}
	printf("\n");

	ptr = lpBuffer;
	strlen = *reinterpret_cast<int*>((uint64_t)ptr + 16);
	ptr = *reinterpret_cast<PVOID*>((uint64_t)ptr);

	if (packetId > 0x7f) {
		helper::printHexDump(ptr, 2, strlen - 2);
	}
	else {
		helper::printHexDump(ptr, 1, strlen - 1);
	}
	printf("\n");

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

		// Allocate memory for string buffer
		lpStrBuffer = VirtualAllocEx(GetCurrentProcess(), NULL, 32, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		// Initialize Minhook
		if (MH_Initialize() != MH_OK) {
			MessageBox(NULL, L"Failed to initialise hook", L"No good...", NULL);
			return FALSE;
		}

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
		break;
	}

	return TRUE;
}
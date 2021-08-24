#pragma once
#include <Windows.h>
#include <cmath>

namespace helper {

	PVOID getVTable(PVOID lpObject) {
		return *reinterpret_cast<PVOID*>((uint64_t)lpObject);
	}

	VOID parseString(PVOID lpStr, PVOID* lpBuffer, int* len) {
		PVOID ptr = lpStr;
		int strlen = *reinterpret_cast<int*>((uint64_t)lpStr + 16);
		if (strlen > 16) {
			ptr = *reinterpret_cast<PVOID*>((uint64_t)lpStr);
		}
		*len = strlen;
		*lpBuffer = ptr;
		return;
	}

	VOID printHexDump(PVOID buffer, int readerIndex, int len) {
		if (len <= 0) return;
		// HEADER
		printf("         ");
		for (int i = 0; i < 51; i++) {
			printf("-");
		}
		printf("\n         | ");
		for (int i = 0; i < 16; i++) {
			printf("%02x ", i);
		}
		printf("|\n");
		for (int i = 0; i < 79; i++) {
			printf("-");
		}

		// BODY
		BYTE b;
		CHAR c;
		for (int row = 0; row < ceil(1.0 * len / 16); row++) {
			printf("\n%08x | ", row * 16);
			for (int col = 0; col < 16; col++) {
				int i = row * 16 + col;
				if (i < len) {
					b = *reinterpret_cast<byte*>((uint64_t)buffer + readerIndex + i);
					printf("%02x ", b);
				}
				else {
					printf("   ");
				}
			}
			printf("| ");
			for (int col = 0; col < 16; col++) {
				int i = row * 16 + col;
				if (i < len) {
					c = *reinterpret_cast<char*>((uint64_t)buffer + readerIndex + i);
					if (c > 31 && c < 127) {
						printf("%c", c);
					}
					else {
						printf(".");
					}
				}
				else {
					printf(" ");
				}
			}
			printf(" |");
		}

		// FOOTER
		printf("\n");
		for (int i = 0; i < 79; i++) {
			printf("-");
		}
		return;
	}
}
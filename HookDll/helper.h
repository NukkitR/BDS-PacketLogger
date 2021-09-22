#pragma once
#include <Windows.h>
#include <cmath>

namespace helper {

	PVOID getVTable(PVOID lpObject) {
		return *reinterpret_cast<PVOID*>((uint64_t)lpObject);
	}

	BOOL isString(PVOID lpBuffer, int len) {
		CHAR c;
		for (int i = 0; i < len; i++) {
			c = *reinterpret_cast<char*>((uint64_t)lpBuffer + i);
			if (c < 32 || c >126) return FALSE;
		}
		return TRUE;
	}

	int hexDump(PVOID lpInBuffer, int readerIndex, int len, char* lpOutBuffer) {
		if (len <= 0) return 0;
		int outLen = 0;

		BYTE b;
		for (int i = 0; i < len; i++) {
			b = *reinterpret_cast<byte*>((uint64_t)lpInBuffer + readerIndex + i);
			outLen += sprintf(lpOutBuffer + outLen, "%02x ", b);
		}

		*(lpOutBuffer + outLen) = 0;
		return outLen;
	}

	int prettyHexDump(PVOID lpInBuffer, int readerIndex, int len, char* lpOutBuffer) {
		*(lpOutBuffer) = 0;
		if (len <= 0) return 0;

		int outLen = 0;
		// HEADER
		outLen += sprintf(lpOutBuffer + outLen, "         ");
		for (int i = 0; i < 51; i++) {
			outLen += sprintf(lpOutBuffer + outLen, "-");
		}
		outLen += sprintf(lpOutBuffer + outLen, "\n         | ");
		for (int i = 0; i < 16; i++) {
			outLen += sprintf(lpOutBuffer + outLen, " %01x ", i);
		}
		outLen += sprintf(lpOutBuffer + outLen, "|\n");
		for (int i = 0; i < 79; i++) {
			outLen += sprintf(lpOutBuffer + outLen, "-");
		}

		// BODY
		BYTE b;
		CHAR c;
		for (int row = 0; row < ceil(1.0 * len / 16); row++) {
			outLen += sprintf(lpOutBuffer + outLen, "\n%08x | ", row * 16);
			for (int col = 0; col < 16; col++) {
				int i = row * 16 + col;
				if (i < len) {
					b = *reinterpret_cast<byte*>((uint64_t)lpInBuffer + readerIndex + i);
					outLen += sprintf(lpOutBuffer + outLen, "%02x ", b);
				}
				else {
					outLen += sprintf(lpOutBuffer + outLen, "   ");
				}
			}

			outLen += sprintf(lpOutBuffer + outLen, "| ");
			for (int col = 0; col < 16; col++) {
				int i = row * 16 + col;
				if (i < len) {
					c = *reinterpret_cast<char*>((uint64_t)lpInBuffer + readerIndex + i);
					if (c > 31 && c < 127) {
						outLen += sprintf(lpOutBuffer + outLen, "%c", c);
					}
					else {
						outLen += sprintf(lpOutBuffer + outLen, ".");
					}
				}
				else {
					outLen += sprintf(lpOutBuffer + outLen, " ");
				}
			}
			outLen += sprintf(lpOutBuffer + outLen, " |");
		}

		// FOOTER
		outLen += sprintf(lpOutBuffer + outLen, "\n");
		for (int i = 0; i < 79; i++) {
			outLen += sprintf(lpOutBuffer + outLen, "-");
		}

		*(lpOutBuffer + outLen) = 0;

		return outLen;
	}
}
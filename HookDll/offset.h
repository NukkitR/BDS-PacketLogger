#pragma once
#include <cstdint>
#include <cstddef>

namespace offset {

	const uint64_t fn_Packet_ReadExtended = 0x3C96D0;
	/*
	Connection *__fastcall NetworkHandler::_sendInternal(
        NetworkHandler* this,
        const struct NetworkIdentifier *a2,
        Packet *packet,
        PVOID packetBody)
	*/
	const uint64_t fn_NetworkHandler_SendInternal = 0x6B4B60;
}
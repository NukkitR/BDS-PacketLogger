#pragma once
#include <cstdint>
#include <cstddef>

namespace offset {

	/*
	CompleteResult *__fastcall Packet::readExtended(
		Packet* packet, 
		ReadOnlyBinaryStream *stream, 
		PVOID a3)
	*/
	const uint64_t fn_Packet_ReadExtended = 0x348C70;
	/*
	Connection *__fastcall NetworkHandler::_sendInternal(
        NetworkHandler* this,
        const struct NetworkIdentifier *a2,
        Packet *packet,
        PVOID packetBody)
	*/
	const uint64_t fn_NetworkHandler_SendInternal = 0x62B250;
}
#pragma once
#include <cstdint>
#include <cstddef>

namespace offset {

	/*
	CompleteResult *__fastcall Packet::readExtended(
		Packet* packet, 
		ReadOnlyBinaryStream *stream, 
		PVOID result)
	*/
	const uint64_t fn_Packet_ReadExtended = 0x367B30;
	/*
	Connection *__fastcall NetworkHandler::_sendInternal(
        NetworkHandler* this,
        const struct NetworkIdentifier *networkId,
        Packet *packet,
        PVOID packetBody)
	*/
	const uint64_t fn_NetworkHandler_SendInternal = 0x646280;
}
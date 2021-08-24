# BDS-PacketLogger

This is a PoC project to log all the packets running throught BDS by using trampoline hook.

## Features
* No hard-coded value used for packets, all dumped from memory at runtime
* Reliable and easy to use, no need to create a proxy
* Get rid of encryption LOL

## Screenshots
![](https://github.com/NukkitReborn/BDS-PacketLogger/raw/master/screenshots/screenshot1.png)
![](https://github.com/NukkitReborn/BDS-PacketLogger/raw/master/screenshots/screenshot2.png)

## How to update
There are two offsets used in this project, which can be located in `offset.h`.

`fn_Packet_ReadExtended` is the relative address of function `Packet::readExtended` in module `bedrock_server.exe`. Currently, the value is `0x3C96D0`.

`fn_NetworkHandler_SendInternal` is the relative address of function `NetworkHandler::_sendInternal` in module `bedrock_server.exe`. Currently, the value is `0x6B4B60`.

The values can be easily updated from the Program Database File `bedrock_server.pdb` which comes along with the executable.

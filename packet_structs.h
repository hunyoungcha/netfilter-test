#pragma once
#include "ip.h"

#pragma pack(push, 1)

struct IpHdr {
    uint8_t VersionAndIhl;
    uint8_t TOS;
    uint16_t TotalLength;

    uint16_t Identification;
    uint16_t FlagAndFragmentOffset;

    uint8_t TTL;
    uint8_t Protocol;
    uint16_t HeaderChecksum;

    Ip SrcIp;
    Ip DstIp;
};

struct TcpHdr {
    uint16_t SourcePort;
    uint16_t DestinationPort;

    uint32_t SequenceNumber;
    uint32_t ACKNumber;

    uint8_t DataOffsetAndReserved;
    uint8_t Flag;

    uint16_t Window;
    
    uint16_t Checksum;
    uint16_t UrgentPointer;
};

#pragma pack(pop)

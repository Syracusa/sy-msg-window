#ifndef TEST_H
#define TEST_H

#include <stdint.h>
#include "iface.h"

#pragma pack(push, 1)
typedef struct SimMsg
{
    uint16_t len;
    uint16_t seq;
    unsigned char payload[];
} __attribute__((packed)) SimMsg;
#pragma pack(pop)


#endif
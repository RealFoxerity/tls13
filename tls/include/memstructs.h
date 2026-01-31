#ifndef MEMSTRUCTS_H
#define MEMSTRUCTS_H

struct {
    unsigned int len;
    void * data;
} typedef Vector;

struct {
    Vector public_key;
    Vector private_key;
} typedef Keys;

#endif
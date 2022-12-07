#ifndef TEST_TOOLS_H
#define TEST_TOOLS_H

#include <stdio.h>
#include <unistd.h>

void read_file(const char* file_name, uint8_t* d, size_t size);
void write_file(const char* file_name, uint8_t* data, size_t size);
void clear_file(const char* filename);

#endif /* test_tools_h */

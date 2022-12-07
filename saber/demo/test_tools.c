#include "test_tools.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

void read_file(const char* file_name, uint8_t* d, size_t size) {
    FILE* fr;
    fr = fopen(file_name, "r");
    if (fr == NULL) {
        printf("file can't be opened for reading\n");
        exit(1);
    }
    fread(d, sizeof(char), size, fr);
    fclose(fr);
}

void write_file(const char* file_name, uint8_t* data, size_t size) {
    FILE *fw;
    fw = fopen(file_name, "w");
    if (fw == NULL) {
		printf("file can't be opened for writing\n");
		exit(1);
	}
    fwrite(data, sizeof(char), size, fw);
    fclose(fw);
}

void clear_file(const char* filename) {
    fclose(fopen(filename, "w"));
}

/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <sgx_tprotected_fs.h> /* protected open/read/write functions */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

char *buffer;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void free_buffer()
{
    if(buffer != NULL) free(buffer);
}

void ecall_allocate(size_t size) 
{
    buffer = (char *) malloc(size * sizeof(char));
    if(buffer == NULL)  printf("Error allocating buffer memory with size of %d\n", size);  
}


size_t ecall_write_to_disk(const char *fname, size_t size)
{
    SGX_FILE* sFile = sgx_fopen_auto_key(fname, "w");
    if(sFile == NULL)
    {   
        printf("failed to open the file!\n");
        return 0;
    } 
    
    size_t result = sgx_fwrite(buffer, sizeof(char), size, sFile);
    /*printf("error number is %d \n" , sgx_ferror(sFile));
    if(sgx_ferror(sFile) != 0) {
        printf("File is in a bad status and now fixing it!\n");
        sgx_clearerr(sFile);
        if(sgx_ferror(sFile) != 0) printf("problem couldn't be fixed!\n");
    }*/
    if(result != size)
    {
        printf("writting failed!\n");
        return 0;
    }

    if(sgx_fclose(sFile) != 0)
    {
        printf("failed to close the file!\n");
        return 0;
    } 
    free_buffer();
    return result;
}

size_t ecall_read_from_disk(const char *fname, size_t size)
{
    SGX_FILE* sFile = sgx_fopen_auto_key(fname, "r");
    if(sFile == NULL)
    {   
        printf("failed to open the file!\n");
        return 0;
    }
    ecall_allocate(size);
    size_t result = sgx_fread(buffer, sizeof(char), size, sFile);
    if(result != size)
    {
        printf("reading failed!\n");
        return 0;
    }

    if(sgx_fclose(sFile) != 0)
    {
        printf("failed to close the file!\n");
        return 0;
    } 
    free_buffer();
    return result;
}

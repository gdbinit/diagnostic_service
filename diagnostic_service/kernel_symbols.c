/*
 *  _(`-')     _     (`-')  _           <-. (`-')_             (`-').->(`-')      _
 * ( (OO ).-> (_)    (OO ).-/     .->      \( OO) )     .->    ( OO)_  ( OO).->  (_)     _
 *  \    .'_  ,-(`-')/ ,---.   ,---(`-'),--./ ,--/ (`-')----. (_)--\_) /    '._  ,-(`-') \-,-----.
 *  '`'-..__) | ( OO)| \ /`.\ '  .-(OO )|   \ |  | ( OO).-.  '/    _ / |'--...__)| ( OO)  |  .--./
 *  |  |  ' | |  |  )'-'|_.' ||  | .-, \|  . '|  |)( _) | |  |\_..`--. `--.  .--'|  |  ) /_) (`-')
 *  |  |  / :(|  |_/(|  .-.  ||  | '.(_/|  |\    |  \|  |)|  |.-._)   \   |  |  (|  |_/  ||  |OO )
 *  |  '-'  / |  |'->|  | |  ||  '-'  | |  | \   |   '  '-'  '\       /   |  |   |  |'->(_'  '--'\
 *  `------'  `--'   `--' `--' `-----'  `--'  `--'    `-----'  `-----'    `--'   `--'      `-----'
 *  (`-').->(`-')  _   (`-')       (`-')  _                (`-')  _
 *  ( OO)_  ( OO).-/<-.(OO )      _(OO ) (_)     _         ( OO).-/
 * (_)--\_)(,------.,------,),--.(_/,-.\ ,-(`-') \-,-----.(,------.
 * /    _ / |  .---'|   /`. '\   \ / (_/ | ( OO)  |  .--./ |  .---'
 * \_..`--.(|  '--. |  |_.' | \   /   /  |  |  ) /_) (`-')(|  '--.
 * .-._)   \|  .--' |  .   .'_ \     /_)(|  |_/  ||  |OO ) |  .--'
 * \       /|  `---.|  |\  \ \-'\   /    |  |'->(_'  '--'\ |  `---.
 *  `-----' `------'`--' '--'    `-'     `--'      `-----' `------'
 *
 * A kernel rootkit loader based on processor_set_tasks() vulnerability
 *
 * Copyright (c) fG!, 2014, 2015. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * kernel_symbols.c
 * Functions related to solve kernel symbols
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "kernel_symbols.h"

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <mach/processor_set.h>
#include <mach/mach_vm.h>
#include <sys/param.h>
#include <mach/mach.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

#include "logging.h"

#pragma mark Mach-O header and symbol related functions

/*
 * retrieve necessary mach-o header information from the kernel buffer
 * results stored in kernel_info structure
 */
kern_return_t
process_kernel_mach_header(const uint8_t *kernel_buffer, struct kernel_info *kinfo)
{
    if (kernel_buffer == NULL || kinfo == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return KERN_FAILURE;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64*)kernel_buffer;
    /* only support for 64 bits kernels */
    if (mh->magic != MH_MAGIC_64)
    {
        return KERN_FAILURE;
    }
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        ERROR_MSG("Invalid nr of commands or size.");
        return KERN_FAILURE;
    }
    
    struct load_command *load_cmd = NULL;
    // point to the first load command
    char *load_cmd_addr = (char*)kernel_buffer + sizeof(struct mach_header_64);
    // iterate over all load cmds and retrieve required info to solve symbols
    // __LINKEDIT location and symbol/string table location
    int found_linkedit = 0;
    int found_symtab = 0;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
            {
                kinfo->linkedit_fileoff = seg_cmd->fileoff;
                kinfo->linkedit_size    = seg_cmd->filesize;
                /* set a pointer to __LINKEDIT location in the kernel buffer */
                kinfo->linkedit_buf = kernel_buffer + kinfo->linkedit_fileoff;
                found_linkedit++;
            }
        }
        // table information available at LC_SYMTAB command
        else if (load_cmd->cmd == LC_SYMTAB)
        {
            struct symtab_command *symtab_cmd = (struct symtab_command*)load_cmd;
            kinfo->symboltable_fileoff    = symtab_cmd->symoff;
            kinfo->symboltable_nr_symbols = symtab_cmd->nsyms;
            kinfo->stringtable_fileoff    = symtab_cmd->stroff;
            kinfo->stringtable_size       = symtab_cmd->strsize;
            found_symtab++;
        }
        load_cmd_addr += load_cmd->cmdsize;
    }
    
    /* validate if we got all info we need */
    if (found_linkedit == 0 || found_symtab == 0)
    {
        ERROR_MSG("Failed to find all necessary kernel mach-o header information.");
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

/*
 * function to solve a kernel symbol
 */
mach_vm_address_t
solve_kernel_symbol(struct kernel_info *kinfo, char *symbol_to_solve)
{
    struct nlist_64 *nlist = NULL;
    
    if (kinfo == NULL || kinfo->linkedit_buf == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return 0;
    }
    
    for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++)
    {
        // symbols and strings offsets into LINKEDIT
        mach_vm_address_t symbol_off = kinfo->symboltable_fileoff - kinfo->linkedit_fileoff;
        mach_vm_address_t string_off = kinfo->stringtable_fileoff - kinfo->linkedit_fileoff;
        
        nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
        char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
        // find if symbol matches
        if (strncmp(symbol_to_solve, symbol_string, strlen(symbol_to_solve)) == 0)
        {
//            DEBUG_MSG("Found kernel symbol %s at %p (without ASLR: %p)", symbol_to_solve, (void*)(nlist->n_value + kinfo->kaslr_slide), (void*)nlist->n_value);
            // the symbols are without kernel ASLR so we need to add it
            return (nlist->n_value + kinfo->kaslr_slide);
        }
    }
    // failure
    return 0;
}

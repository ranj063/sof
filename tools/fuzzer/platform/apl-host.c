// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2019 Intel Corporation. All rights reserved.
//

/* Core IA host SHIM support for Apollolake audio DSP. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include "shim.h"
#include "cavs.h"
#include "hda.h"
#include <ipc/trace.h>
#include <ipc/info.h>
#include "../fuzzer.h"
#include "../qemu-bridge.h"

pthread_cond_t apl_cond = PTHREAD_COND_INITIALIZER;

struct apl_data {
	void *bar[MAX_BAR_COUNT];
	struct mailbox host_box;
	struct mailbox dsp_box;
	int boot_complete;
	pthread_mutex_t mutex;
};

/* Platform host description taken from Qemu  - mapped to BAR 0 - 4 */
static struct fuzzer_mem_desc apl_mem[] = {
    {.name = "l2-sram", .base = ADSP_CAVS_1_5_DSP_SRAM_BASE,
     .size = ADSP_CAVS_1_5_DSP_SRAM_SIZE},
    {.name = "hp-sram", .base = ADSP_CAVS_1_5_DSP_HP_SRAM_BASE,
     .size = ADSP_CAVS_1_5_DSP_HP_SRAM_SIZE,
     .alias = ADSP_CAVS_1_5_DSP_UNCACHE_BASE},
    {.name = "lp-sram", .base = ADSP_CAVS_1_5_DSP_LP_SRAM_BASE,
     .size = ADSP_CAVS_1_5_DSP_LP_SRAM_SIZE},
    {.name = "imr", .base = ADSP_CAVS_1_5_DSP_IMR_BASE,
     .size = ADSP_CAVS_1_5_DSP_IMR_SIZE},
    {.name = "rom", .base = ADSP_CAVS_DSP_ROM_BASE,
     .size = ADSP_CAVS_DSP_ROM_SIZE},
};

/* mapped to BAR 5, 6*/
static struct fuzzer_reg_space apl_io[] = {
	{ .name = "ipc",
	  .desc = {.base = ADSP_CAVS_HOST_IPC_BASE,
		   .size = ADSP_CAVS_1_5_DSP_IPC_HOST_SIZE},},
	{ .name = "shim",
	  .desc = {.base = ADSP_CAVS_HOST_SHIM_BASE,
		   .size = ADSP_CAVS_1_5_SHIM_SIZE},},
};

#define APL_DSP_IPC_BAR	5
#define APL_MBOX_BAR	1
#define MBOX_OFFSET	0xf000

/*
 * Platform support for APL.
 *
 * The IPC portions below are copied and pasted from the SOF driver with some
 * modification for data structure and printing.
 *
 * The "driver" code below no longer writes directly to the HW but writes
 * to the virtual HW as exported by qemu as Posix SHM and message queues.
 *
 * Register IO and mailbox IO is performed using shared memory regions between
 * fuzzer and qemu.
 *
 * IRQs are send using message queues between fuzzer and qemu.
 *
 * SHM and message queues can be inspected from the cmd line by using
 * "less -C" on /dev/shm/name and /dev/mqueue/name
 */
static uint32_t dsp_read32(struct fuzz *fuzzer, unsigned int bar,
			   unsigned int reg)
{
	struct apl_data *data = fuzzer->platform_data;

	return *((uint32_t *)(data->bar[bar] + reg));
}

static void dsp_write32(struct fuzz *fuzzer, unsigned int bar,
			unsigned int reg, uint32_t value)
{
	struct apl_data *data = fuzzer->platform_data;
	struct qemu_io_msg_reg32 reg32;
	struct qemu_io_msg_irq irq;
	uint32_t dipcie, dipct, dipcctl;

	/* write value to SHM */
	*((uint32_t *)(data->bar[bar] + reg)) = value;

	/* most IO is handled by SHM, but there are some exceptions */
	switch (reg) {
	case HDA_DSP_REG_HIPCT:

		/* now set status bit */
		dipcie = dsp_read32(fuzzer, bar, IPC_DIPCIE) | IPC_DIPCIE_DONE;
		dsp_write32(fuzzer, bar, IPC_DIPCIE, dipcie);

		dipcctl = dsp_read32(fuzzer, bar, IPC_DIPCCTL5) |
				IPC_DIPCCTL5_IPCIDIE;
		dsp_write32(fuzzer, bar, IPC_DIPCCTL5, dipcctl);

		printf("irq: send done interrupt 0x%8.8x\n", value);

		/* send IRQ to child */
		irq.hdr.type = QEMU_IO_TYPE_IRQ;
		irq.hdr.msg = QEMU_IO_MSG_IRQ;
		irq.hdr.size = sizeof(irq);
		irq.irq = 0;

		qemu_io_send_msg(&irq.hdr);
		break;
	case HDA_DSP_REG_HIPCI:

		/* set status bit */
		dipct = dsp_read32(fuzzer, bar, IPC_DIPCT) | IPC_DIPCT_DSPLRST;
		dsp_write32(fuzzer, bar, IPC_DIPCT, dipct);

		printf("dipct 0x%x\n", dipct);

		dipcctl = dsp_read32(fuzzer, bar, IPC_DIPCCTL5) |
				     IPC_DIPCCTL5_IPCTBIE;
		dsp_write32(fuzzer, bar, IPC_DIPCCTL5, dipcctl);

		printf("irq: send busy interrupt 0x%8.8x\n", value);

		/* send IRQ to child */
		irq.hdr.type = QEMU_IO_TYPE_IRQ;
		irq.hdr.msg = QEMU_IO_MSG_IRQ;
		irq.hdr.size = sizeof(irq);
		irq.irq = 0;
		qemu_io_send_msg(&irq.hdr);
		break;
	default:
		break;
	}
}

static uint64_t dsp_update_bits32_unlocked(struct fuzz *fuzzer,
					   unsigned int bar, uint32_t offset,
					   uint32_t mask, uint32_t value)
{
	struct apl_data *data = fuzzer->platform_data;
	uint32_t old, new;
	uint32_t ret;

	ret = dsp_read32(fuzzer, bar, offset);
	old = ret;

	new = (old & ~mask) | (value & mask);

	if (old == new)
		return 0;

	dsp_write32(fuzzer, bar, offset, new);
	return 1;
}

static void mailbox_read(struct fuzz *fuzzer, unsigned int offset,
			 void *mbox_data, unsigned int size)
{
	struct apl_data *data = fuzzer->platform_data;

	memcpy(mbox_data, (void *)(data->bar[APL_MBOX_BAR] + offset), size);
}

static void mailbox_write(struct fuzz *fuzzer, unsigned int offset,
			  void *mbox_data, unsigned int size)
{
	struct apl_data *data = fuzzer->platform_data;

	memcpy((void *)(data->bar[APL_MBOX_BAR] + offset), mbox_data, size);
}

static void apl_ipc_host_done(struct fuzz *fuzzer)
{
	/*
	 * tell DSP cmd is done - clear busy
	 * interrupt and send reply msg to dsp
	 */
	dsp_update_bits32_unlocked(fuzzer, APL_DSP_IPC_BAR,
				   HDA_DSP_REG_HIPCT,
				   HDA_DSP_REG_HIPCT_BUSY,
				   ~HDA_DSP_REG_HIPCT_BUSY);
#if 0
	/* unmask BUSY interrupt */
	dsp_update_bits64_unlocked(fuzzer, APL_DSP_IPC_BAR,
				   HDA_DSP_REG_HIPCCTL,
				   HDA_DSP_REG_HIPCCTL_BUSY,
				   HDA_DSP_REG_HIPCCTL_BUSY);
#endif
}

static void apl_ipc_dsp_done(struct fuzz *fuzzer)
{
	/*
	 * set DONE bit - tell DSP we have received the reply msg
	 * from DSP, and processed it, don't send more reply to host
	 */
	dsp_update_bits32_unlocked(fuzzer, APL_DSP_IPC_BAR,
				   HDA_DSP_REG_HIPCIE,
				   HDA_DSP_REG_HIPCIE_DONE,
				   ~HDA_DSP_REG_HIPCIE_DONE);
#if 0
	/* unmask Done interrupt */
	dsp_update_bits64_unlocked(fuzzer, APL_DSP_IPC_BAR,
				   HDA_DSP_REG_HIPCCTL,
				   HDA_DSP_REG_HIPCCTL_DONE,
				   HDA_DSP_REG_HIPCCTL_DONE);
#endif
}

/*
 * IPC Doorbell IRQ handler and thread.
 */

static int apl_irq_handler(int irq, void *context)
{
	/* only IPC interrutps for now */
	return IRQ_WAKE_THREAD;
}

static int apl_irq_thread(int irq, void *context)
{
	struct fuzz *fuzzer = (struct fuzz *)context;
	struct apl_data *data = fuzzer->platform_data;
	uint32_t hipci;
	uint32_t hipcie;
	uint32_t hipct;
	uint32_t hipcte;
	uint32_t msg;
	uint32_t msg_ext;

	/* read IPC status */
	hipcie = dsp_read32(fuzzer, APL_DSP_IPC_BAR, HDA_DSP_REG_HIPCIE);
	hipct = dsp_read32(fuzzer, APL_DSP_IPC_BAR, HDA_DSP_REG_HIPCT);
	hipci = dsp_read32(fuzzer, APL_DSP_IPC_BAR, HDA_DSP_REG_HIPCI);
	hipcte = dsp_read32(fuzzer, APL_DSP_IPC_BAR, HDA_DSP_REG_HIPCTE);

	/* is this a reply message from the DSP */
	if (hipcie & HDA_DSP_REG_HIPCIE_DONE) {
		printf ("reply message \n");
		msg = hipci & HDA_DSP_REG_HIPCI_MSG_MASK;
		msg_ext = hipcie & HDA_DSP_REG_HIPCIE_MSG_MASK;

		/* handle immediate reply from DSP core - ignore ROM messages */
		fuzzer_ipc_msg_reply(fuzzer);
#if 0
		/* wake up sleeper if we are loading code */
		if (sdev->code_loading)	{
			sdev->code_loading = 0;
			wake_up(&sdev->waitq);
		}
#endif
		/* set the done bit */
		apl_ipc_dsp_done(fuzzer);
	}

	/* is this a new message from DSP */
	if (hipct & HDA_DSP_REG_HIPCT_BUSY) {

		printf ("new message \n");

		msg = hipct & HDA_DSP_REG_HIPCT_MSG_MASK;
		msg_ext = hipcte & HDA_DSP_REG_HIPCTE_MSG_MASK;

		/* handle messages from DSP */
		if ((hipct & SOF_IPC_PANIC_MAGIC_MASK) == SOF_IPC_PANIC_MAGIC) {
			/* TODO: this is a PANIC message !! */
		} else {
			/* normal message - process normally */
			fuzzer_ipc_msg_rx(fuzzer);
		}

		if (!data->boot_complete && fuzzer->boot_complete) {
			data->boot_complete = 1;
			apl_ipc_host_done(fuzzer);
			pthread_cond_signal(&apl_cond);
			return IRQ_HANDLED;
		}
	}

	return IRQ_HANDLED;
}

static int apl_send_msg(struct fuzz *fuzzer, struct ipc_msg *msg)
{
	struct fuzz_platform *plat = fuzzer->platform;
	struct apl_data *data = fuzzer->platform_data;

	/* send IPC message to DSP */
	mailbox_write(fuzzer, data->host_box.offset, msg->msg_data,
		      msg->msg_size);
	dsp_write32(fuzzer, APL_DSP_IPC_BAR, HDA_DSP_REG_HIPCI,
		    HDA_DSP_REG_HIPCI_BUSY);

	return 0;
}

static int apl_get_reply(struct fuzz *fuzzer, struct ipc_msg *msg)
{
	struct fuzz_platform *plat = fuzzer->platform;
	struct apl_data *data = fuzzer->platform_data;
	struct sof_ipc_reply reply;
	int ret = 0;
	uint32_t size;

	/* get reply */
	mailbox_read(fuzzer, data->host_box.offset, &reply, sizeof(reply));

	if (reply.error < 0) {
		size = sizeof(reply);
		ret = reply.error;
	} else {
		/* reply correct size ? */
		if (reply.hdr.size != msg->reply_size) {
			printf("error: reply expected 0x%x got 0x%x bytes\n",
			       msg->reply_size, reply.hdr.size);
			size = msg->reply_size;
			ret = -EINVAL;
		} else {
			size = reply.hdr.size;
		}
	}

	/* read the message */
	if (msg->msg_data && size > 0)
		mailbox_read(fuzzer, data->host_box.offset, msg->reply_data,
			     size);

	return ret;

}

/* called when we receive a message from qemu */
static int bridge_cb(void *data, struct qemu_io_msg *msg)
{
	struct fuzz *fuzzer = (struct fuzz *)data;

	fprintf(stdout, "msg: id %d msg %d size %d type %d\n",
		msg->id, msg->msg, msg->size, msg->type);

	switch (msg->type) {
	case QEMU_IO_TYPE_IRQ:
		/* IRQ from DSP */
		if (apl_irq_handler(0, fuzzer) != IRQ_NONE)
			apl_irq_thread(0, fuzzer);
		break;
	default:
		break;
	}

	return 0;
}

static int apl_platform_init(struct fuzz *fuzzer,
			     struct fuzz_platform *platform)
{
	struct timespec timeout;
	struct apl_data *data;
	struct timeval tp;
	int i, bar;
	int ret = 0;

	/* init private data */
	data = calloc(sizeof(*data), 1);
	if (!data)
		return -ENOMEM;
	fuzzer->platform_data = data;
	fuzzer->platform = platform;

	/* create SHM for memories and register regions */
	for (i = 0, bar = 0; i < platform->num_mem_regions; i++, bar++) {
		data->bar[bar] = fuzzer_create_memory_region(fuzzer, bar, i);
		if (!data->bar[bar]) {
			fprintf(stderr, "error: failed to create mem region %s\n",
				platform->mem_region[i].name);
			return -ENOMEM;
		}
	}

	for (i = 0; i < platform->num_reg_regions; i++, bar++) {
		data->bar[bar] = fuzzer_create_io_region(fuzzer, bar, i);
		if (!data->bar[bar]) {
			fprintf(stderr, "error: failed to create mem region %s\n",
				platform->reg_region[i].name);
			return -ENOMEM;
		}
	}

	/*
	 * Hardcode offsets for now.
	 * TODO: calculate from memory map
	 */
	data->host_box.offset = 0xc000;
	data->host_box.size = 0x2000;
	data->dsp_box.offset = 0xf000;
	data->dsp_box.size = 0x1000;

	/* initialise bridge to qemu */
	qemu_io_register_parent(platform->name, &bridge_cb, (void *)fuzzer);

	/* set boot wait timeout */
	gettimeofday(&tp, NULL);
	timeout.tv_sec  = tp.tv_sec;
	timeout.tv_nsec = tp.tv_usec * 1000;
	timeout.tv_sec += 5;

	/* first lock the boot wait mutex */
	pthread_mutex_lock(&data->mutex);

	/* now wait for mutex to be unlocked by boot ready message */
	while (!ret && !data->boot_complete)
		ret = pthread_cond_timedwait(&apl_cond, &data->mutex, &timeout);

	if (ret == ETIMEDOUT && !data->boot_complete)
		fprintf(stderr, "error: DSP boot timeout\n");

	pthread_mutex_unlock(&data->mutex);

	return ret;
}

static void apl_platform_free(struct fuzz *fuzzer)
{
	struct apl_data *data = fuzzer->platform_data;

	fuzzer_free_regions(fuzzer);
	free(data);
}

static void apl_fw_ready(struct fuzz *fuzzer)
{
	struct apl_data *data = fuzzer->platform_data;
	struct sof_ipc_fw_ready fw_ready;
	struct sof_ipc_fw_version version;

	/* read fw_ready data from mailbox */
	mailbox_read(fuzzer, data->dsp_box.offset, &fw_ready,
		     sizeof(fw_ready));

	printf("host box 0x%x size 0x%x\n", data->host_box.offset,
	       data->host_box.size);
	printf("dsp box 0x%x size 0x%x\n", data->dsp_box.offset,
	       data->dsp_box.size);

	version = fw_ready.version;
	printf("FW version major: %d minor: %d tag: %s\n",
	       version.major, version.minor, version.tag);
}

static unsigned int apl_dsp_box_offset(struct fuzz *fuzzer)
{
	struct apl_data *data = fuzzer->platform_data;
	return 	data->dsp_box.offset;
}

struct fuzz_platform apl_platform = {
	.name = "bxt",
	.send_msg = apl_send_msg,
	.get_reply = apl_get_reply,
	.init = apl_platform_init,
	.free = apl_platform_free,
	.mailbox_read = mailbox_read,
	.mailbox_write = mailbox_write,
	.fw_ready = apl_fw_ready,
	.get_dsp_box_offset = apl_dsp_box_offset,
	.num_mem_regions = ARRAY_SIZE(apl_mem),
	.mem_region = apl_mem,
	.num_reg_regions = ARRAY_SIZE(apl_io),
	.reg_region = apl_io,
};

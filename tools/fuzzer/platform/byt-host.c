/* Core IA host SHIM support for Baytrail audio DSP.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */



#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include "shim.h"
#include <uapi/ipc/trace.h>
#include "../fuzzer.h"
#include "../qemu-bridge.h"

#define BYT_DSP_BAR	0
#define MBOX_OFFSET		0x144000

/* Baytrail, Cherrytrail and Braswell - taken from qemu */
#define ADSP_PCI_SIZE				0x00001000
#define ADSP_BYT_PCI_BASE           0xF1200000
#define ADSP_BYT_MMIO_BASE          0xF1400000
#define ADSP_BYT_HOST_IRAM_OFFSET   0x000c0000
#define ADSP_BYT_HOST_DRAM_OFFSET   0x00100000
#define ADSP_BYT_HOST_IRAM_BASE     (ADSP_BYT_MMIO_BASE + ADSP_BYT_HOST_IRAM_OFFSET)
#define ADSP_BYT_HOST_DRAM_BASE     (ADSP_BYT_MMIO_BASE + ADSP_BYT_HOST_DRAM_OFFSET)
#define ADSP_BYT_HOST_SHIM_BASE     (ADSP_BYT_MMIO_BASE + 0x00140000)
#define ADSP_BYT_HOST_MAILBOX_BASE  (ADSP_BYT_MMIO_BASE + 0x00144000)

#define ADSP_CHT_PCI_BASE           0xF1600000
#define ADSP_CHT_MMIO_BASE          0xF1800000
#define ADSP_CHT_HOST_IRAM_BASE     (ADSP_CHT_MMIO_BASE + ADSP_BYT_HOST_IRAM_OFFSET)
#define ADSP_CHT_HOST_DRAM_BASE     (ADSP_CHT_MMIO_BASE + ADSP_BYT_HOST_DRAM_OFFSET)
#define ADSP_CHT_HOST_SHIM_BASE     (ADSP_CHT_MMIO_BASE + 0x00140000)
#define ADSP_CHT_HOST_MAILBOX_BASE  (ADSP_CHT_MMIO_BASE + 0x00144000)

#define ADSP_BYT_IRAM_SIZE          0x14000
#define ADSP_BYT_DRAM_SIZE          0x28000
#define ADSP_BYT_SHIM_SIZE          0x1000
#define ADSP_MAILBOX_SIZE			0x1000

// TODO get from driver.
#define BYT_PANIC_OFFSET(x)	(x)

struct byt_data {
	void *bar[MAX_BAR_COUNT];
	struct mailbox host_box;
	struct mailbox dsp_box;
	int boot_complete;
	pthread_mutex_t mutex;
};

/* Platform host description taken from Qemu */
static struct fuzzer_mem_desc byt_mem[] = {
    {.name = "iram", .base = ADSP_BYT_HOST_IRAM_BASE,
        .size = ADSP_BYT_IRAM_SIZE},
    {.name = "dram", .base = ADSP_BYT_HOST_DRAM_BASE,
        .size = ADSP_BYT_DRAM_SIZE},
};

static struct fuzzer_reg_space byt_io[] = {
    { .name = "pci",
        .desc = {.base = ADSP_BYT_PCI_BASE, .size = ADSP_PCI_SIZE},},
    { .name = "shim",
        .desc = {.base = ADSP_BYT_HOST_SHIM_BASE, .size = ADSP_BYT_SHIM_SIZE},},
    { .name = "mbox",
        .desc = {.base = ADSP_BYT_HOST_MAILBOX_BASE, .size = ADSP_MAILBOX_SIZE},},
};

/*
 * Platform support for BYT/CHT.
 *
 * The IPC portions below are copy and pasted from the SOF driver with some
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

static uint64_t dsp_read64(struct fuzz *fuzzer,
						   unsigned bar, unsigned reg)
{
	struct byt_data *data = fuzzer->platform_data;

	return *((uint64_t*)(data->bar[bar] + reg));
}

static void dsp_write64(struct fuzz *fuzzer,
						unsigned bar, unsigned reg, uint64_t value)
{
	struct byt_data *data = fuzzer->platform_data;
	struct qemu_io_msg_reg32 reg32;
	struct qemu_io_msg_irq irq;
	uint32_t active, isrd;

	/* write value to SHM */
	*((uint64_t*)(data->bar[bar] + reg)) = value;

	/* most IO is handled by SHM, but there are some exceptions */
	switch (reg) {
	case SHIM_IPCX:

		/* now set/clear status bit */
		isrd = dsp_read64(fuzzer, bar, SHIM_ISRD) & ~(SHIM_ISRD_DONE | SHIM_ISRD_BUSY);
		isrd |= value & SHIM_IPCX_BUSY ? SHIM_ISRD_BUSY : 0;
		isrd |= value & SHIM_IPCX_DONE ? SHIM_ISRD_DONE : 0;
		dsp_write64(fuzzer, bar, SHIM_ISRD, isrd);

		/* do we need to send an IRQ ? */
		if (value & SHIM_IPCX_BUSY) {

			printf("irq: send busy interrupt 0x%8.8lx\n", value);

			/* send IRQ to child */
			irq.hdr.type = QEMU_IO_TYPE_IRQ;
			irq.hdr.msg = QEMU_IO_MSG_IRQ;
			irq.hdr.size = sizeof(irq);
			irq.irq = 0;

			qemu_io_send_msg(&irq.hdr);
		}
		break;
	case SHIM_IPCD:

		/* set/clear status bit */
		isrd = dsp_read64(fuzzer, bar, SHIM_ISRD) &
			~(SHIM_ISRD_DONE | SHIM_ISRD_BUSY);
		isrd |= value & SHIM_IPCD_BUSY ? SHIM_ISRD_BUSY : 0;
		isrd |= value & SHIM_IPCD_DONE ? SHIM_ISRD_DONE : 0;
		dsp_write64(fuzzer, bar, SHIM_ISRD, isrd);

		/* do we need to send an IRQ ? */
		if (value & SHIM_IPCD_DONE) {

			printf("irq: send done interrupt 0x%8.8lx\n", value);

			/* send IRQ to child */
			irq.hdr.type = QEMU_IO_TYPE_IRQ;
			irq.hdr.msg = QEMU_IO_MSG_IRQ;
			irq.hdr.size = sizeof(irq);
			irq.irq = 0;

			qemu_io_send_msg(&irq.hdr);
		}
		break;
	case SHIM_IMRX:

		active = dsp_read64(fuzzer, bar, SHIM_ISRX) &
			~(dsp_read64(fuzzer, bar, SHIM_IMRX));

		printf(
			"irq: masking %lx mask %lx active %x\n",
			dsp_read64(fuzzer, bar, SHIM_ISRD),
			dsp_read64(fuzzer, bar, SHIM_IMRD), active);
		break;
	default:
		break;
	}
}

static uint64_t dsp_update_bits64_unlocked(struct fuzz *fuzzer,
									unsigned bar, uint32_t offset,
									uint64_t mask, uint64_t value)
{
	struct byt_data *data = fuzzer->platform_data;
	uint64_t old, new;
	uint64_t ret;

	ret = dsp_read64(fuzzer, bar, offset);
	old = ret;

	new = (old & ~mask) | (value & mask);

	if (old == new)
		return 0;

	dsp_write64(fuzzer, bar, offset, new);
	return 1;
}

static void mailbox_read(struct fuzz *fuzzer, unsigned offset,
		void *mbox_data, unsigned size)
{
	struct byt_data *data = fuzzer->platform_data;

	memcpy(mbox_data, (void*)(data->bar[0] + offset), size);
}

static void mailbox_write(struct fuzz *fuzzer, unsigned offset,
		void *mbox_data, unsigned size)
{
	struct byt_data *data = fuzzer->platform_data;

	memcpy((void*)(data->bar[0] + offset), mbox_data, size);
}

static int byt_cmd_done(struct fuzz *fuzzer, int dir)
{
	if (dir == SOF_IPC_HOST_REPLY) {
		/* clear BUSY bit and set DONE bit - accept new messages */
		dsp_update_bits64_unlocked(fuzzer, BYT_DSP_BAR, SHIM_IPCD,
						   SHIM_BYT_IPCD_BUSY |
						   SHIM_BYT_IPCD_DONE,
						   SHIM_BYT_IPCD_DONE);

		/* unmask busy interrupt */
		dsp_update_bits64_unlocked(fuzzer, BYT_DSP_BAR, SHIM_IMRX,
						   SHIM_IMRX_BUSY, 0);
	} else {
		/* clear DONE bit - tell DSP we have completed */
		dsp_update_bits64_unlocked(fuzzer, BYT_DSP_BAR, SHIM_IPCX,
						   SHIM_BYT_IPCX_DONE, 0);

		/* unmask Done interrupt */
		dsp_update_bits64_unlocked(fuzzer, BYT_DSP_BAR, SHIM_IMRX,
						   SHIM_IMRX_DONE, 0);
	}

	return 0;
}

/*
 * IPC Doorbell IRQ handler and thread.
 */

static int byt_irq_handler(int irq, void *context)
{
	struct fuzz *fuzzer = (struct fuzz *)context;
	uint64_t isr;
	int ret = IRQ_NONE;

	/* Interrupt arrived, check src */
	isr = dsp_read64(fuzzer, BYT_DSP_BAR, SHIM_ISRX);
	if (isr & (SHIM_ISRX_DONE | SHIM_ISRX_BUSY))
		ret = IRQ_WAKE_THREAD;

	return ret;
}

static int byt_irq_thread(int irq, void *context)
{
	struct fuzz *fuzzer = (struct fuzz *)context;
	struct byt_data *data = fuzzer->platform_data;
	uint64_t ipcx, ipcd;
	uint64_t imrx;

	imrx = dsp_read64(fuzzer, BYT_DSP_BAR, SHIM_IMRX);
	ipcx = dsp_read64(fuzzer, BYT_DSP_BAR, SHIM_IPCX);

	/* reply message from DSP */
	if ((ipcx & SHIM_BYT_IPCX_DONE) &&
	    !(imrx & SHIM_IMRX_DONE)) {
		/* Mask Done interrupt before first */
		dsp_update_bits64_unlocked(fuzzer, BYT_DSP_BAR,
						   SHIM_IMRX,
						   SHIM_IMRX_DONE,
						   SHIM_IMRX_DONE);
		/*
		 * handle immediate reply from DSP core. If the msg is
		 * found, set done bit in cmd_done which is called at the
		 * end of message processing function, else set it here
		 * because the done bit can't be set in cmd_done function
		 * which is triggered by msg
		 */
		fuzzer_ipc_msg_reply(fuzzer);
		byt_cmd_done(fuzzer, SOF_IPC_DSP_REPLY);
	}

	/* new message from DSP */
	ipcd = dsp_read64(fuzzer, BYT_DSP_BAR, SHIM_IPCD);
	if ((ipcd & SHIM_BYT_IPCD_BUSY) &&
	    !(imrx & SHIM_IMRX_BUSY)) {
		/* Mask Busy interrupt before return */
		dsp_update_bits64_unlocked(fuzzer, BYT_DSP_BAR,
						   SHIM_IMRX,
						   SHIM_IMRX_BUSY,
						   SHIM_IMRX_BUSY);

		/* boot not complete ?? - TODO check message dont just assume */
		if (!data->boot_complete) {
			/* use a mutex here to wake init code */
			data->boot_complete = 1;
			pthread_mutex_unlock(&data->mutex);
			return IRQ_HANDLED;
		}

		/* Handle messages from DSP Core */
		if ((ipcd & SOF_IPC_PANIC_MAGIC_MASK) == SOF_IPC_PANIC_MAGIC) {
			fuzzer_ipc_crash(fuzzer, BYT_PANIC_OFFSET(ipcd) +
					  MBOX_OFFSET);
		} else {
			fuzzer_ipc_msg_rx(fuzzer);
		}
	}

	return IRQ_HANDLED;
}

static int byt_send_msg(struct fuzz *fuzzer, struct ipc_msg *msg)
{
	struct fuzz_platform *plat = fuzzer->platform;
	struct byt_data *data = fuzzer->platform_data;
	uint64_t cmd = msg->header;

	/* send the message */
	mailbox_write(fuzzer, data->host_box.offset, msg->msg_data,
			  msg->msg_size);
	dsp_write64(fuzzer, BYT_DSP_BAR, SHIM_IPCX,
			    cmd | SHIM_BYT_IPCX_BUSY);

	return 0;
}

static int byt_get_reply(struct fuzz *fuzzer, struct ipc_msg *msg)
{
	struct fuzz_platform *plat = fuzzer->platform;
	struct byt_data *data = fuzzer->platform_data;
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
    case QEMU_IO_TYPE_REG:
        /* mostly handled by SHM, some exceptions */
     //   adsp_byt_shim_msg(adsp, msg);
        break;
    case QEMU_IO_TYPE_IRQ:
    	/* IRQ from DSP */
    	if (byt_irq_handler(0, fuzzer) != IRQ_NONE)
    		byt_irq_thread(0, fuzzer);
        break;
    case QEMU_IO_TYPE_PM:
   //     adsp_pm_msg(adsp, msg);
        break;
    case QEMU_IO_TYPE_DMA:
     //   dw_dma_msg(msg);
        break;
    case QEMU_IO_TYPE_MEM:
    default:
        break;
    }

    return 0;
}

static int byt_platform_init(struct fuzz *fuzzer,
							 struct fuzz_platform *platform)
{
	struct byt_data *data;
	struct timespec timeout;
	pthread_cond_t cond;
	int i;
	int ret;

	/* init private data */
	data = calloc(sizeof(*data), 1);
	if (!data)
		return -ENOMEM;
	fuzzer->platform_data = data;
	fuzzer->platform = platform;

	/* create SHM for memories and register regions */
	/* TODO: SHM index should match with qemu index numbers for same regions ?? */
	for (i = 0; i < platform->num_mem_regions; i++) {
		data->bar[i] = fuzzer_create_memory_region(fuzzer, i);
		if (!data->bar[i]) {
			fprintf(stderr, "error: failed to create mem region %s\n",
					platform->mem_region[i].name);
			return -ENOMEM;
		}
	}

	for (; i < platform->num_reg_regions; i++) {
		data->bar[i] = fuzzer_create_io_region(fuzzer, i);
		if (!data->bar[i]) {
			fprintf(stderr, "error: failed to create mem region %s\n",
					platform->reg_region[i].name);
			return -ENOMEM;
		}
	}

	/* initialise bridge to qemu */
	qemu_io_register_parent(platform->name, &bridge_cb, (void*)fuzzer);

	// TODO; at this point start qemu
	//exec("name of qemu shell script with args");

	timeout.tv_nsec = 0;
	timeout.tv_sec = 1;
	//data->mutex = PTHREAD_MUTEX_INITIALIZER; TODO: needed ???? man page says yes ??

	/* first lock the boot wait mutex */
	pthread_mutex_lock(&data->mutex);

	/* now wait for mutex to be unlocked by boot ready message */
	ret = pthread_cond_timedwait(&cond, &data->mutex, &timeout);
	if (ret < 0) {
		fprintf(stderr, "error: DSP boot timeout\n");
	}

	return ret;
}

static void byt_platform_free(struct fuzz *fuzzer)
{
	struct byt_data *data = fuzzer->platform_data;

	fuzzer_free_regions(fuzzer);
	free(data);
}

struct fuzz_platform byt_platform = {
	.name = "byt",
	.send_msg = byt_send_msg,
	.get_reply = byt_get_reply,
	.init = byt_platform_init,
	.free = byt_platform_free,
	.num_mem_regions = ARRAY_SIZE(byt_mem),
	.mem_region = byt_mem,
	.num_reg_regions = ARRAY_SIZE(byt_io),
	.reg_region = byt_io,
};

struct fuzz_platform cht_platform = {
	.name = "cht",
	.send_msg = byt_send_msg,
	.get_reply = byt_get_reply,
	.init = byt_platform_init,
	.free = byt_platform_free,
	.num_mem_regions = ARRAY_SIZE(byt_mem),
	.mem_region = byt_mem,
	.num_reg_regions = ARRAY_SIZE(byt_io),
	.reg_region = byt_io,
};


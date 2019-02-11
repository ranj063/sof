/*
 * Copyright (c) 2016, Intel Corporation
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
 * Author: Marcin Rajwa <marcin.rajwa@linux.intel.com>
 *
 */

#include <stdint.h>
#include <uapi/ipc/topology.h>
#include <sof/ipc.h>
#include <sof/audio/component.h>
#include <sof/audio/kpb.h>
#include <sof/list.h>
#include <sof/audio/buffer.h>

static int kpb_register_client(struct comp_dev *dev, struct kpb_client *cli);
static int kpb_begin_drainning(struct comp_dev *dev, uint8_t client_id);
static void kpb_buffer_data(struct comp_data *kpb, struct comp_buffer *source);

/**
 * kpb_new() - create a key phrase buffer component.
 * @arg1: generic ipc component pointer.
 *
 * Return: A pointer to newly created KPB component.
 */
static struct comp_dev *kpb_new(struct sof_ipc_comp *comp)
{
	struct comp_dev *dev;
	struct sof_ipc_comp_kpb *kpb;
	struct sof_ipc_comp_kpb *ipc_kpb = (struct sof_ipc_comp_kpb *)comp;
	struct comp_data *cd;

	trace_kpb("kpb_new()");

	if (IPC_IS_SIZE_INVALID(ipc_kpb->config)) {
		IPC_SIZE_ERROR_TRACE(TRACE_CLASS_KPB, ipc_kpb->config);
		return NULL;
	}

	/* Validate input parameters */
	if (ipc_kpb->channels > MAX_SUPPORETED_CHANNELS) {
		trace_kpb_error("kpb_new() error: "
		"nr of channels exceeded the limit");
		return NULL;
	}

	if (ipc_kpb->history_depth > MAX_BUFFER_SIZE) {
		trace_kpb_error("kpb_new() error: "
		"history depth exceeded the limit");
		return NULL;
	}

	if (ipc_kpb->sampling_freq != MAX_SAMPLNG_FREQUENCY) {
		trace_kpb_error("kpb_new() error: "
		"requested sampling frequency not supported");
		return NULL;
	}

	if (ipc_kpb->sampling_width != SAMPLING_WIDTH) {
		trace_kpb_error("kpb_new() error: "
		"requested sampling width not supported");
		return NULL;
	}

	dev = rzalloc(RZONE_RUNTIME, SOF_MEM_CAPS_RAM,
		      COMP_SIZE(struct sof_ipc_comp_kpb));
	if (!dev)
		return NULL;

	kpb = (struct sof_ipc_comp_kpb *)&dev->comp;
	memcpy(kpb, ipc_kpb, sizeof(struct sof_ipc_comp_kpb));

	cd = rzalloc(RZONE_RUNTIME, SOF_MEM_CAPS_RAM, sizeof(*cd));
	if (!cd) {
		rfree(dev);
		return NULL;
	}

	cd->history_depth = ipc_kpb->history_depth;
	comp_set_drvdata(dev, cd);

	dev->state = COMP_STATE_READY;
	return dev;
}

/**
 * kpb_free() - reclaim memory for a key phrase buffer.
 * @arg1: component device pointer
 */
static void kpb_free(struct comp_dev *dev)
{
	struct comp_data *kd = comp_get_drvdata(dev);

	trace_kpb("kpb_free()");

	rfree(kd);
	rfree(dev);
}

static int kpb_trigger(struct comp_dev *dev, int cmd)
{
	trace_kpb("kpb_trigger()");

	return comp_set_state(dev, cmd);
}

/**
 * kpb_prepare() - prepare key phrase buffer.
 * @arg1:  kpb component.
 *
 * Return: integer representing either 0 - success
 * or -EINVAL - failure.
 */
static int kpb_prepare(struct comp_dev *dev)
{
	struct comp_data *cd = comp_get_drvdata(dev);
	int ret = 0;
	int i;

	trace_kpb("kpb_prepare()");

	ret = comp_set_state(dev, COMP_TRIGGER_PREPARE);
	if (ret < 0)
		return ret;

	cd->no_of_clients = 0;

	/* allocate history_buffer/s */
#if KPB_NO_OF_HISTORY_BUFFERS == 2

	cd->his_buf_hp.sta_addr = rballoc(RZONE_RUNTIME, SOF_MEM_CAPS_RAM,
					  MAX_BUFFER_SIZE - LPSRAM_SIZE);
	cd->his_buf_lp.sta_addr = rballoc(RZONE_RUNTIME, SOF_MEM_CAPS_LP,
					  LPSRAM_SIZE);

	if (cd->his_buf_hp.sta_addr || cd->his_buf_lp.sta_addr) {
		trace_kpb_error("Failed to allocate space for "
				"KPB bufefrs");
		return -EINVAL;
	}

	cd->his_buf_hp.end_addr = cd->his_buf_hp.sta_addr +
	(MAX_BUFFER_SIZE - LPSRAM_SIZE);

	cd->his_buf_lp.end_addr = cd->his_buf_lp.sta_addr +
	LPSRAM_SIZE;

#elif KPB_NO_OF_HISTORY_BUFFERS == 1

	cd->his_buf_hp.sta_addr = rballoc(RZONE_RUNTIME, SOF_MEM_CAPS_RAM,
					  MAX_BUFFER_SIZE);

	if (cd->his_buf_hp.sta_addr) {
		trace_kpb_error("Failed to allocate space for "
				"KPB bufefrs");
	return -EINVAL;
	}

	cd->his_buf_hp.end_addr = cd->his_buf_hp.sta_addr + MAX_BUFFER_SIZE;

#else
#error "Wrong number of key phrase buffers configured"
#endif

	/* TODO: zeroes both buffers */

	/* Initialize clients data */
	for (i = 0; i < MAX_NO_OF_CLIENTS; i++)
		cd->clients[i].state = KPB_CLIENT_UNREGISTERED;

	return ret;
}

/**
 * kpb_copy() - copy real time input stream into sink buffer,
 * and in the same time buffers that input for
 * later use by some of clients.
 *
 * @arg1:  kpb component.
 *
 * Return: integer representing either 0 - success
 * or -EINVAL - failure.
 */
static int kpb_copy(struct comp_dev *dev)
{
	int ret;
	struct comp_data *kpb = comp_get_drvdata(dev);
	struct comp_buffer *source;
	struct comp_buffer *sink;

	trace_kpb("kpb_copy()");

	/* Get source and sink buffers */
	source = list_first_item(&dev->bsource_list, struct comp_buffer,
				 source_list);
	sink = list_first_item(&dev->bsink_list, struct comp_buffer,
			       sink_list);
	/* Process source data */
	/* Check if source have data and valid pointer to read from */
	if (source->avail > 0 && source && sink && source->r_ptr) {
		/* Real time copying */
		if (sink->free >= source->avail && sink->w_ptr) {
			/* Sink and source are both ready and have space */
			memcpy(sink->w_ptr, source->r_ptr,
			       source->avail);

			/* update source & snik data*/
			comp_update_buffer_produce(sink, source->avail);
			comp_update_buffer_consume(source, source->avail);
		} else {
			;/* What should we do if sink isn't ready(state/size)?
			  * Simple skip is OK?
			  */
		}
		/* Buffer source data internally for future use by clients */
		if (source->avail <= MAX_BUFFER_SIZE)
			kpb_buffer_data(kpb, source);
	} else
		ret = -EINVAL;
	return ret;
}

/**
 * kpb_buffer_data() - buffer real time data stream in
 * the internal buffer.
 *
 * @arg1:  kpb component.
 * @arg2:  pointer to the source.
 *
 * Return: integer representing either 0 - success
 * or -EINVAL - failure.
 */
static void kpb_buffer_data(struct comp_data *kpb, struct comp_buffer *source)
{
trace_kpb("kpb_buffer_data()");

#if KPB_NO_OF_HISTORY_BUFFERS == 2
	int size_to_copy = source->avail;

	while (size_to_copy) {
		struct history_buffer *hb =
		(kpb->his_buf_lp.state == KPB_BUFFER_FREE) ?
		&kpb->his_buf_lp : &kpb->his_buf_hp;
		int space_avail = (int)hb->end_addr - (int)hb->w_ptr;

		if (size_to_copy > space_avail) {
			memcpy(hb->w_ptr, source->r_ptr, space_avail);
			size_to_copy = size_to_copy - space_avail;
			hb->w_ptr = hb->sta_addr;
			hb->state = KPB_BUFFER_FULL;

			if (hb->id == KPB_LP)
				kpb->his_buf_hp.state = KPB_BUFFER_FREE;
			else
				kpb->his_buf_lp.state = KPB_BUFFER_FREE;
		} else  {
			memcpy(hb->w_ptr, source->r_ptr, size_to_copy);
			hb->w_ptr += size_to_copy;
			size_to_copy = 0;
		}
	}
#elif KPB_NO_OF_HISTORY_BUFFERS == 1
	struct history_buffer *hb = &kpb->his_buf_hp;

	int space_avail = hb->end_addr - hb->w_ptr;

	if (size_to_copy > space_avail) {
		/* We need to split copying into two parts
		 * and wrap buffer pointer
		 */
		memcpy(hb->w_ptr, source->r_ptr, space_avail);
		size_to_copy = size_to_copy - space_avail;
		hb->w_ptr = hb->sta_addr;
		memcpy(hb->w_ptr, source->r_ptr, size_to_copy);
		hb->w_ptr += size_to_copy;
		size_to_copy = 0;

	} else {
		memcpy(kpb->w_ptr, source->data_ptr, size_to_copy);
		kpb->w_ptr += size_to_copy;
		size_to_copy = 0;
	}
#else
#error "Wrong number of key phrase buffers configured"
#endif

}

/**
 * kpb_cmd() - kpb event handler.
 * @arg1:  kpb component.
 * @arg2:  command to be executed
 * @arg3:  pointer to data related with request
 * @arg4:  maxiumum size of data
 *
 *
 * Return: integer representing either 0 - success
 * or -EINVAL - failure.
 */
static int kpb_cmd(struct comp_dev *dev, int cmd, void *data,
		   int max_data_size)
{
	int ret = 0;
	struct sof_ipc_ctrl_data *cdata = data;
	struct kpb_client *cli = (struct kpb_client *)cdata->data->data;
	uint8_t client_id = cli->id;

	trace_kpb("kpb_cmd()");

	switch (cmd) {
	case KPB_EVENT_REGISTER_CLIENT:
		ret = kpb_register_client(dev, cli);
		break;
	case KPB_EVENT_UNREGISTER_CLIENT:
		/*TODO*/
		ret = -EINVAL;
		break;
	case KPB_EVENT_BEGIN_DRAINNING:
		ret = kpb_begin_drainning(dev, client_id);
		break;
	case KPB_EVENT_STOP_DRAINNING:
		/*TODO*/
		ret = -EINVAL;
		break;
	default:
		trace_kpb_error("kpb_cmd() error: "
				"unsupported command");
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int kpb_begin_drainning(struct comp_dev *dev, uint8_t client_id)
{
	return 0;
}

static int kpb_register_client(struct comp_dev *dev, struct kpb_client *cli)
{
	return 0;
}

static void kpb_cache(struct comp_dev *dev, int cmd)
{
	/* TODO: writeback history buffer */
}

static int kpb_reset(struct comp_dev *dev)
{
	/* TODO: what data of KPB should we reset here? */
	return -EINVAL;
}

struct comp_driver comp_kpb = {
	.type = SOF_COMP_KPB,
	.ops = {
		.new = kpb_new,
		.free = kpb_free,
		.cmd = kpb_cmd,
		.trigger = kpb_trigger,
		.copy = kpb_copy,
		.prepare = kpb_prepare,
		.reset = kpb_reset,
		.cache = kpb_cache,
	},
};

void sys_comp_kpb_init(void)
{
	comp_register(&comp_kpb);
}

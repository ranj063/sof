// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2018 Intel Corporation. All rights reserved.
//
// Author: Ranjani Sridharan <ranjani.sridharan@linux.intel.com>
//         Liam Girdwood <liam.r.girdwood@linux.intel.com>

/*
 * Topology parser to parse topology bin file
 * and set up components and pipeline
 */

#include <stdio.h>
#ifdef BUILD_TESTBENCH
#include <sof/ipc.h>
#include <sof/string.h>
#include <dlfcn.h>
#include <sof/audio/component.h>
#include "testbench/file.h"
#endif
#ifdef BUILD_FUZZER
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "../fuzzer/fuzzer.h"
#include <ipc/topology.h>
#include <ipc/stream.h>
#include <ipc/dai.h>
#endif
#include "testbench/topology.h"

#ifdef BUILD_FUZZER
const struct sof_dai_types sof_dais[] = {
	{"SSP", SOF_DAI_INTEL_SSP},
	{"HDA", SOF_DAI_INTEL_HDA},
	{"DMIC", SOF_DAI_INTEL_DMIC},
};
#endif

FILE *file;
#ifdef BUILD_TESTBENCH
char pipeline_string[DEBUG_MSG_LEN];
struct shared_lib_table *lib_table;

/*
 * Register component driver
 * Only needed once per component type
 */
static void register_comp(int comp_type)
{
	int index;
	char message[DEBUG_MSG_LEN + MAX_LIB_NAME_LEN];

	/* register file comp driver (no shared library needed) */
	if (comp_type == SND_SOC_TPLG_DAPM_DAI_IN ||
	    comp_type == SND_SOC_TPLG_DAPM_AIF_IN) {
		if (!lib_table[0].register_drv) {
			sys_comp_file_init();
			lib_table[0].register_drv = 1;
			debug_print("registered file comp driver\n");
		}
		return;
	}

	/* get index of comp in shared library table */
	index = get_index_by_type(comp_type, lib_table);
	if (index < 0)
		return;

	/* register comp driver if not already registered */
	if (!lib_table[index].register_drv) {
		sprintf(message, "registered comp driver for %s\n",
			lib_table[index].comp_name);
		debug_print(message);

		/* open shared library object */
		sprintf(message, "opening shared lib %s\n",
			lib_table[index].library_name);
		debug_print(message);

		lib_table[index].handle = dlopen(lib_table[index].library_name,
						 RTLD_LAZY);
		if (!lib_table[index].handle) {
			fprintf(stderr, "error: %s\n", dlerror());
			exit(EXIT_FAILURE);
		}

		/* comp init is executed on lib load */
		lib_table[index].register_drv = 1;
	}

}
#endif

#ifdef BUILD_FUZZER
static int find_widget(struct comp_info *temp_comp_list, int count, char *name)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!strcmp(temp_comp_list[i].name, name))
			return temp_comp_list[i].id;
	}

	return -EINVAL;
}
#endif

/* read vendor tuples array from topology */
static int read_array(struct snd_soc_tplg_vendor_array *array)
{
	struct snd_soc_tplg_vendor_uuid_elem uuid;
	struct snd_soc_tplg_vendor_string_elem string;
	struct snd_soc_tplg_vendor_value_elem value;
	int j, ret = 0;
	size_t size;

	switch (array->type) {
	case SND_SOC_TPLG_TUPLE_TYPE_UUID:

		/* copy uuid elems into array */
		for (j = 0; j < array->num_elems; j++) {
			size = sizeof(struct snd_soc_tplg_vendor_uuid_elem);
			ret = fread(&uuid, size, 1, file);
			if (ret != 1)
				return -EINVAL;
			memcpy(&array->uuid[j], &uuid, size);
		}
		break;
	case SND_SOC_TPLG_TUPLE_TYPE_STRING:

		/* copy string elems into array */
		for (j = 0; j < array->num_elems; j++) {
			size = sizeof(struct snd_soc_tplg_vendor_string_elem);
			ret = fread(&string, size, 1, file);
			if (ret != 1)
				return -EINVAL;
			memcpy(&array->string[j], &string, size);
		}
		break;
	case SND_SOC_TPLG_TUPLE_TYPE_BOOL:
	case SND_SOC_TPLG_TUPLE_TYPE_BYTE:
	case SND_SOC_TPLG_TUPLE_TYPE_WORD:
	case SND_SOC_TPLG_TUPLE_TYPE_SHORT:
		/* copy value elems into array */
		for (j = 0; j < array->num_elems; j++) {
			size = sizeof(struct snd_soc_tplg_vendor_value_elem);
			ret = fread(&value, size, 1, file);
			if (ret != 1)
				return -EINVAL;
			memcpy(&array->value[j], &value, size);
		}
		break;
	default:
		fprintf(stderr, "error: unknown token type %d\n", array->type);
		return -EINVAL;
	}
	return 0;
}

#ifdef BUILD_FUZZER
int complete_pipeline(struct fuzz *fuzzer, uint32_t comp_id)
{
	struct sof_ipc_pipe_ready ready;
	struct sof_ipc_reply r;
	int ret;

	printf("tplg: complete pipeline id %d\n", comp_id);

	ready.hdr.size = sizeof(ready);
	ready.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_PIPE_COMPLETE;
	ready.comp_id = comp_id;

	/* configure fuzzer msg */
	fuzzer->msg.header = ready.hdr.cmd;
	memcpy(fuzzer->msg.msg_data, &ready, ready.hdr.size);
	fuzzer->msg.msg_size = sizeof(ready);
	fuzzer->msg.reply_size = sizeof(r);

	ret = fuzzer_send_msg(fuzzer);
	if (ret < 0)
		return ret;

	return 1;
}
#endif

/* load pipeline graph DAPM widget*/
#ifdef BUILD_TESTBENCH
static int load_graph(struct sof *sof, struct comp_info *temp_comp_list,
		      int count, int num_comps, int pipeline_id)
#endif
#ifdef BUILD_FUZZER
static int load_graph(struct fuzz *fuzzer, struct comp_info *temp_comp_list,
		      int count, int num_comps, int pipeline_id)
#endif
{
	struct sof_ipc_pipe_comp_connect connection;
	struct snd_soc_tplg_dapm_graph_elem *graph_elem;
#ifdef BUILD_FUZZER
	struct sof_ipc_pipe_comp_connect connect;
	struct sof_ipc_reply r;
	char *source, *sink;
#endif
	int i, j, ret = 0;
	size_t size;

#ifdef BUILD_FUZZER
	/* configure route */
	connection.hdr.size = sizeof(connection);
	connection.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_COMP_CONNECT;
#endif
	/* allocate memory for graph elem */
	size = sizeof(struct snd_soc_tplg_dapm_graph_elem);
	graph_elem = (struct snd_soc_tplg_dapm_graph_elem *)malloc(size);
	if (!graph_elem) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	/* set up component connections */
	connection.source_id = -1;
	connection.sink_id = -1;
	for (i = 0; i < count; i++) {
		size = sizeof(struct snd_soc_tplg_dapm_graph_elem);
		ret = fread(graph_elem, size, 1, file);
		if (ret != 1)
			return -EINVAL;

		/* look up component id from the component list */
		for (j = 0; j < num_comps; j++) {
			if (strcmp(temp_comp_list[j].name,
				   graph_elem->source) == 0) {
				connection.source_id = temp_comp_list[j].id;
#ifdef BUILD_FUZZER
				source = graph_elem->source;
#endif
			}

			if (strcmp(temp_comp_list[j].name,
				   graph_elem->sink) == 0) {
				connection.sink_id = temp_comp_list[j].id;
#ifdef BUILD_FUZZER
				sink = graph_elem->sink;
#endif
			}
		}
#ifdef BUILD_TESTBENCH
		strcat(pipeline_string, graph_elem->source);
		strcat(pipeline_string, "->");

		if (i == (count - 1))
			strcat(pipeline_string, graph_elem->sink);

		/* connect source and sink */
		if (connection.source_id != -1 && connection.sink_id != -1)
			if (ipc_comp_connect(sof->ipc, &connection) < 0) {
				fprintf(stderr, "error: comp connect\n");
				return -EINVAL;
			}
	}

	/* pipeline complete after pipeline connections are established */
	for (i = 0; i < num_comps; i++) {
		if (temp_comp_list[i].pipeline_id == pipeline_id &&
		    temp_comp_list[i].type == SND_SOC_TPLG_DAPM_SCHEDULER)
			ipc_pipeline_complete(sof->ipc, temp_comp_list[i].id);
	}

#endif

#ifdef BUILD_FUZZER
		/* connect source and sink */
		if (connection.source_id == -1 || connection.sink_id == -1)
			return -EINVAL;

		printf("loading route %s -> %s\n", source, sink);

		/* configure fuzzer msg */
		fuzzer->msg.header = connection.hdr.cmd;
		memcpy(fuzzer->msg.msg_data, &connection, connection.hdr.size);
		fuzzer->msg.msg_size = sizeof(connection);
		fuzzer->msg.reply_size = sizeof(r);

		ret = fuzzer_send_msg(fuzzer);
		if (ret < 0)
			fprintf(stderr, "error: message tx failed\n");
	}
#endif

	free(graph_elem);
	return 0;
}

/* load buffer DAPM widget */
#ifdef BUILD_TESTBENCH
static int load_buffer(struct sof *sof, int comp_id, int pipeline_id, int size)
#endif
#ifdef BUILD_FUZZER
static int load_buffer(struct fuzz *fuzzer, int comp_id,
		       int pipeline_id, int size)
#endif
{
	struct snd_soc_tplg_vendor_array *array = NULL;
	struct sof_ipc_buffer buffer;
#ifdef BUILD_FUZZER
	struct sof_ipc_comp_reply r;
#endif
	int ret = 0;

	/* configure buffer */
	buffer.comp.id = comp_id;
	buffer.comp.pipeline_id = pipeline_id;
#ifdef BUILD_FUZZER
	buffer.comp.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_BUFFER_NEW;
	buffer.comp.type = SOF_COMP_BUFFER;
	buffer.comp.hdr.size = sizeof(buffer);
#endif

	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	ret = fread(array, sizeof(struct snd_soc_tplg_vendor_array), 1, file);
	if (ret != 1)
		return -EINVAL;

	read_array(array);
	/* parse buffer tokens */
	ret = sof_parse_tokens(&buffer, buffer_tokens,
			       ARRAY_SIZE(buffer_tokens), array,
			       size);
#ifdef BUILD_TESTBENCH
	/* create buffer component */
	if (ipc_buffer_new(sof->ipc, &buffer) < 0) {
		fprintf(stderr, "error: buffer new\n");
		return -EINVAL;
	}
#endif

#ifdef BUILD_FUZZER
	/* configure fuzzer msg */
	fuzzer->msg.header = buffer.comp.hdr.cmd;
	memcpy(fuzzer->msg.msg_data, &buffer, buffer.comp.hdr.size);
	fuzzer->msg.msg_size = sizeof(buffer);
	fuzzer->msg.reply_size = sizeof(r);

	/* load volume component */
	ret = fuzzer_send_msg(fuzzer);
	if (ret < 0)
		fprintf(stderr, "error: message tx failed\n");
#endif
	free(array);
	return 0;
}

#ifdef BUILD_TESTBENCH
/* load fileread component */
static int load_fileread(struct sof *sof, int comp_id, int pipeline_id,
			 int size, int *fr_id, int *sched_id,
			 struct testbench_prm *tp)
#endif
#ifdef BUILD_FUZZER
/* load pcm component */
static int load_pcm(struct fuzz *fuzzer, int comp_id, int pipeline_id,
		    int size, int dir)
#endif
{
#ifdef BUILD_TESTBENCH
	struct sof_ipc_comp_file fileread;
#endif
	struct snd_soc_tplg_vendor_array *array = NULL;
#ifdef BUILD_FUZZER
	struct sof_ipc_comp_host host;
	struct sof_ipc_comp_reply r;
#endif
	size_t total_array_size = 0, read_size;
	int ret = 0;

#ifdef BUILD_TESTBENCH
	fileread.config.frame_fmt = find_format(tp->bits_in);
#endif

#ifdef BUILD_FUZZER
	/* configure host comp IPC message */
	host.comp.hdr.size = sizeof(host);
	host.comp.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_COMP_NEW;
	host.comp.id = comp_id;
	host.comp.type = SOF_COMP_HOST;
	host.comp.pipeline_id = pipeline_id;
	host.direction = dir;
	host.config.hdr.size = sizeof(host.config);
#endif

	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	if (!array) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	/* read vendor tokens */
	while (total_array_size < size) {
		read_size = sizeof(struct snd_soc_tplg_vendor_array);
		ret = fread(array, read_size, 1, file);
		if (ret != 1)
			return -EINVAL;
		read_array(array);

		/* parse comp tokens */
#ifdef BUILD_TESTBENCH
		ret = sof_parse_tokens(&fileread.config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
#endif
#ifdef BUILD_FUZZER
		ret = sof_parse_tokens(&host.config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse comp tokens %d\n",
				size);
			return -EINVAL;
		}

		/* parse pcm tokens */
		ret = sof_parse_tokens(&host, pcm_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
#endif
		if (ret != 0) {
#ifdef BUILD_TESTBENCH
			fprintf(stderr, "error: parse fileread tokens %d\n",
				size);
#endif
#ifdef BUILD_FUZZER
			fprintf(stderr, "error: parse pcm tokens %d\n", size);
#endif
			return -EINVAL;
		}

		total_array_size += array->size;
	}

#ifdef BUILD_TESTBENCH
	/* configure fileread */
	fileread.fn = strdup(tp->input_file);
	fileread.mode = FILE_READ;
	fileread.comp.id = comp_id;

	/* use fileread comp as scheduling comp */
	*fr_id = *sched_id = comp_id;
	fileread.comp.hdr.size = sizeof(struct sof_ipc_comp_file);
	fileread.comp.type = SOF_COMP_FILEREAD;
	fileread.comp.pipeline_id = pipeline_id;
	fileread.config.hdr.size = sizeof(struct sof_ipc_comp_config);

	/* create fileread component */
	if (ipc_comp_new(sof->ipc, (struct sof_ipc_comp *)&fileread) < 0) {
		fprintf(stderr, "error: comp register\n");
		return -EINVAL;
	}
#endif
#ifdef BUILD_FUZZER
	/* configure fuzzer msg */
	fuzzer->msg.header = host.comp.hdr.cmd;
	memcpy(fuzzer->msg.msg_data, &host, host.comp.hdr.size);
	fuzzer->msg.msg_size = sizeof(host);
	fuzzer->msg.reply_size = sizeof(r);

	/* load volume component */
	ret = fuzzer_send_msg(fuzzer);
	if (ret < 0)
		fprintf(stderr, "error: message tx failed\n");
#endif

	free(array);
#ifdef BUILD_TESTBENCH
	free(fileread.fn);
#endif
	return 0;
}

#ifdef BUILD_TESTBENCH
/* load filewrite component */
static int load_filewrite(struct sof *sof, int comp_id, int pipeline_id,
			  int size, int *fw_id, struct testbench_prm *tp)
#endif
#ifdef BUILD_FUZZER
/* load dai component */
static int load_dai(struct fuzz *fuzzer, int comp_id, int pipeline_id,
		    int size)
#endif
{
#ifdef BUILD_TESTBENCH
	struct sof_ipc_comp_file filewrite;
#endif
	struct snd_soc_tplg_vendor_array *array = NULL;
#ifdef BUILD_FUZZER
	struct sof_ipc_comp_dai comp_dai;
	struct sof_ipc_comp_reply r;
#endif
	size_t total_array_size = 0, read_size;
	int ret = 0;
#ifdef BUILD_FUZZER
	/* configure comp_dai */
	comp_dai.comp.hdr.size = sizeof(comp_dai);
	comp_dai.comp.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_COMP_NEW;
	comp_dai.comp.id = comp_id;
	comp_dai.comp.type = SOF_COMP_DAI;
	comp_dai.comp.pipeline_id = pipeline_id;
	comp_dai.config.hdr.size = sizeof(comp_dai.config);
#endif
	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	if (!array) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	/* read vendor tokens */
	while (total_array_size < size) {
		read_size = sizeof(struct snd_soc_tplg_vendor_array);
		ret = fread(array, read_size, 1, file);
		if (ret != 1)
			return -EINVAL;

		read_array(array);
#ifdef BUILD_FUZZER
		ret = sof_parse_tokens(&comp_dai, dai_tokens,
				       ARRAY_SIZE(dai_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse dai tokens failed %d\n",
				size);
			return -EINVAL;
		}

		/* parse comp tokens */
		ret = sof_parse_tokens(&comp_dai.config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
#endif
#ifdef BUILD_TESTBENCH
		ret = sof_parse_tokens(&filewrite.config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
#endif
		if (ret != 0) {
			fprintf(stderr, "error: parse filewrite tokens %d\n",
				size);
			return -EINVAL;
		}
		total_array_size += array->size;
	}

#ifdef BUILD_TESTBENCH
	/* configure filewrite */
	filewrite.fn = strdup(tp->output_file);
	filewrite.comp.id = comp_id;
	filewrite.mode = FILE_WRITE;
	*fw_id = comp_id;
	filewrite.comp.hdr.size = sizeof(struct sof_ipc_comp_file);
	filewrite.comp.type = SOF_COMP_FILEREAD;
	filewrite.comp.pipeline_id = pipeline_id;
	filewrite.config.hdr.size = sizeof(struct sof_ipc_comp_config);

	/* create filewrite component */
	if (ipc_comp_new(sof->ipc, (struct sof_ipc_comp *)&filewrite) < 0) {
		fprintf(stderr, "error: comp register\n");
		return -EINVAL;
	}
#endif
#ifdef BUILD_FUZZER
	/* configure fuzzer msg */
	fuzzer->msg.header = comp_dai.comp.hdr.cmd;
	memcpy(fuzzer->msg.msg_data, &comp_dai, comp_dai.comp.hdr.size);
	fuzzer->msg.msg_size = sizeof(comp_dai);
	fuzzer->msg.reply_size = sizeof(r);

	/* load volume component */
	ret = fuzzer_send_msg(fuzzer);
	if (ret < 0)
		fprintf(stderr, "error: message tx failed\n");
#endif
	free(array);
#ifdef BUILD_TESTBENCH
	free(filewrite.fn);
#endif
	return 0;
}

/* load pda dapm widget */
#ifdef BUILD_TESTBENCH
static int load_pga(struct sof *sof, int comp_id, int pipeline_id, int size)
#endif
#ifdef BUILD_FUZZER
static int load_pga(struct fuzz *fuzzer, int comp_id, int pipeline_id,
		    int size)
#endif
{
	struct sof_ipc_comp_volume volume;
	struct snd_soc_tplg_vendor_array *array = NULL;
#ifdef BUILD_FUZZER
	struct sof_ipc_comp_reply r;
#endif
	size_t total_array_size = 0, read_size;
	int ret = 0;

	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	if (!array) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	/* read vendor tokens */
	while (total_array_size < size) {
		read_size = sizeof(struct snd_soc_tplg_vendor_array);
		ret = fread(array, read_size, 1, file);
		if (ret != 1)
			return -EINVAL;
		read_array(array);

		/* parse volume tokens */
		ret = sof_parse_tokens(&volume.config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse pga tokens %d\n", size);
			return -EINVAL;
		}
		total_array_size += array->size;
	}

	/* configure volume */
#ifdef BUILD_FUZZER
	volume.comp.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_COMP_NEW;
#endif
	volume.comp.id = comp_id;
	volume.comp.hdr.size = sizeof(struct sof_ipc_comp_volume);
	volume.comp.type = SOF_COMP_VOLUME;
	volume.comp.pipeline_id = pipeline_id;
	volume.config.hdr.size = sizeof(struct sof_ipc_comp_config);

#ifdef BUILD_FUZZER
	/* configure fuzzer msg */
	fuzzer->msg.header = volume.comp.hdr.cmd;
	memcpy(fuzzer->msg.msg_data, &volume, volume.comp.hdr.size);
	fuzzer->msg.msg_size = sizeof(volume);
	fuzzer->msg.reply_size = sizeof(r);
#endif

	/* load volume component */
#ifdef BUILD_TESTBENCH
	if (ipc_comp_new(sof->ipc, (struct sof_ipc_comp *)&volume) < 0) {
		fprintf(stderr, "error: comp register\n");
		return -EINVAL;
	}
#endif
#ifdef BUILD_FUZZER
	ret = fuzzer_send_msg(fuzzer);
	if (ret < 0)
		fprintf(stderr, "error: message tx failed\n");
#endif
	free(array);
	return 0;
}

/* load scheduler dapm widget */
#ifdef BUILD_TESTBENCH
static int load_pipeline(struct sof *sof, struct sof_ipc_pipe_new *pipeline,
			 int comp_id, int pipeline_id, int size, int *sched_id)
#endif
#ifdef BUILD_FUZZER
static int load_pipeline(struct fuzz *fuzzer, int comp_id, int pipeline_id,
			 int size, int sched_id)
#endif
{
	struct snd_soc_tplg_vendor_array *array = NULL;
#ifdef BUILD_FUZZER
	struct sof_ipc_pipe_new pipeline;
	struct sof_ipc_comp_reply r;
#endif
	size_t total_array_size = 0, read_size;
	int ret = 0;

	/* configure pipeline */
#ifdef BUILD_TESTBENCH
	pipeline->sched_id = *sched_id;
	pipeline->comp_id = comp_id;
	pipeline->pipeline_id = pipeline_id;
#endif
#ifdef BUILD_FUZZER
	pipeline.hdr.size = sizeof(pipeline);
	pipeline.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_PIPE_NEW;
	pipeline.sched_id = sched_id;
	pipeline.comp_id = comp_id;
	pipeline.pipeline_id = pipeline_id;
#endif
	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	if (!array) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	/* read vendor arrays */
	while (total_array_size < size) {
		read_size = sizeof(struct snd_soc_tplg_vendor_array);
		ret = fread(array, read_size, 1, file);
		if (ret != 1)
			return -EINVAL;

		ret = read_array(array);
		if (ret < 0)
			return -EINVAL;

		/* parse scheduler tokens */
#ifdef BUILD_TESTBENCH
		ret = sof_parse_tokens(pipeline, sched_tokens,
				       ARRAY_SIZE(sched_tokens), array,
				       array->size);
#endif
#ifdef BUILD_FUZZER
		ret = sof_parse_tokens(&pipeline, sched_tokens,
				       ARRAY_SIZE(sched_tokens), array,
				       array->size);
#endif
		if (ret != 0) {
			fprintf(stderr, "error: parse pipeline tokens %d\n",
				size);
			return -EINVAL;
		}
		total_array_size += array->size;
	}
#ifdef BUILD_TESTBENCH
	/* Create pipeline */
	if (ipc_pipeline_new(sof->ipc, pipeline) < 0) {
		fprintf(stderr, "error: pipeline new\n");
		return -EINVAL;
	}
#endif
#ifdef BUILD_FUZZER
	/* configure fuzzer msg */
	fuzzer->msg.header = pipeline.hdr.cmd;
	memcpy(fuzzer->msg.msg_data, &pipeline, pipeline.hdr.size);
	fuzzer->msg.msg_size = sizeof(pipeline);
	fuzzer->msg.reply_size = sizeof(r);

	/* load volume component */
	ret = fuzzer_send_msg(fuzzer);
	if (ret < 0)
		fprintf(stderr, "error: message tx failed\n");
#endif
	free(array);
	return 0;
}

/* load dapm widget kcontrols
 * we don't use controls in the testbench or the fuzzer atm.
 * so just skip to the next dapm widget
 */
#ifdef BUILD_TESTBENCH
static int load_controls(struct sof *sof, int num_kcontrols)
#endif
#ifdef BUILD_FUZZER
static int load_controls(struct fuzz *fuzzer, int num_kcontrols)
#endif
{
	struct snd_soc_tplg_ctl_hdr *ctl_hdr;
	struct snd_soc_tplg_mixer_control *mixer_ctl;
	struct snd_soc_tplg_enum_control *enum_ctl;
	struct snd_soc_tplg_bytes_control *bytes_ctl;
	size_t read_size, size;
	int j, ret = 0;

	/* allocate memory */
	size = sizeof(struct snd_soc_tplg_ctl_hdr);
	ctl_hdr = (struct snd_soc_tplg_ctl_hdr *)malloc(size);
	if (!ctl_hdr) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	size = sizeof(struct snd_soc_tplg_mixer_control);
	mixer_ctl = (struct snd_soc_tplg_mixer_control *)malloc(size);
	if (!mixer_ctl) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	size = sizeof(struct snd_soc_tplg_enum_control);
	enum_ctl = (struct snd_soc_tplg_enum_control *)malloc(size);
	if (!enum_ctl) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	size = sizeof(struct snd_soc_tplg_bytes_control);
	bytes_ctl = (struct snd_soc_tplg_bytes_control *)malloc(size);
	if (!bytes_ctl) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	for (j = 0; j < num_kcontrols; j++) {
		/* read control header */
		read_size = sizeof(struct snd_soc_tplg_ctl_hdr);
		ret = fread(ctl_hdr, read_size, 1, file);
		if (ret != 1)
			return -EINVAL;

		/* load control based on type */
		switch (ctl_hdr->ops.info) {
		case SND_SOC_TPLG_CTL_VOLSW:
		case SND_SOC_TPLG_CTL_STROBE:
		case SND_SOC_TPLG_CTL_VOLSW_SX:
		case SND_SOC_TPLG_CTL_VOLSW_XR_SX:
		case SND_SOC_TPLG_CTL_RANGE:
		case SND_SOC_TPLG_DAPM_CTL_VOLSW:

			/* load mixer type control */
			read_size = sizeof(struct snd_soc_tplg_ctl_hdr);
			fseek(file, read_size * -1, SEEK_CUR);
			read_size = sizeof(struct snd_soc_tplg_mixer_control);
			ret = fread(mixer_ctl, read_size, 1, file);
			if (ret != 1)
				return -EINVAL;

			/* skip mixer private data */
			fseek(file, mixer_ctl->priv.size, SEEK_CUR);
			break;
		case SND_SOC_TPLG_CTL_ENUM:
		case SND_SOC_TPLG_CTL_ENUM_VALUE:
		case SND_SOC_TPLG_DAPM_CTL_ENUM_DOUBLE:
		case SND_SOC_TPLG_DAPM_CTL_ENUM_VIRT:
		case SND_SOC_TPLG_DAPM_CTL_ENUM_VALUE:

			/* load enum type control */
			read_size = sizeof(struct snd_soc_tplg_ctl_hdr);
			fseek(file, read_size * -1, SEEK_CUR);
			read_size = sizeof(struct snd_soc_tplg_enum_control);
			ret = fread(enum_ctl, read_size, 1, file);
			if (ret != 1)
				return -EINVAL;

			/* skip enum private data */
			fseek(file, enum_ctl->priv.size, SEEK_CUR);
			break;
		case SND_SOC_TPLG_CTL_BYTES:

			/* load bytes type controls */
			read_size = sizeof(struct snd_soc_tplg_ctl_hdr);
			fseek(file, read_size * -1, SEEK_CUR);
			read_size = sizeof(struct snd_soc_tplg_bytes_control);
			ret = fread(bytes_ctl, read_size, 1, file);
			if (ret != 1)
				return -EINVAL;

			/* skip bytes private data */
			fseek(file, bytes_ctl->priv.size, SEEK_CUR);
			break;
		default:
			printf("info: control type not supported\n");
			return -EINVAL;
		}
	}

	/* free all data */
	free(mixer_ctl);
	free(enum_ctl);
	free(bytes_ctl);
	free(ctl_hdr);
	return 0;
}

/* load src dapm widget */
#ifdef BUILD_TESTBENCH
static int load_src(struct sof *sof, int comp_id, int pipeline_id,
		    int size, struct testbench_prm *tp)
#endif
#ifdef BUILD_FUZZER
static int load_src(struct fuzz *fuzzer, int comp_id, int pipeline_id,
		    int size)
#endif
{
	struct sof_ipc_comp_src src = {0};
	struct snd_soc_tplg_vendor_array *array = NULL;
#ifdef BUILD_FUZZER
	struct sof_ipc_comp_reply r;
#endif
	size_t total_array_size = 0, read_size;
	int ret = 0;

	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	if (!array) {
		fprintf(stderr, "error: mem alloc for src vendor array\n");
		return -EINVAL;
	}

	/* read vendor tokens */
	while (total_array_size < size) {
		read_size = sizeof(struct snd_soc_tplg_vendor_array);
		ret = fread(array, read_size, 1, file);
		if (ret != 1)
			return -EINVAL;
		read_array(array);

		/* parse comp tokens */
		ret = sof_parse_tokens(&src.config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse src comp_tokens %d\n",
				size);
			return -EINVAL;
		}

		/* parse src tokens */
		ret = sof_parse_tokens(&src, src_tokens,
				       ARRAY_SIZE(src_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse src tokens %d\n", size);
			return -EINVAL;
		}

		total_array_size += array->size;

		/* read next array */
		array = (void *)array + array->size;
	}

	array = (void *)array - size;

#ifdef BUILD_TESTBENCH
	/* set testbench input and output sample rate from topology */
	if (!tp->fs_out) {
		tp->fs_out = src.sink_rate;

		if (!tp->fs_in)
			tp->fs_in = src.source_rate;
		else
			src.source_rate = tp->fs_in;
	} else {
		src.sink_rate = tp->fs_out;
	}
#endif
	/* configure src */
#ifdef BUILD_FUZZER
	src.comp.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_COMP_NEW;
#endif
	src.comp.id = comp_id;
	src.comp.hdr.size = sizeof(struct sof_ipc_comp_src);
	src.comp.type = SOF_COMP_SRC;
	src.comp.pipeline_id = pipeline_id;
	src.config.hdr.size = sizeof(struct sof_ipc_comp_config);

#ifdef BUILD_TESTBENCH
	/* load src component */
	if (ipc_comp_new(sof->ipc, (struct sof_ipc_comp *)&src) < 0) {
		fprintf(stderr, "error: new src comp\n");
		return -EINVAL;
	}
#endif
#ifdef BUILD_FUZZER
	/* configure fuzzer msg */
	fuzzer->msg.header = src.comp.hdr.cmd;
	memcpy(fuzzer->msg.msg_data, &src, src.comp.hdr.size);
	fuzzer->msg.msg_size = sizeof(src);
	fuzzer->msg.reply_size = sizeof(r);

	/* load volume component */
	ret = fuzzer_send_msg(fuzzer);
	if (ret < 0)
		fprintf(stderr, "error: message tx failed\n");
#endif
	free(array);
	return 0;
}

#ifdef BUILD_FUZZER
/* load mixer dapm widget */
static int load_mixer(struct fuzz *fuzzer, int comp_id, int pipeline_id,
		      int size)
{
	struct sof_ipc_comp_mixer mixer = {0};
	struct snd_soc_tplg_vendor_array *array = NULL;
	struct sof_ipc_comp_reply r;
	size_t total_array_size = 0, read_size;
	int ret = 0;

	/* allocate memory for vendor tuple array */
	array = (struct snd_soc_tplg_vendor_array *)malloc(size);
	if (!array) {
		fprintf(stderr, "error: mem alloc for src vendor array\n");
		return -EINVAL;
	}

	/* read vendor tokens */
	while (total_array_size < size) {
		read_size = sizeof(struct snd_soc_tplg_vendor_array);
		ret = fread(array, read_size, 1, file);
		if (ret != 1)
			return -EINVAL;
		read_array(array);

		/* parse comp tokens */
		ret = sof_parse_tokens(&mixer.config, comp_tokens,
				       ARRAY_SIZE(comp_tokens), array,
				       array->size);
		if (ret != 0) {
			fprintf(stderr, "error: parse src comp_tokens %d\n",
				size);
			return -EINVAL;
		}

		total_array_size += array->size;

		/* read next array */
		array = (void *)array + array->size;
	}

	array = (void *)array - size;

	/* configure src */
	mixer.comp.hdr.cmd = SOF_IPC_GLB_TPLG_MSG | SOF_IPC_TPLG_COMP_NEW;
	mixer.comp.id = comp_id;
	mixer.comp.hdr.size = sizeof(struct sof_ipc_comp_src);
	mixer.comp.type = SOF_COMP_MIXER;
	mixer.comp.pipeline_id = pipeline_id;
	mixer.config.hdr.size = sizeof(struct sof_ipc_comp_config);

	/* configure fuzzer msg */
	fuzzer->msg.header = mixer.comp.hdr.cmd;
	memcpy(fuzzer->msg.msg_data, &mixer, mixer.comp.hdr.size);
	fuzzer->msg.msg_size = sizeof(mixer);
	fuzzer->msg.reply_size = sizeof(r);

	/* load volume component */
	ret = fuzzer_send_msg(fuzzer);
	if (ret < 0)
		fprintf(stderr, "error: message tx failed\n");

	free(array);
	return 0;
}
#endif

/* load dapm widget */
#ifdef BUILD_TESTBENCH
static int load_widget(struct sof *sof, int *fr_id, int *fw_id, int *sched_id,
		       struct comp_info *temp_comp_list,
		       struct sof_ipc_pipe_new *pipeline, int comp_id,
		       int comp_index, int pipeline_id,
		       struct testbench_prm *tp)
#endif
#ifdef BUILD_FUZZER
static int load_widget(struct fuzz *fuzzer, struct comp_info *temp_comp_list,
		       int comp_id, int comp_index, int pipeline_id)
#endif
{
	struct snd_soc_tplg_dapm_widget *widget;
	char message[DEBUG_MSG_LEN];
	size_t read_size, size;
#ifdef BUILD_FUZZER
	int sched_id;
#endif
	int ret = 0;

	/* allocate memory for widget */
	size = sizeof(struct snd_soc_tplg_dapm_widget);
	widget = (struct snd_soc_tplg_dapm_widget *)malloc(size);
	if (!widget) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}

	/* read widget data */
	read_size = sizeof(struct snd_soc_tplg_dapm_widget);
	ret = fread(widget, read_size, 1, file);
	if (ret != 1)
		return -EINVAL;

	/*
	 * create a list with all widget info
	 * containing mapping between component names and ids
	 * which will be used for setting up component connections
	 */
	temp_comp_list[comp_index].id = comp_id;
	temp_comp_list[comp_index].name = strdup(widget->name);
	temp_comp_list[comp_index].type = widget->id;
	temp_comp_list[comp_index].pipeline_id = pipeline_id;

	sprintf(message, "loading widget %s id %d\n",
		temp_comp_list[comp_index].name,
		temp_comp_list[comp_index].id);
#ifdef BUILD_TESTBENCH
	debug_print(message);

	/* register comp driver */
	register_comp(temp_comp_list[comp_index].type);
#endif
#ifdef BUILD_FUZZER
	printf("debug %s\n", message);
#endif

	/* load widget based on type */
	switch (temp_comp_list[comp_index].type) {
	/* load pga widget */
	case(SND_SOC_TPLG_DAPM_PGA):
#ifdef BUILD_TESTBENCH
		if (load_pga(sof, temp_comp_list[comp_index].id,
			     pipeline_id, widget->priv.size) < 0) {
			fprintf(stderr, "error: load pga\n");
			return -EINVAL;
		}
#endif
#ifdef BUILD_FUZZER
		if (load_pga(fuzzer, temp_comp_list[comp_index].id,
			     pipeline_id, widget->priv.size) < 0) {
			fprintf(stderr, "error: load pga\n");
			return -EINVAL;
		}
#endif
		break;
	/* replace pcm playback component with fileread in testbench */
	case(SND_SOC_TPLG_DAPM_AIF_IN):
#ifdef BUILD_TESTBENCH
		if (load_fileread(sof, temp_comp_list[comp_index].id,
				  pipeline_id, widget->priv.size,
				  fr_id, sched_id, tp) < 0) {
			fprintf(stderr, "error: load fileread\n");
			return -EINVAL;
		}
#endif
#ifdef BUILD_FUZZER
		if (load_pcm(fuzzer, temp_comp_list[comp_index].id,
			     pipeline_id, widget->priv.size,
			     SOF_IPC_STREAM_PLAYBACK) < 0) {
			fprintf(stderr, "error: load playback pcm\n");
			return -EINVAL;
		}
#endif
		break;
#ifdef BUILD_FUZZER
	case(SND_SOC_TPLG_DAPM_AIF_OUT):
		if (load_pcm(fuzzer, temp_comp_list[comp_index].id,
			     pipeline_id, widget->priv.size,
			     SOF_IPC_STREAM_CAPTURE) < 0) {
			fprintf(stderr, "error: load capture pcm\n");
			return -EINVAL;
		}
		break;
#endif
	/* replace dai in component with filewrite in testbench */
	case(SND_SOC_TPLG_DAPM_DAI_IN):
#ifdef BUILD_TESTBENCH
		if (load_filewrite(sof, temp_comp_list[comp_index].id,
				   pipeline_id, widget->priv.size,
				   fw_id, tp) < 0)
			fprintf(stderr, "error: load filewrite\n");
#endif
#ifdef BUILD_FUZZER
	case(SND_SOC_TPLG_DAPM_DAI_OUT):
		if (load_dai(fuzzer, temp_comp_list[comp_index].id,
			     pipeline_id, widget->priv.size) < 0)
			fprintf(stderr, "error: load dai\n");
#endif
		return -EINVAL;
		break;

	/* load buffer */
	case(SND_SOC_TPLG_DAPM_BUFFER):
#ifdef BUILD_TESTBENCH
		if (load_buffer(sof, temp_comp_list[comp_index].id,
				pipeline_id, widget->priv.size) < 0) {
			fprintf(stderr, "error: load buffer\n");
			return -EINVAL;
		}
#endif
#ifdef BUILD_FUZZER
		if (load_buffer(fuzzer, temp_comp_list[comp_index].id,
				pipeline_id, widget->priv.size) < 0) {
			fprintf(stderr, "error: load buffer\n");
			return -EINVAL;
		}
#endif
		break;

	/* load pipeline */
	case(SND_SOC_TPLG_DAPM_SCHEDULER):
#ifdef BUILD_FUZZER
		/* find comp id for schedulimp comp */
		sched_id = find_widget(temp_comp_list, comp_id,
				       widget->sname);
#endif
#ifdef BUILD_TESTBENCH
		if (load_pipeline(sof, pipeline, temp_comp_list[comp_index].id,
				  pipeline_id,
				  widget->priv.size, sched_id) < 0) {
			fprintf(stderr, "error: load pipeline\n");
			return -EINVAL;
		}
#endif
#ifdef BUILD_FUZZER
		if (load_pipeline(fuzzer, temp_comp_list[comp_index].id,
				  pipeline_id,
				  widget->priv.size, sched_id) < 0) {
			fprintf(stderr, "error: load pipeline\n");
			return -EINVAL;
		}
#endif
		break;

	/* load src widget */
	case(SND_SOC_TPLG_DAPM_SRC):
#ifdef BUILD_TESTBENCH
		if (load_src(sof, temp_comp_list[comp_index].id,
			     pipeline_id, widget->priv.size, tp) < 0) {
			fprintf(stderr, "error: load src\n");
			return -EINVAL;
		}
#endif
#ifdef BUILD_FUZZER
		if (load_src(fuzzer, temp_comp_list[comp_index].id,
			     pipeline_id, widget->priv.size) < 0) {
			fprintf(stderr, "error: load src\n");
			return -EINVAL;
		}
#endif
		break;
#ifdef BUILD_FUZZER
	/* load mixer widget */
	case(SND_SOC_TPLG_DAPM_MIXER):
		if (load_mixer(fuzzer, temp_comp_list[comp_index].id,
			       pipeline_id, widget->priv.size) < 0) {
			fprintf(stderr, "error: load mixer\n");
			return -EINVAL;
		}
		break;
#endif
	/* unsupported widgets */
	default:
#ifdef BUILD_FUZZER
		fseek(file, widget->priv.size, SEEK_CUR);
#endif
		printf("info: Widget type not supported %d\n",
		       widget->id);
		break;
	}

	/* load widget kcontrols */
	if (widget->num_kcontrols > 0)
#ifdef BUILD_TESTBENCH
		if (load_controls(sof, widget->num_kcontrols) < 0) {
			fprintf(stderr, "error: load buffer\n");
			return -EINVAL;
		}
#endif
#ifdef BUILD_FUZZER
		if (load_controls(fuzzer, widget->num_kcontrols) < 0) {
			fprintf(stderr, "error: load buffer\n");
			return -EINVAL;
		}
#endif
	free(widget);
	return 0;
}

/* parse topology file and set up pipeline */
#ifdef BUILD_TESTBENCH
int parse_topology(struct sof *sof, struct shared_lib_table *library_table,
		   struct testbench_prm *tp, int *fr_id, int *fw_id,
		   int *sched_id, char *pipeline_msg)
#endif
#ifdef BUILD_FUZZER
int parse_tplg(struct fuzz *fuzzer, char *tplg_filename)
#endif
{
	struct snd_soc_tplg_hdr *hdr;

	struct comp_info *temp_comp_list = NULL;
	struct sof_ipc_pipe_new pipeline;
	char message[DEBUG_MSG_LEN];
	int next_comp_id = 0, num_comps = 0;
	int i, ret = 0;
	size_t file_size, size;

	/* open topology file */
#ifdef BUILD_TESTBENCH
	file = fopen(tp->tplg_file, "rb");
#endif
#ifdef BUILD_FUZZER
	file = fopen(tplg_filename, "rb");
#endif
	if (!file) {
#ifdef BUILD_TESTBENCH
		fprintf(stderr, "error: opening file %s\n", tp->tplg_file);
#endif
#ifdef BUILD_FUZZER
		fprintf(stderr, "error: opening file %s\n", tplg_filename);
#endif
		return -EINVAL;
	}
#ifdef BUILD_TESTBENCH
	lib_table = library_table;
#endif
	/* file size */
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	/* allocate memory */
	size = sizeof(struct snd_soc_tplg_hdr);
	hdr = (struct snd_soc_tplg_hdr *)malloc(size);
	if (!hdr) {
		fprintf(stderr, "error: mem alloc\n");
		return -EINVAL;
	}
#ifdef BUILD_TESTBENCH
	debug_print("topology parsing start\n");
#endif
#ifdef BUILD_FUZZER
	printf("debug: %s", "topology parsing start\n");
#endif
	while (1) {
		/* read topology header */
		ret = fread(hdr, sizeof(struct snd_soc_tplg_hdr), 1, file);
		if (ret != 1)
			return -EINVAL;

		sprintf(message, "type: %x, size: 0x%x count: %d index: %d\n",
			hdr->type, hdr->payload_size, hdr->count, hdr->index);
#ifdef BUILD_TESTBENCH
		debug_print(message);
#endif
#ifdef BUILD_FUZZER
		printf("debug %s\n", message);
#endif
		/* parse header and load the next block based on type */
		switch (hdr->type) {
		/* load dapm widget */
		case SND_SOC_TPLG_TYPE_DAPM_WIDGET:
			sprintf(message, "number of DAPM widgets %d\n",
				hdr->count);
#ifdef BUILD_TESTBENCH
			debug_print(message);
#endif
#ifdef BUILD_FUZZER
			printf("debug %s\n", message);
#endif

			num_comps += hdr->count;
			size = sizeof(struct comp_info) * num_comps;
			temp_comp_list = (struct comp_info *)
					 realloc(temp_comp_list, size);

			for (i = (num_comps - hdr->count); i < num_comps; i++)
#ifdef BUILD_TESTBENCH
				ret = load_widget(sof, fr_id, fw_id, sched_id,
						  temp_comp_list, &pipeline,
						  next_comp_id++,
						  i, hdr->index, tp);
#endif
#ifdef BUILD_FUZZER
				ret = load_widget(fuzzer, temp_comp_list,
						  next_comp_id++, i,
						  hdr->index);
#endif
				if (ret < 0) {
					printf("error: loading widget\n");
					goto finish;
				}
			break;

		/* set up component connections from pipeline graph */
		case SND_SOC_TPLG_TYPE_DAPM_GRAPH:
#ifdef BUILD_TESTBENCH
			if (load_graph(sof, temp_comp_list, hdr->count,
				       num_comps, hdr->index) < 0) {
				fprintf(stderr, "error: pipeline graph\n");
				return -EINVAL;
			}
#endif
#ifdef BUILD_FUZZER
			if (load_graph(fuzzer, temp_comp_list, hdr->count,
				       num_comps, hdr->index) < 0) {
				fprintf(stderr, "error: pipeline graph\n");
				return -EINVAL;
			}
#endif
			if (ftell(file) == file_size)
				goto finish;
			break;
		default:
			fseek(file, hdr->payload_size, SEEK_CUR);
			if (ftell(file) == file_size)
				goto finish;
			break;
		}
	}
finish:
#ifdef BUILD_TESTBENCH
	debug_print("topology parsing end\n");
	strcpy(pipeline_msg, pipeline_string);
#endif
#ifdef BUILD_FUZZER
	/* pipeline complete after pipeline connections are established */
	for (i = 0; i < num_comps; i++)
		if (temp_comp_list[i].type == SND_SOC_TPLG_DAPM_SCHEDULER)
			complete_pipeline(fuzzer, temp_comp_list[i].id);

	printf("debug: %s", "topology parsing end\n");
#endif
	/* free all data */
	free(hdr);

	for (i = 0; i < num_comps; i++)
		free(temp_comp_list[i].name);

	free(temp_comp_list);
	fclose(file);
	return 0;
}

/* parse vendor tokens in topology */
int sof_parse_tokens(void *object, const struct sof_topology_token *tokens,
		     int count, struct snd_soc_tplg_vendor_array *array,
		     int priv_size)
{
	int asize;

	while (priv_size > 0) {
		asize = array->size;

		/* validate asize */
		if (asize < 0) { /* FIXME: A zero-size array makes no sense */
			fprintf(stderr, "error: invalid array size 0x%x\n",
				asize);
			return -EINVAL;
		}

		/* make sure there is enough data before parsing */
		priv_size -= asize;

		if (priv_size < 0) {
			fprintf(stderr, "error: invalid array size 0x%x\n",
				asize);
			return -EINVAL;
		}

		/* call correct parser depending on type */
		switch (array->type) {
		case SND_SOC_TPLG_TUPLE_TYPE_UUID:
			sof_parse_uuid_tokens(object, tokens, count,
					      array);
			break;
		case SND_SOC_TPLG_TUPLE_TYPE_STRING:
			sof_parse_string_tokens(object, tokens, count,
						array);
			break;
		case SND_SOC_TPLG_TUPLE_TYPE_BOOL:
		case SND_SOC_TPLG_TUPLE_TYPE_BYTE:
		case SND_SOC_TPLG_TUPLE_TYPE_WORD:
		case SND_SOC_TPLG_TUPLE_TYPE_SHORT:
			sof_parse_word_tokens(object, tokens, count,
					      array);
			break;
		default:
			fprintf(stderr, "error: unknown token type %d\n",
				array->type);
			return -EINVAL;
		}
	}
	return 0;
}

/* parse word tokens */
void sof_parse_word_tokens(void *object,
			   const struct sof_topology_token *tokens,
			   int count,
			   struct snd_soc_tplg_vendor_array *array)
{
	struct snd_soc_tplg_vendor_value_elem *elem;
	int i, j;

	/* parse element by element */
	for (i = 0; i < array->num_elems; i++) {
		elem = &array->value[i];

		/* search for token */
		for (j = 0; j < count; j++) {
			/* match token type */
			if (tokens[j].type != SND_SOC_TPLG_TUPLE_TYPE_WORD)
				continue;

			/* match token id */
			if (tokens[j].token != elem->token)
				continue;

			/* matched - now load token */
			tokens[j].get_token(elem, object, tokens[j].offset,
					    tokens[j].size);
		}
	}
}

/* parse uuid tokens */
void sof_parse_uuid_tokens(void *object,
			   const struct sof_topology_token *tokens,
			   int count,
			   struct snd_soc_tplg_vendor_array *array)
{
	struct snd_soc_tplg_vendor_uuid_elem *elem;
	int i, j;

	/* parse element by element */
	for (i = 0; i < array->num_elems; i++) {
		elem = &array->uuid[i];

		/* search for token */
		for (j = 0; j < count; j++) {
			/* match token type */
			if (tokens[j].type != SND_SOC_TPLG_TUPLE_TYPE_UUID)
				continue;

			/* match token id */
			if (tokens[j].token != elem->token)
				continue;

			/* matched - now load token */
			tokens[j].get_token(elem, object, tokens[j].offset,
					    tokens[j].size);
		}
	}
}

/* parse string tokens */
void sof_parse_string_tokens(void *object,
			     const struct sof_topology_token *tokens,
			     int count,
			     struct snd_soc_tplg_vendor_array *array)
{
	struct snd_soc_tplg_vendor_string_elem *elem;
	int i, j;

	/* parse element by element */
	for (i = 0; i < array->num_elems; i++) {
		elem = &array->string[i];

		/* search for token */
		for (j = 0; j < count; j++) {
			/* match token type */
			if (tokens[j].type != SND_SOC_TPLG_TUPLE_TYPE_STRING)
				continue;

			/* match token id */
			if (tokens[j].token != elem->token)
				continue;

			/* matched - now load token */
			tokens[j].get_token(elem, object, tokens[j].offset,
					    tokens[j].size);
		}
	}
}

enum sof_ipc_frame find_format(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sof_frames); i++) {
		if (strcmp(name, sof_frames[i].name) == 0)
			return sof_frames[i].frame;
	}

	/* use s32le if nothing is specified */
	return SOF_IPC_FRAME_S32_LE;
}

/* helper functions to get tokens */
int get_token_uint32_t(void *elem, void *object, uint32_t offset,
		       uint32_t size)
{
	struct snd_soc_tplg_vendor_value_elem *velem = elem;
	uint32_t *val = object + offset;

	*val = velem->value;
	return 0;
}

int get_token_comp_format(void *elem, void *object, uint32_t offset,
			  uint32_t size)
{
	struct snd_soc_tplg_vendor_string_elem *velem = elem;
	uint32_t *val = object + offset;

	*val = find_format(velem->string);
	return 0;
}

#ifdef BUILD_FUZZER
int get_token_dai_type(void *elem, void *object, uint32_t offset, uint32_t size)
{
	struct snd_soc_tplg_vendor_string_elem *velem = elem;
	uint32_t *val = (uint32_t *)((uint8_t *)object + offset);

	*val = find_dai(velem->string);
	return 0;
}

/* find dai type */
enum sof_ipc_dai_type find_dai(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sof_dais); i++) {
		if (strcmp(name, sof_dais[i].name) == 0)
			return sof_dais[i].type;
	}

	return SOF_DAI_INTEL_NONE;
}
#endif

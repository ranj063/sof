#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation. All rights reserved.
set -e

DYNAMIC_PIPELINES=0

# parse the args
while getopts "d:i:" OPTION; do
        case "$OPTION" in
		d) DYNAMIC_PIPELINES=$OPTARG ;;
		i) INPUT_FILE=$OPTARG ;;
        esac
done

# Read input file and process machine quirks
while IFS= read -r line; do
	if [[ "$line" == *"dynamic_pipeline"* ]]; then
		printf '\t\t%s\n' "dynamic_pipeline $DYNAMIC_PIPELINES"
	else
		printf '%s\n' "$line"
	fi
done < ${INPUT_FILE}

# SPDX-License-Identifier: BSD-3-Clause

# Array of "input-file-name;output-file-name;pre-processor macros separated by comma"
set(TPLGS
# HDA Generic topology
"sof-hda-generic\;sof-hda-generic\;\
DYNAMIC_PIPELINE=1"

# HDA Generic topology with 1ch DMIC
"sof-hda-generic\;sof-hda-generic-1ch\; \
DYNAMIC_PIPELINE=1,\
DMIC_INCLUDE=1,\
DMIC_CH_COUNT=1"

# HDA Generic topology with 2ch DMIC
"sof-hda-generic\;sof-hda-generic-2ch\;\
DYNAMIC_PIPELINE=1,\
DMIC_INCLUDE=1,\
DMIC_CH_COUNT=2"

# HDA Generic topology with 3ch DMIC
"sof-hda-generic\;sof-hda-generic-3ch\;\
DYNAMIC_PIPELINE=1,\
DMIC_INCLUDE=1,\
DMIC_CH_COUNT=3"

# HDA Generic topology with 4ch DMIC
"sof-hda-generic\;sof-hda-generic-4ch\;\
DYNAMIC_PIPELINE=1,\
DMIC_INCLUDE=1,\
DMIC_CH_COUNT=4"
)

add_custom_target(topologies2 ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory . ${SOF_TOPOLOGY_BINARY_DIRECTORY}
)

add_dependencies(topologies2 topologies1)

# generate ABI object. Only need to do this once for all topologies
execute_process(
	COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/get_abi.sh ${SOF_ROOT_SOURCE_DIRECTORY}
	OUTPUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/abi.conf
)

foreach(tplg ${TPLGS})
	set(defines "")
	list(LENGTH tplg length)
	list(GET tplg 0 input)
	list(GET tplg 1 output)

	math(EXPR last_index "${length}-1")

	if (${last_index} EQUAL 2)
		list(GET tplg ${last_index} defines)
	endif()

	# copy ABI and input conf file contents
	configure_file(${CMAKE_CURRENT_BINARY_DIR}/abi.conf ${CMAKE_CURRENT_BINARY_DIR}/${output}_abi.conf)
	file(READ ${CMAKE_CURRENT_SOURCE_DIR}/${input}.conf CONTENTS)
	file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/${output}_abi.conf "${CONTENTS}")

# Note: this does NOT use VERBATIM, see explanation in ../topology/CMakeLists.txt
	add_custom_command(
		OUTPUT ${output}.tplg
		# -p to pre-process Topology2.0 conf file
		COMMAND alsatplg \$\${VERBOSE:+-v 1} -D ${defines} -p -c ${output}_abi.conf -o ${output}.tplg
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${output}_abi.conf
		USES_TERMINAL
	)

	add_custom_target(topology2_${output} DEPENDS ${output}.tplg)
	add_dependencies(topologies2 topology2_${output})
endforeach()

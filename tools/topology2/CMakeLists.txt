# SPDX-License-Identifier: BSD-3-Clause

# Array of "input-file-name;output-file-name;machine quirks"
# machine quirks are defined as follows:
# -d : Set pipelines as dynamic/static. Use -d1 for dynamic and -d0 for static
set(TPLGS
	"sof-cnl-nocodec\;sof-cnl-nocodec\;-d1"
)

add_custom_target(topology2 ALL)

foreach(tplg ${TPLGS})
	list(GET tplg 0 input)
	list(GET tplg 1 output)
	list(GET tplg 2 machine_quirks)

	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${output}_temp.conf
		COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/get_abi.sh ${SOF_ROOT_SOURCE_DIRECTORY}
			${CMAKE_CURRENT_SOURCE_DIR}/${input}.conf > ${CMAKE_CURRENT_BINARY_DIR}/${output}_temp.conf
		USES_TERMINAL
	)

	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${output}.conf
		COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/build_quirks.sh ${machine_quirks}
			-i ${CMAKE_CURRENT_BINARY_DIR}/${output}_temp.conf > ${CMAKE_CURRENT_BINARY_DIR}/${output}.conf
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${output}_temp.conf
		USES_TERMINAL
	)

# Note: this does NOT use VERBATIM, see explanation in ../topology/CMakeLists.txt
	add_custom_command(
		OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${output}.tplg
		COMMAND alsatplg \$\${VERBOSE:+-v 1} -p -c ${CMAKE_CURRENT_BINARY_DIR}/${output}.conf -o ${output}.tplg
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${output}.conf
		USES_TERMINAL
	)

	add_custom_target(topology2_${output} DEPENDS ${output}.tplg)
	add_dependencies(topology2 topology2_${output})
endforeach()

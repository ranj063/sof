add_executable(sof-fuzzer
	main.c
	qemu-bridge.c
	../testbench/topology.c
	platform/byt-host.c
)

target_compile_definitions(sof-fuzzer PRIVATE -DBUILD_FUZZER=1)

find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
target_include_directories(sof-fuzzer PRIVATE ${GLIB_INCLUDE_DIRS})
target_link_libraries(sof-fuzzer PRIVATE ${GLIB_LDFLAGS})

find_library(LIBRT rt)
if(LIBRT)
	target_link_libraries(sof-fuzzer PRIVATE ${LIBRT})
endif()

target_include_directories(sof-fuzzer PRIVATE
	"${SOF_ROOT_SOURCE_DIRECTORY}/src/include"
	"${SOF_ROOT_SOURCE_DIRECTORY}/src/arch/host/include"
	"${SOF_ROOT_SOURCE_DIRECTORY}/tools/testbench/include"
	"${SOF_ROOT_SOURCE_DIRECTORY}"
)

install(TARGETS sof-fuzzer DESTINATION bin)

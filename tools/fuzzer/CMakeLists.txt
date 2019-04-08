add_executable(sof-fuzzer
	main.c
	qemu-bridge.c
	platform/byt-host.c
)

target_link_libraries(sof-fuzzer PRIVATE
	"-lglib-2.0 -lrt"
)

target_include_directories(sof-fuzzer PRIVATE
	"/usr/include/glib-2.0"
	"/usr/lib/x86_64-linux-gnu/glib-2.0/include"
	"${SOF_ROOT_SOURCE_DIRECTORY}/src/include"
	"${SOF_ROOT_SOURCE_DIRECTORY}"
)

install(TARGETS sof-fuzzer DESTINATION bin)

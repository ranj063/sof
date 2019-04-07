add_executable(sof-fuzzer
	main.c
	qemu-bridge.c
	platform/byt-host.c
)

target_link_libraries(sof-fuzzer PRIVATE
	"-lgibc -lrt"
)

install(TARGETS sof-fuzzer DESTINATION bin)

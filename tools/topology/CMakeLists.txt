set(SOF_TOPOLOGY_BINARY_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

add_custom_target(topologies ALL)
add_dependencies(topologies topologies2)

add_subdirectory(topology1)
add_subdirectory(topology2)

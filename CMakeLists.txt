cmake_minimum_required(VERSION 3.14)

set(CMAKE_VERBOSE_MAKEFILE ON)

# Set project name and languge.
project(qwfwd C)

include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
set(CARES_STATIC ON CACHE BOOL "Build static c-ares")
set(CARES_SHARED OFF CACHE BOOL "Build shared c-ares")
set(CARES_BUILD_TOOLS OFF CACHE BOOL "Build c-ares tools")
set(CARES_INSTALL OFF CACHE BOOL "Install c-ares")
FetchContent_Declare(cares
    URL https://github.com/c-ares/c-ares/releases/download/v1.34.9/c-ares-1.34.9.tar.gz
    URL_HASH SHA256=9364b70a12eb59a06830fb488d9357f90100dff0d98b23ea3593a183d43e6f2f
)
FetchContent_MakeAvailable(cares)
configure_file("${cares_SOURCE_DIR}/LICENSE.md" "${CMAKE_CURRENT_BINARY_DIR}/c-ares-LICENSE.md" COPYONLY)

######################################################################################################

# Set where sources located.
set(DIR_SRC "src")

# Add sources
set(SRC_COMMON
	"${DIR_SRC}/ban.c"
    "${DIR_SRC}/ban.c"
    "${DIR_SRC}/clc.c"
    "${DIR_SRC}/cmd.c"
    "${DIR_SRC}/cvar.c"
    "${DIR_SRC}/dns.c"
    "${DIR_SRC}/fs.c"
    "${DIR_SRC}/huff.c"
    "${DIR_SRC}/info.c"
    "${DIR_SRC}/main.c"
    "${DIR_SRC}/msg.c"
    "${DIR_SRC}/net.c"
    "${DIR_SRC}/peer.c"
    "${DIR_SRC}/query.c"
    "${DIR_SRC}/svc.c"
    "${DIR_SRC}/sys.c"
    "${DIR_SRC}/token.c"
    "${DIR_SRC}/whitelist.c"
	)


######################################################################################################

# Set base compiler flags
set(CFLAGS -Wall)
set(LFLAGS)


######################################################################################################

# Set target
add_executable(${PROJECT_NAME} ${SRC_COMMON})
target_compile_features(${PROJECT_NAME} PRIVATE c_std_11)
target_link_libraries(${PROJECT_NAME} PRIVATE c-ares::cares_static)
set_target_properties(${PROJECT_NAME}
	PROPERTIES #PREFIX "" # Strip lib prefix.
	C_VISIBILITY_PRESET hidden # Hide all symbols unless excplicitly marked to export.
	)


######################################################################################################

# Set include directories
target_include_directories(${PROJECT_NAME} PRIVATE)


######################################################################################################

# Check build target, and included sources and libs
if(UNIX)
else()
	target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
	set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc")
endif()


######################################################################################################

# Assign compiler flags
target_compile_options(${PROJECT_NAME} PRIVATE ${CFLAGS})


######################################################################################################

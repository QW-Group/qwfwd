cmake_minimum_required(VERSION 3.4.0)

set(CMAKE_VERBOSE_MAKEFILE ON)

# Set project name and languge.
project(qwfwd C)


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
	)


######################################################################################################

# Set base compiler flags
set(CFLAGS -Wall)
set(LFLAGS)


######################################################################################################

# Set target
add_executable(${PROJECT_NAME} ${SRC_COMMON})
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
	target_link_libraries(${PROJECT_NAME} ws2_32)
	set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc")
endif()


######################################################################################################

# Assign compiler flags
target_compile_options(${PROJECT_NAME} PRIVATE ${CFLAGS})


######################################################################################################

set(CMAKE_INCLUDE_CURRENT_DIR ON)

include(FindPkgConfig)
pkg_check_modules(LIBSNIFFDET REQUIRED libsniffdet)
include_directories(${LIBSNIFFDET_INCLUDE_DIRS})
add_definitions(${LIBSNIFFDET_CFLAGS})

MESSAGE(STATUS "libs: " "${LIBSNIFFDET_LIBRARIES}")
MESSAGE("include: " "${LIBSNIFFDET_INCLUDE_DIRS}")

set(sniffdet_SOURCES
    sniffdet.c
    sniffdet.h
    log.c
    log.h
    config_file.c
    util.c
    util.h
)

#add_subdirectory(lib)
#include_directories(lib)
#add_subdirectory(plugins)

add_executable(sniffdet ${sniffdet_SOURCES})

# won't work because sniffdet (a reserved name for being a target)
# is present in ${LIBSNIFFDET_LIBRARIES}
target_link_libraries(sniffdet ${LIBSNIFFDET_LIBRARIES})

install(TARGETS sniffdet DESTINATION bin)

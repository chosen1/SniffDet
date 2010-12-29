set(BUILD_SHARED_LIBS ON)

add_library(libsniffdet
    arptest.c
    dnstest.c
    helpers.c
    icmptest.c
    init.c
    latencytest.c
    ping.c
    libsniffdet.h
)

install(FILES libsniffdet.h DESTINATION include)
install(TARGETS libsniffdet LIBRARY DESTINATION lib)

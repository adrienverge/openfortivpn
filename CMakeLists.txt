cmake_minimum_required(VERSION 3.15)

project(openfortivpn C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Version from configure.ac
set(PROJECT_VERSION "1.24.1")

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Common sources (platform-independent)
set(COMMON_SOURCES
    src/config.c
    src/event.c
    src/hdlc.c
    src/http.c
    src/xml.c
)

# Platform-specific sources and libraries
if(WIN32)
    set(PLATFORM_SOURCES
        src/ppp.c
        src/io_win.c
        src/tunnel_win.c
        src/ipv4_win.c
        src/userinput_win.c
        src/log_win.c
        src/http_server_win.c
    )
    set(PLATFORM_LIBS ws2_32 iphlpapi)

    # Bundled getopt for MSVC (MinGW has its own)
    if(MSVC)
        list(APPEND PLATFORM_SOURCES lib/getopt/getopt.c)
        set(GETOPT_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/lib/getopt")
    endif()

    # Platform definitions
    add_definitions(
        -D_WIN32_WINNT=0x0A00  # Windows 10+
        -DWIN32_LEAN_AND_MEAN
        -D_CRT_SECURE_NO_WARNINGS
    )
else()
    set(PLATFORM_SOURCES
        src/io.c
        src/tunnel.c
        src/ipv4.c
        src/userinput.c
        src/log.c
        src/http_server.c
    )
    set(PLATFORM_LIBS pthread)

    # Check for libutil (forkpty)
    include(CheckLibraryExists)
    check_library_exists(util forkpty "" HAVE_LIBUTIL)
    if(HAVE_LIBUTIL)
        list(APPEND PLATFORM_LIBS util)
    endif()

    # Platform detection (mirroring configure.ac)
    include(CheckIncludeFile)
    include(CheckSymbolExists)
    include(CheckStructHasMember)

    check_include_file(pty.h HAVE_PTY_H)
    check_include_file(util.h HAVE_UTIL_H)
    check_include_file(libutil.h HAVE_LIBUTIL_H)
    check_include_file(mach/mach.h HAVE_MACH_MACH_H)
    check_include_file(semaphore.h HAVE_SEMAPHORE_H)
    check_include_file(termios.h HAVE_STRUCT_TERMIOS)

    # Check for /proc/net/route (Linux)
    if(EXISTS "/proc/net/route")
        set(HAVE_PROC_NET_ROUTE 1)
    else()
        set(HAVE_PROC_NET_ROUTE 0)
    endif()

    # Check for rtentry with rt_dst
    include(CheckCSourceCompiles)
    check_c_source_compiles("
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <net/route.h>
        int main() { struct rtentry r; r.rt_dst.sa_family = 0; return 0; }
    " HAVE_RT_ENTRY_WITH_RT_DST)
    if(NOT HAVE_RT_ENTRY_WITH_RT_DST)
        set(HAVE_RT_ENTRY_WITH_RT_DST 0)
    endif()

    # Check for SO_BINDTODEVICE
    check_c_source_compiles("
        #include <sys/socket.h>
        int main() { int x = SO_BINDTODEVICE; return x; }
    " HAVE_SO_BINDTODEVICE)

    # Check for pppd or ppp
    find_program(PPPD_PATH pppd PATHS /usr/sbin /sbin)
    find_program(PPP_PATH_BIN ppp PATHS /usr/sbin /sbin)

    if(PPPD_PATH)
        set(HAVE_USR_SBIN_PPPD 1)
        set(HAVE_USR_SBIN_PPP 0)
        set(PPP_PATH "${PPPD_PATH}")
    elseif(PPP_PATH_BIN)
        set(HAVE_USR_SBIN_PPPD 0)
        set(HAVE_USR_SBIN_PPP 1)
        set(PPP_PATH "${PPP_PATH_BIN}")
    else()
        set(HAVE_USR_SBIN_PPPD 1)
        set(HAVE_USR_SBIN_PPP 0)
        set(PPP_PATH "/usr/sbin/pppd")
    endif()

    # Check for resolvconf
    find_program(RESOLVCONF_PATH resolvconf PATHS /sbin /usr/sbin)
    if(RESOLVCONF_PATH)
        set(HAVE_RESOLVCONF 1)
        set(USE_RESOLVCONF 1)
    else()
        set(HAVE_RESOLVCONF 0)
        set(USE_RESOLVCONF 0)
        set(RESOLVCONF_PATH "")
    endif()

    # Check for netstat
    find_program(NETSTAT_PATH netstat PATHS /usr/bin /bin /usr/sbin /sbin)
    if(NOT NETSTAT_PATH)
        set(NETSTAT_PATH "/usr/bin/netstat")
    endif()

    # Check for systemd
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(LIBSYSTEMD QUIET libsystemd)
    endif()
    if(LIBSYSTEMD_FOUND)
        set(HAVE_SYSTEMD 1)
        list(APPEND PLATFORM_LIBS ${LIBSYSTEMD_LIBRARIES})
    else()
        set(HAVE_SYSTEMD 0)
    endif()

    # Check for vdprintf
    include(CheckFunctionExists)
    check_function_exists(vdprintf HAVE_VDPRINTF)

    set(LEGACY_PPPD 0 CACHE BOOL "Support pppd < 2.5.0")
    set(SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc"
        CACHE PATH "System configuration directory")
endif()

# Main executable
add_executable(openfortivpn
    src/main.c
    ${COMMON_SOURCES}
    ${PLATFORM_SOURCES}
)

target_link_libraries(openfortivpn
    OpenSSL::SSL
    OpenSSL::Crypto
    ${PLATFORM_LIBS}
)

target_include_directories(openfortivpn PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}  # for generated config
)

if(DEFINED GETOPT_INCLUDE_DIR)
    target_include_directories(openfortivpn PRIVATE ${GETOPT_INCLUDE_DIR})
endif()

# Common compile definitions
target_compile_definitions(openfortivpn PRIVATE
    VERSION="${PROJECT_VERSION}"
    PACKAGE_VERSION="${PROJECT_VERSION}"
)

# Platform-specific compile definitions
if(WIN32)
    target_compile_definitions(openfortivpn PRIVATE
        HAVE_USR_SBIN_PPPD=0
        HAVE_USR_SBIN_PPP=0
        HAVE_PROC_NET_ROUTE=0
        HAVE_RT_ENTRY_WITH_RT_DST=0
        HAVE_RESOLVCONF=0
        USE_RESOLVCONF=0
        HAVE_SYSTEMD=0
        HAVE_PTY_H=0
        HAVE_UTIL_H=0
        HAVE_LIBUTIL_H=0
        HAVE_MACH_MACH_H=0
        HAVE_STRUCT_TERMIOS=0
        HAVE_SO_BINDTODEVICE=0
        LEGACY_PPPD=0
        SYSCONFDIR="C:/ProgramData/openfortivpn"
        PPP_PATH=""
        NETSTAT_PATH=""
        RESOLVCONF_PATH=""
        REVISION="${PROJECT_VERSION}"
        _WIN32_WINNT=0x0A00
    )
else()
    target_compile_definitions(openfortivpn PRIVATE
        HAVE_USR_SBIN_PPPD=${HAVE_USR_SBIN_PPPD}
        HAVE_USR_SBIN_PPP=${HAVE_USR_SBIN_PPP}
        HAVE_PROC_NET_ROUTE=${HAVE_PROC_NET_ROUTE}
        HAVE_RT_ENTRY_WITH_RT_DST=$<BOOL:${HAVE_RT_ENTRY_WITH_RT_DST}>
        HAVE_RESOLVCONF=${HAVE_RESOLVCONF}
        USE_RESOLVCONF=${USE_RESOLVCONF}
        HAVE_SYSTEMD=${HAVE_SYSTEMD}
        HAVE_SO_BINDTODEVICE=$<BOOL:${HAVE_SO_BINDTODEVICE}>
        LEGACY_PPPD=$<BOOL:${LEGACY_PPPD}>
        SYSCONFDIR="${SYSCONFDIR}"
        PPP_PATH="${PPP_PATH}"
        NETSTAT_PATH="${NETSTAT_PATH}"
        RESOLVCONF_PATH="${RESOLVCONF_PATH}"
        REVISION="${PROJECT_VERSION}"
    )

    if(HAVE_PTY_H)
        target_compile_definitions(openfortivpn PRIVATE HAVE_PTY_H=1)
    endif()
    if(HAVE_UTIL_H)
        target_compile_definitions(openfortivpn PRIVATE HAVE_UTIL_H=1)
    endif()
    if(HAVE_LIBUTIL_H)
        target_compile_definitions(openfortivpn PRIVATE HAVE_LIBUTIL_H=1)
    endif()
    if(HAVE_MACH_MACH_H)
        target_compile_definitions(openfortivpn PRIVATE HAVE_MACH_MACH_H=1)
    endif()
    if(HAVE_STRUCT_TERMIOS)
        target_compile_definitions(openfortivpn PRIVATE HAVE_STRUCT_TERMIOS=1)
    endif()
    if(HAVE_VDPRINTF)
        target_compile_definitions(openfortivpn PRIVATE HAVE_VDPRINTF=1)
    endif()
endif()

# PPP unit tests
if(BUILD_TESTING)
    enable_testing()
    add_executable(test_ppp
        tests/test_ppp.c
        src/ppp.c
        src/hdlc.c
    )
    target_include_directories(test_ppp PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_definitions(test_ppp PRIVATE
        HAVE_USR_SBIN_PPPD=0
        HAVE_USR_SBIN_PPP=0
    )
    if(WIN32)
        target_compile_definitions(test_ppp PRIVATE
            _WIN32_WINNT=0x0A00
            WIN32_LEAN_AND_MEAN
        )
    endif()
    add_test(NAME ppp_state_machine COMMAND test_ppp)
endif()

# Install target
include(GNUInstallDirs)
install(TARGETS openfortivpn RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

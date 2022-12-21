#
# Libevent CMake project
#
# Based on initial work by:
#    Alexey Ozeritsky
#
# Additional changes:
#   Brodie Thiesfield
#   Joakim Soderberg
#   Trond Norbye
#   Sergei Nikulov
#
#   Build example:
#
#       cd libevent
#       md build
#       cd build
#       cmake -G "Visual Studio 10" ..
#       start libevent.sln
#

cmake_minimum_required(VERSION 3.1.2 FATAL_ERROR)

if (POLICY CMP0054)
    cmake_policy(SET CMP0054 NEW)
endif ()
if (POLICY CMP0074)
    cmake_policy(SET CMP0074 NEW)
endif ()
if (POLICY CMP0075)
    cmake_policy(SET CMP0075 NEW)
endif ()

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release
            CACHE STRING "Set build type to Debug or Release (default Release)" FORCE)
endif ()
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

set(CMAKE_DEBUG_POSTFIX d CACHE STRING "Debug library postfix" FORCE)

set(EVENT__LIBRARY_TYPE DEFAULT CACHE STRING
        "Set library type to SHARED/STATIC/BOTH (default SHARED for MSVC, otherwise BOTH)")

project(libevent C)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")
string(REGEX MATCH "SunOS" SOLARIS "${CMAKE_SYSTEM_NAME}")

set(libevent_source_dir "${test_quic_SOURCE_DIR}/third_party/libevent")
set(libevent_binary_dir "${test_quic_BINARY_DIR}/third_party/libevent")

include(CheckTypeSize)
include(CheckFileOffsetBits)
include(Macros)
include(CheckVariableExists)
include(CheckSymbolExists)
include(CheckStructHasMember)
include(CheckCSourceCompiles)
include(CheckPrototypeDefinition)
include(CheckFunctionKeywords)
include(CheckConstExists)

include(AddCompilerFlags)
include(VersionViaGit)

event_fuzzy_version_from_git()

set(EVENT_VERSION_MAJOR ${EVENT_GIT___VERSION_MAJOR})
set(EVENT_VERSION_MINOR ${EVENT_GIT___VERSION_MINOR})
set(EVENT_VERSION_PATCH ${EVENT_GIT___VERSION_PATCH})
set(EVENT_VERSION_STAGE ${EVENT_GIT___VERSION_STAGE})


set(EVENT_ABI_MAJOR ${EVENT_VERSION_MAJOR})
set(EVENT_ABI_MINOR ${EVENT_VERSION_MINOR})
set(EVENT_ABI_PATCH ${EVENT_VERSION_PATCH})

set(EVENT_ABI_LIBVERSION
        "${EVENT_ABI_MAJOR}.${EVENT_ABI_MINOR}.${EVENT_ABI_PATCH}")

set(EVENT_PACKAGE_VERSION
        "${EVENT_VERSION_MAJOR}.${EVENT_VERSION_MINOR}.${EVENT_VERSION_PATCH}")

# equals to VERSION_INFO in Makefile.am
set(EVENT_ABI_LIBVERSION_CURRENT 1)
set(EVENT_ABI_LIBVERSION_REVISION 0)
set(EVENT_ABI_LIBVERSION_AGE 0)

# equals to RELEASE in Makefile.am
set(EVENT_PACKAGE_RELEASE 2.2)

set(EVENT_NUMERIC_VERSION 0x02020001)

# only a subset of names can be used, defaults to "beta"
set(EVENT_STAGE_NAME ${EVENT_VERSION_STAGE})

# a list that defines what can set for EVENT_STAGE_VERSION
set(EVENT__ALLOWED_STAGE_NAMES
        rc
        beta
        alpha
        alpha-dev
        release
        stable
        )
list(
        FIND EVENT__ALLOWED_STAGE_NAMES
        "${EVENT_STAGE_NAME}"
        EVENT__STAGE_RET
)
if (EVENT__STAGE_RET EQUAL -1)
    message(WARNING
            "stage ${EVENT_STAGE_NAME} is not allowed, reset to beta")
    set(EVENT_STAGE_NAME beta)
endif ()

set(EVENT_VERSION
        "${EVENT_VERSION_MAJOR}.${EVENT_VERSION_MINOR}.${EVENT_VERSION_PATCH}-${EVENT_STAGE_NAME}")

option(EVENT__DISABLE_DEBUG_MODE
        "Define if libevent should build without support for a debug mode" OFF)

option(EVENT__ENABLE_VERBOSE_DEBUG
        "Enables verbose debugging" OFF)

option(EVENT__DISABLE_MM_REPLACEMENT
        "Define if libevent should not allow replacing the mm functions" OFF)

option(EVENT__DISABLE_THREAD_SUPPORT
        "Define if libevent should not be compiled with thread support" OFF)

option(EVENT__DISABLE_OPENSSL
        "Define if libevent should build without support for OpenSSL encryption" OFF)

option(EVENT__DISABLE_MBEDTLS
        "Define if libevent should build without support for mbed TLS encryption" ON)

option(EVENT__DISABLE_BENCHMARK
        "Defines if libevent should build without the benchmark executables" OFF)

option(EVENT__DISABLE_TESTS
        "If tests should be compiled or not" OFF)

option(EVENT__DISABLE_REGRESS
        "Disable the regress tests" OFF)

option(EVENT__DISABLE_SAMPLES
        "Disable sample files" OFF)

option(EVENT__DISABLE_CLOCK_GETTIME
        "Do not use clock_gettime even if it is available" OFF)

option(EVENT__FORCE_KQUEUE_CHECK
        "When crosscompiling forces running a test program that verifies that Kqueue works with pipes. Note that this requires you to manually run the test program on the cross compilation target to verify that it works. See cmake documentation for try_run for more details" OFF)

# TODO: Add --disable-largefile     omit support for large files
option(EVENT__COVERAGE
        "Enable running gcov to get a test coverage report (only works with GCC/CLang). Make sure to enable -DCMAKE_BUILD_TYPE=Debug as well." OFF)

# Put the libaries and binaries that get built into directories at the
# top of the build tree rather than in hard-to-find leaf directories.
#
# But only if this variables are not defined yet
# (i.e. libevent is used via add_subdirectory())
if (NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
endif ()
if (NOT DEFINED CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif ()
if (NOT DEFINED CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif ()

# The RPATH to be used when installing, but only if it's not a system directory
#
# Refs: https://gitlab.kitware.com/cmake/community/-/wikis/doc/cmake/RPATH-handling
macro(Configure_RPATH)
    # NOTE: that CMAKE_INSTALL_PREFIX not always normalized correctly, i.e.:
    # - "///" -> "/"
    # - "/////usr///" -> "//usr"
    # So it should be normalized again.

    get_filename_component(CMAKE_INSTALL_PREFIX_NORMALIZED "${CMAKE_INSTALL_PREFIX}" REALPATH)
    list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX_NORMALIZED}/lib" isSystemDir)

    if ("${isSystemDir}" STREQUAL "-1")
        set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX_NORMALIZED}/lib")
    endif ()
endmacro()
Configure_RPATH()

if (EVENT__ENABLE_VERBOSE_DEBUG)
    add_definitions(-DUSE_DEBUG=1)
endif ()

# make it colorful under ninja-build
if ("${CMAKE_GENERATOR}" STREQUAL "Ninja")
    add_compiler_flags(-fdiagnostics-color=always)
endif ()

# Setup compiler flags for coverage.
if (EVENT__COVERAGE)
    if (NOT "${CMAKE_BUILD_TYPE_LOWER}" STREQUAL "debug")
        message(FATAL_ERROR "Coverage requires -DCMAKE_BUILD_TYPE=Debug")
    endif ()

    message(STATUS "Setting coverage compiler flags")

    list(APPEND CMAKE_REQUIRED_LIBRARIES "--coverage")
    add_compiler_flags(-g -O0 --coverage)
    list(REMOVE_ITEM CMAKE_REQUIRED_LIBRARIES "--coverage")
endif ()

set(GNUC 0)
set(CLANG 0)
set(MSVC 0)
if (("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang") OR
("${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang"))
    set(CLANG 1)
endif ()
if (("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU") OR (${CLANG}))
    set(GNUC 1)
endif ()
if (("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC") OR ("${CMAKE_C_SIMULATE_ID}" STREQUAL "MSVC"))
    set(MSVC 1)
endif ()

# Detect library type
set(EVENT_LIBRARY_TYPE)
if ("${EVENT__LIBRARY_TYPE}" STREQUAL "DEFAULT")
    if (${MSVC})
        set(EVENT_LIBRARY_TYPE SHARED)
    else ()
        set(EVENT_LIBRARY_TYPE BOTH)
    endif ()
else ()
    string(TOUPPER "${EVENT__LIBRARY_TYPE}" EVENT_LIBRARY_TYPE)
endif ()
if ((${MSVC}) AND ("${EVENT_LIBRARY_TYPE}" STREQUAL "BOTH"))
    message(WARNING
            "Building SHARED and STATIC is not supported for MSVC "
            "(due to conflicts in library name"
            " between STATIC library and IMPORTED library for SHARED libraries)")
endif ()
set(EVENT_LIBRARY_STATIC OFF)
set(EVENT_LIBRARY_SHARED OFF)
if ("${EVENT_LIBRARY_TYPE}" STREQUAL "BOTH")
    set(EVENT_LIBRARY_STATIC ON)
    set(EVENT_LIBRARY_SHARED ON)
elseif ("${EVENT_LIBRARY_TYPE}" STREQUAL "STATIC")
    set(EVENT_LIBRARY_STATIC ON)
elseif ("${EVENT_LIBRARY_TYPE}" STREQUAL "SHARED")
    set(EVENT_LIBRARY_SHARED ON)
else ()
    message(FATAL_ERROR "${EVENT_LIBRARY_TYPE} is not supported")
endif ()

# brew support
if (APPLE)
    find_program(BREW brew)
endif ()

if (${MSVC})
    set(msvc_static_runtime OFF)
    if ("${EVENT_LIBRARY_TYPE}" STREQUAL "STATIC")
        set(msvc_static_runtime ON)
    endif ()

    # For more info:
    # - https://docs.microsoft.com/en-us/cpp/build/reference/md-mt-ld-use-run-time-library?view=vs-2017
    # - https://gitlab.kitware.com/cmake/community/wikis/FAQ#how-can-i-build-my-msvc-application-with-a-static-runtime
    option(EVENT__MSVC_STATIC_RUNTIME
            "Link static runtime libraries"
            ${msvc_static_runtime})

    if (EVENT__MSVC_STATIC_RUNTIME)
        foreach (flag_var
                CMAKE_C_FLAGS_DEBUG
                CMAKE_C_FLAGS_RELEASE
                CMAKE_C_FLAGS_MINSIZEREL
                CMAKE_C_FLAGS_RELWITHDEBINFO
                )
            if (${flag_var} MATCHES "/MD")
                string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
            endif ()
        endforeach ()
    endif ()
endif ()

# GNUC specific options.
if (${GNUC})
    option(EVENT__DISABLE_GCC_WARNINGS "Disable verbose warnings with GCC" OFF)
    option(EVENT__ENABLE_GCC_HARDENING "Enable compiler security checks" OFF)
    option(EVENT__ENABLE_GCC_FUNCTION_SECTIONS "Enable gcc function sections" OFF)
    option(EVENT__ENABLE_GCC_WARNINGS "Make all GCC warnings into errors" OFF)

    set(GCC_V ${CMAKE_C_COMPILER_VERSION})

    list(APPEND __FLAGS
            -Wall -Wextra -Wno-unused-parameter -Wstrict-aliasing -Wstrict-prototypes
            -Wundef

            -fno-strict-aliasing # gcc 2.9.5+
            -Wmissing-prototypes

            # gcc 4
            -Winit-self
            -Wmissing-field-initializers
            -Wdeclaration-after-statement

            # gcc 4.2
            -Waddress
            -Wnormalized=id
            -Woverride-init

            # gcc 4.5
            -Wlogical-op

            -Wwrite-strings

            # Disable unused-function warnings. These trigger for minheap-internal.h.
            -Wno-unused-function
            )

    if (${CLANG})
        list(APPEND __FLAGS
                # we use this hack in tests
                -Wno-void-pointer-to-enum-cast)
    endif ()

    if (EVENT__DISABLE_GCC_WARNINGS)
        list(APPEND __FLAGS -w)
    endif ()

    if (EVENT__ENABLE_GCC_HARDENING)
        list(APPEND __FLAGS
                -fstack-protector-all
                -fwrapv
                -fPIE
                -Wstack-protector
                "--param ssp-buffer-size=1")

        add_definitions(-D_FORTIFY_SOURCE=2)
    endif ()

    if (EVENT__ENABLE_GCC_FUNCTION_SECTIONS)
        list(APPEND __FLAGS -ffunction-sections)
        # TODO: Add --gc-sections support. We need some checks for NetBSD to ensure this works.
    endif ()

    if (EVENT__ENABLE_GCC_WARNINGS)
        list(APPEND __FLAGS -Werror)
    endif ()

    add_compiler_flags(${__FLAGS})
endif ()

if (APPLE)
    # Clang on macOS emits warnings for each directory specified which isn't used
    add_compiler_flags(
            -Qunused-arguments
    )
endif ()

if (MINGW OR CYGWIN)
    set(WIN32 TRUE)
endif ()

# Winsock.
if (WIN32)
    list(APPEND CMAKE_REQUIRED_LIBRARIES
            ws2_32
            shell32
            advapi32
            bcrypt
            )
    set(CMAKE_REQUIRED_DEFINITIONS -FIwinsock2.h -FIws2tcpip.h -D_WIN32_WINNT=0x0600)
endif ()
if (SOLARIS)
    list(APPEND CMAKE_REQUIRED_LIBRARIES
            socket
            nsl
            )
endif ()

# Check if _GNU_SOURCE is available.
if (NOT DEFINED _GNU_SOURCE)
    CHECK_SYMBOL_EXISTS(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)

    if (NOT _GNU_SOURCE)
        unset(_GNU_SOURCE CACHE)
        CHECK_SYMBOL_EXISTS(_GNU_SOURCE "features.h" _GNU_SOURCE)
    endif ()

    if (ANDROID)
        set(_GNU_SOURCE TRUE)
    endif ()
endif ()

if (_GNU_SOURCE)
    add_definitions(-D_GNU_SOURCE=1)
    set(CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
endif ()

# Check if header files exist
list(APPEND FILES_TO_CHECK
        fcntl.h
        inttypes.h
        memory.h
        signal.h
        stdarg.h
        stddef.h
        stdint.h
        stdlib.h
        string.h
        errno.h
        unistd.h
        time.h
        sys/types.h
        sys/stat.h
        sys/time.h
        sys/param.h
        )
if (WIN32)
    list(APPEND FILES_TO_CHECK
            io.h
            winsock2.h
            ws2tcpip.h
            afunix.h
            )
else ()
    list(APPEND FILES_TO_CHECK
            netdb.h
            dlfcn.h
            arpa/inet.h
            poll.h
            port.h
            sys/socket.h
            sys/random.h
            sys/un.h
            sys/devpoll.h
            sys/epoll.h
            sys/eventfd.h
            sys/event.h
            sys/ioctl.h
            sys/mman.h
            sys/queue.h
            sys/select.h
            sys/sendfile.h
            sys/uio.h
            sys/wait.h
            sys/resource.h
            sys/timerfd.h
            netinet/in.h
            netinet/in6.h
            netinet/tcp.h
            ifaddrs.h
            )
endif ()

if (NOT "${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Linux")
    list(APPEND FILES_TO_CHECK sys/sysctl.h)
endif ()

if (APPLE)
    list(APPEND FILES_TO_CHECK
            mach/mach_time.h
            mach/mach.h
            )
endif ()

if (NOT EVENT__DISABLE_THREAD_SUPPORT AND NOT WIN32)
    list(APPEND FILES_TO_CHECK pthread.h)
    # (Only `CHECK_TYPE_SIZE()' will use `CMAKE_EXTRA_INCLUDE_FILES')
    list(APPEND CMAKE_EXTRA_INCLUDE_FILES pthread.h)
endif ()

# Fills EVENT_INCLUDES
foreach (FILE ${FILES_TO_CHECK})
    CHECK_INCLUDE_FILE_CONCAT(${FILE} "EVENT")
endforeach ()
unset(FILES_TO_CHECK)

# Check if functions exist
list(APPEND SYMBOLS_TO_CHECK
        getaddrinfo
        getnameinfo
        getprotobynumber
        getservbyname
        gethostbyname
        inet_ntop
        inet_pton
        gettimeofday
        signal
        strtoll
        strlcpy
        strsep
        strtok_r
        timerclear
        timercmp
        timerisset
        timeradd
        nanosleep
        putenv
        umask
        )
if (NOT EVENT__DISABLE_CLOCK_GETTIME)
    list(APPEND SYMBOLS_TO_CHECK clock_gettime)
endif ()

if (WIN32)
    list(APPEND SYMBOLS_TO_CHECK
            _gmtime64_s
            _gmtime64
            )
else ()
    list(APPEND SYMBOLS_TO_CHECK
            getifaddrs
            select
            epoll_create
            epoll_create1
            epoll_ctl
            eventfd
            poll
            port_create
            kqueue
            fcntl
            mmap
            pipe
            pipe2
            sendfile
            sigaction
            strsignal
            sysctl
            accept4
            arc4random
            arc4random_buf
            arc4random_addrandom
            getrandom
            getegid
            geteuid
            issetugid
            usleep
            timerfd_create
            setenv
            unsetenv
            setrlimit
            gethostbyname_r
            mmap64
            )
    if (APPLE)
        list(APPEND SYMBOLS_TO_CHECK mach_absolute_time)
    endif ()
endif ()

if (NOT EVENT__DISABLE_THREAD_SUPPORT)
    if (WIN32)
        list(APPEND SRC_CORE evthread_win32.c)
    else ()
        find_package(Threads REQUIRED)
        if (NOT CMAKE_USE_PTHREADS_INIT)
            message(FATAL_ERROR
                    "Failed to find Pthreads, set EVENT__DISABLE_THREAD_SUPPORT to disable")
        endif ()

        set(EVENT__HAVE_PTHREADS 1)
        list(APPEND LIB_APPS ${CMAKE_THREAD_LIBS_INIT})

        # for CHECK_SYMBOLS_EXIST()
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})

        CHECK_TYPE_SIZE(pthread_t EVENT__SIZEOF_PTHREAD_T)
        list(APPEND SYMBOLS_TO_CHECK pthread_mutexattr_setprotocol)
    endif ()
endif ()

list(APPEND CMAKE_EXTRA_INCLUDE_FILES ${EVENT_INCLUDES} stdio.h)
CHECK_SYMBOLS_EXIST("${SYMBOLS_TO_CHECK}" "${CMAKE_EXTRA_INCLUDE_FILES}" "EVENT")
unset(SYMBOLS_TO_CHECK)
set(EVENT__HAVE_EPOLL ${EVENT__HAVE_EPOLL_CREATE})
if (WIN32 AND NOT CYGWIN)
    set(EVENT__HAVE_WEPOLL 1)
endif ()

# Get the gethostbyname_r prototype.
if (EVENT__HAVE_GETHOSTBYNAME_R)
    CHECK_PROTOTYPE_DEFINITION(gethostbyname_r
            "int gethostbyname_r(const char *name, struct hostent *hp, struct hostent_data *hdata)"
            "0"
            "netdb.h"
            EVENT__HAVE_GETHOSTBYNAME_R_3_ARG)

    CHECK_PROTOTYPE_DEFINITION(gethostbyname_r
            "struct hostent *gethostbyname_r(const char *name, struct hostent *hp, char *buf, size_t buflen, int *herr)"
            "NULL"
            "netdb.h"
            EVENT__HAVE_GETHOSTBYNAME_R_5_ARG)

    CHECK_PROTOTYPE_DEFINITION(gethostbyname_r
            "int gethostbyname_r(const char *name, struct hostent *hp, char *buf, size_t buflen, struct hostent **result, int *herr)"
            "0"
            "netdb.h"
            EVENT__HAVE_GETHOSTBYNAME_R_6_ARG)
endif ()

if (HAVE_PORT_H AND HAVE_PORT_CREATE)
    set(EVENT__HAVE_EVENT_PORTS 1)
endif ()

CHECK_TYPE_SIZE("struct sockaddr_un" EVENT__HAVE_STRUCT_SOCKADDR_UN)
CHECK_TYPE_SIZE("uint8_t" EVENT__HAVE_UINT8_T)
CHECK_TYPE_SIZE("uint16_t" EVENT__HAVE_UINT16_T)
CHECK_TYPE_SIZE("uint32_t" EVENT__HAVE_UINT32_T)
CHECK_TYPE_SIZE("uint64_t" EVENT__HAVE_UINT64_T)
CHECK_TYPE_SIZE("short" EVENT__SIZEOF_SHORT BUILTIN_TYPES_ONLY)
CHECK_TYPE_SIZE("int" EVENT__SIZEOF_INT BUILTIN_TYPES_ONLY)
CHECK_TYPE_SIZE("unsigned" EVENT__SIZEOF_UNSIGNED BUILTIN_TYPES_ONLY)
CHECK_TYPE_SIZE("unsigned int" EVENT__SIZEOF_UNSIGNED_INT BUILTIN_TYPES_ONLY)
CHECK_TYPE_SIZE("long" EVENT__SIZEOF_LONG BUILTIN_TYPES_ONLY)
CHECK_TYPE_SIZE("long long" EVENT__SIZEOF_LONG_LONG BUILTIN_TYPES_ONLY)

if (WIN32)
    # These aren't available until Windows Vista.
    # But you can still link them. They just won't be found when running the exe.
    set(EVENT__HAVE_INET_NTOP 0)
    set(EVENT__HAVE_INET_PTON 0)
endif ()

# Check for different inline keyword versions.
check_function_keywords("inline" "__inline" "__inline__")

if (HAVE_INLINE)
    set(EVENT__inline inline)
elseif (HAVE___INLINE)
    set(EVENT__inline __inline)
elseif (HAVE___INLINE__)
    set(EVENT__inline __inline__)
else ()
    set(EVENT__inline)
endif ()

# __func__/__FUNCTION__ is not a macros in general
CHECK_SYMBOL_EXISTS("__func__" "" EVENT__HAVE___func__)
CHECK_SYMBOL_EXISTS("__FUNCTION__" "" EVENT__HAVE___FUNCTION__)

CHECK_SYMBOL_EXISTS(TAILQ_FOREACH sys/queue.h EVENT__HAVE_TAILQFOREACH)
CHECK_CONST_EXISTS(CTL_KERN sys/sysctl.h EVENT__HAVE_DECL_CTL_KERN)
CHECK_CONST_EXISTS(KERN_ARND sys/sysctl.h EVENT__HAVE_DECL_KERN_ARND)
CHECK_SYMBOL_EXISTS(F_SETFD fcntl.h EVENT__HAVE_SETFD)

CHECK_TYPE_SIZE(fd_mask EVENT__HAVE_FD_MASK)

CHECK_TYPE_SIZE(size_t EVENT__SIZEOF_SIZE_T)
if (NOT EVENT__SIZEOF_SIZE_T)
    set(EVENT__size_t "unsigned")
    set(EVENT__SIZEOF_SIZE_T ${EVENT__SIZEOF_UNSIGNED})
else ()
    set(EVENT__size_t size_t)
endif ()

CHECK_TYPE_SIZE("off_t" EVENT__SIZEOF_OFF_T LANGUAGE C)


# XXX we should functionalize these size and type sets. --elley

# Winssck.
if (_MSC_VER)
    list(APPEND CMAKE_EXTRA_INCLUDE_FILES BaseTsd.h)
endif ()
CHECK_TYPE_SIZE("ssize_t" EVENT__SIZEOF_SSIZE_T_LOWER LANGUAGE C)
CHECK_TYPE_SIZE("SSIZE_T" EVENT__SIZEOF_SSIZE_T_UPPER LANGUAGE C)

if (EVENT__SIZEOF_SSIZE_T_LOWER)
    set(EVENT__ssize_t "ssize_t")
    set(EVENT__SIZEOF_SSIZE_T ${EVENT__SIZEOF_SSIZE_T_LOWER})
elseif (EVENT__SIZEOF_SSIZE_T_UPPER)
    set(EVENT__ssize_t "SSIZE_T")
    set(EVENT__SIZEOF_SSIZE_T ${EVENT__SIZEOF_SSIZE_T_UPPER})
else ()
    set(EVENT__ssize_t "int")
    set(EVENT__SIZEOF_SSIZE_T ${EVENT__SIZEOF_INT})
endif ()

CHECK_TYPE_SIZE(socklen_t EVENT__SIZEOF_SOCKLEN_T)
if (NOT EVENT__SIZEOF_SOCKLEN_T)
    set(EVENT__socklen_t "unsigned int")
    set(EVENT__SIZEOF_SOCKLEN_T ${EVENT__SIZEOF_UNSIGNED_INT})
else ()
    set(EVENT__socklen_t "socklen_t")
endif ()

CHECK_TYPE_SIZE(pid_t EVENT__SIZEOF_PID_T)
if (NOT EVENT__SIZEOF_PID_T)
    set(EVENT__SIZEOF_PID_T ${EVENT__SIZEOF_INT})
else ()
    set(EVENT__SIZEOF_PID_T EVENT__SIZEOF_PID_T)
endif ()

if (EVENT__HAVE_CLOCK_GETTIME)
    set(EVENT__DNS_USE_CPU_CLOCK_FOR_ID 1)
endif ()

# we're just getting lazy now.
CHECK_TYPE_SIZE("uintptr_t" EVENT__HAVE_UINTPTR_T)
CHECK_TYPE_SIZE("void *" EVENT__SIZEOF_VOID_P)
CHECK_TYPE_SIZE("time_t" EVENT__SIZEOF_TIME_T)

# Tests file offset bits.
# TODO: Add AIX test for if -D_LARGE_FILES is needed.

# XXX: Why is this here? we don't even use it. Well, we don't even use it
#      on top of that, why is it set in the config.h?! IT_MAKES_NO_SENSE
#      I'm commenting it out for now.
#      - ellzey

#CHECK_FILE_OFFSET_BITS()

# Verify kqueue works with pipes.
if (EVENT__HAVE_KQUEUE)
    if ((CMAKE_CROSSCOMPILING OR APPLE) AND NOT EVENT__FORCE_KQUEUE_CHECK)
        message(WARNING "Cannot check if kqueue works with pipes when crosscompiling, use EVENT__FORCE_KQUEUE_CHECK to be sure (this requires manually running a test program on the cross compilation target)")
        set(EVENT__HAVE_WORKING_KQUEUE 1)
    else ()
        message(STATUS "Checking if kqueue works with pipes...")
        include(CheckWorkingKqueue)
    endif ()
endif ()

if (EVENT__HAVE_NETDB_H)
    list(APPEND CMAKE_EXTRA_INCLUDE_FILES netdb.h)
    CHECK_TYPE_SIZE("struct addrinfo" EVENT__HAVE_STRUCT_ADDRINFO)
elseif (WIN32)
    list(APPEND CMAKE_EXTRA_INCLUDE_FILES ws2tcpip.h)
    CHECK_TYPE_SIZE("struct addrinfo" EVENT__HAVE_STRUCT_ADDRINFO)
endif ()

# Check for sockaddr structure sizes.
set(SOCKADDR_HEADERS)
if (WIN32)
    set(CMAKE_REQUIRED_DEFINITIONS "-DWIN32_LEAN_AND_MEAN")
    if (_MSC_VER LESS 1300)
        set(SOCKADDR_HEADERS winsock.h)
    else ()
        set(SOCKADDR_HEADERS winsock2.h ws2tcpip.h)
    endif ()
else ()
    if (EVENT__HAVE_NETINET_IN_H)
        set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} netinet/in.h)
    endif ()

    if (EVENT__HAVE_NETINET_IN6_H)
        set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} netinet/in6.h)
    endif ()

    if (EVENT__HAVE_SYS_SOCKET_H)
        set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} sys/socket.h)
    endif ()

    if (EVENT__HAVE_NETDB_H)
        set(SOCKADDR_HEADERS ${SOCKADDR_HEADERS} netdb.h)
    endif ()
endif ()

CHECK_TYPE_SIZE("struct in6_addr" EVENT__HAVE_STRUCT_IN6_ADDR)
if (EVENT__HAVE_STRUCT_IN6_ADDR)
    CHECK_STRUCT_HAS_MEMBER("struct in6_addr"
            s6_addr16 "${SOCKADDR_HEADERS}"
            EVENT__HAVE_STRUCT_IN6_ADDR_S6_ADDR16)

    CHECK_STRUCT_HAS_MEMBER("struct in6_addr"
            s6_addr32 "${SOCKADDR_HEADERS}"
            EVENT__HAVE_STRUCT_IN6_ADDR_S6_ADDR32)
endif ()

CHECK_TYPE_SIZE("sa_family_t" EVENT__HAVE_SA_FAMILY_T)
CHECK_TYPE_SIZE("struct sockaddr_in6" EVENT__HAVE_STRUCT_SOCKADDR_IN6)

if (EVENT__HAVE_STRUCT_SOCKADDR_IN6)
    CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in6"
            sin6_len "${SOCKADDR_HEADERS}"
            EVENT__HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN)

    CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in6"
            sin_len "${SOCKADDR_HEADERS}"
            EVENT__HAVE_STRUCT_SOCKADDR_IN_SIN_LEN)
endif ()

CHECK_TYPE_SIZE("struct sockaddr_storage" EVENT__HAVE_STRUCT_SOCKADDR_STORAGE)
if (EVENT__HAVE_STRUCT_SOCKADDR_STORAGE)
    CHECK_STRUCT_HAS_MEMBER("struct sockaddr_storage"
            ss_family "${SOCKADDR_HEADERS}"
            EVENT__HAVE_STRUCT_SOCKADDR_STORAGE_SS_FAMILY)

    CHECK_STRUCT_HAS_MEMBER("struct sockaddr_storage"
            __ss_family "${SOCKADDR_HEADERS}" EVENT__HAVE_STRUCT_SOCKADDR_STORAGE___SS_FAMILY)
endif ()

CHECK_TYPE_SIZE("struct linger" EVENT__HAVE_STRUCT_LINGER)

# Group the source files.
set(HDR_PRIVATE
        ${libevent_source_dir}/bufferevent-internal.h
        ${libevent_source_dir}/changelist-internal.h
        ${libevent_source_dir}/defer-internal.h
        ${libevent_source_dir}/epolltable-internal.h
        ${libevent_source_dir}/evbuffer-internal.h
        ${libevent_source_dir}/event-internal.h
        ${libevent_source_dir}/evmap-internal.h
        ${libevent_source_dir}/evrpc-internal.h
        ${libevent_source_dir}/evsignal-internal.h
        ${libevent_source_dir}/evthread-internal.h
        ${libevent_source_dir}/ht-internal.h
        ${libevent_source_dir}/http-internal.h
        ${libevent_source_dir}/iocp-internal.h
        ${libevent_source_dir}/ipv6-internal.h
        ${libevent_source_dir}/log-internal.h
        ${libevent_source_dir}/minheap-internal.h
        ${libevent_source_dir}/mm-internal.h
        ${libevent_source_dir}/ratelim-internal.h
        ${libevent_source_dir}/strlcpy-internal.h
        ${libevent_source_dir}/util-internal.h
        ${libevent_source_dir}/evconfig-private.h
        ${libevent_source_dir}/compat/sys/queue.h)

set(HDR_COMPAT
        ${libevent_source_dir}/include/evdns.h
        ${libevent_source_dir}/include/evrpc.h
        ${libevent_source_dir}/include/event.h
        ${libevent_source_dir}/include/evhttp.h
        ${libevent_source_dir}/include/evutil.h)

set(HDR_PUBLIC
        ${libevent_source_dir}/include/event2/buffer.h
        ${libevent_source_dir}/include/event2/bufferevent.h
        ${libevent_source_dir}/include/event2/bufferevent_compat.h
        ${libevent_source_dir}/include/event2/bufferevent_struct.h
        ${libevent_source_dir}/include/event2/buffer_compat.h
        ${libevent_source_dir}/include/event2/dns.h
        ${libevent_source_dir}/include/event2/dns_compat.h
        ${libevent_source_dir}/include/event2/dns_struct.h
        ${libevent_source_dir}/include/event2/event.h
        ${libevent_source_dir}/include/event2/event_compat.h
        ${libevent_source_dir}/include/event2/event_struct.h
        ${libevent_source_dir}/include/event2/watch.h
        ${libevent_source_dir}/include/event2/http.h
        ${libevent_source_dir}/include/event2/http_compat.h
        ${libevent_source_dir}/include/event2/http_struct.h
        ${libevent_source_dir}/include/event2/keyvalq_struct.h
        ${libevent_source_dir}/include/event2/listener.h
        ${libevent_source_dir}/include/event2/rpc.h
        ${libevent_source_dir}/include/event2/rpc_compat.h
        ${libevent_source_dir}/include/event2/rpc_struct.h
        ${libevent_source_dir}/include/event2/tag.h
        ${libevent_source_dir}/include/event2/tag_compat.h
        ${libevent_source_dir}/include/event2/thread.h
        ${libevent_source_dir}/include/event2/util.h
        ${libevent_source_dir}/include/event2/visibility.h
        ${libevent_binary_dir}/include/event2/event-config.h)

list(APPEND SRC_CORE
        ${libevent_source_dir}/buffer.c
        ${libevent_source_dir}/bufferevent.c
        ${libevent_source_dir}/bufferevent_filter.c
        ${libevent_source_dir}/bufferevent_pair.c
        ${libevent_source_dir}/bufferevent_ratelim.c
        ${libevent_source_dir}/bufferevent_sock.c
        ${libevent_source_dir}/event.c
        ${libevent_source_dir}/evmap.c
        ${libevent_source_dir}/evthread.c
        ${libevent_source_dir}/evutil.c
        ${libevent_source_dir}/evutil_rand.c
        ${libevent_source_dir}/evutil_time.c
        ${libevent_source_dir}/watch.c
        ${libevent_source_dir}/listener.c
        ${libevent_source_dir}/log.c
        ${libevent_source_dir}/signal.c
        ${libevent_source_dir}/strlcpy.c)

if (EVENT__HAVE_SELECT)
    list(APPEND SRC_CORE ${libevent_source_dir}/select.c)
endif ()

if (EVENT__HAVE_POLL)
    list(APPEND SRC_CORE ${libevent_source_dir}/poll.c)
endif ()

if (EVENT__HAVE_KQUEUE)
    list(APPEND SRC_CORE ${libevent_source_dir}/kqueue.c)
endif ()

if (EVENT__HAVE_DEVPOLL)
    list(APPEND SRC_CORE ${libevent_source_dir}/devpoll.c)
endif ()

if (EVENT__HAVE_EPOLL)
    list(APPEND SRC_CORE ${libevent_source_dir}/epoll.c)
endif ()

if (EVENT__HAVE_WEPOLL)
    list(APPEND SRC_CORE
            ${libevent_source_dir}/epoll.c
            ${libevent_source_dir}/wepoll.c)
endif ()

if (EVENT__HAVE_EVENT_PORTS)
    list(APPEND SRC_CORE
            ${libevent_source_dir}/evport.c)
endif ()

if (NOT EVENT__DISABLE_OPENSSL)
    # only if OPENSSL_ROOT_DIR is not set yet
    if (BREW AND NOT OPENSSL_ROOT_DIR AND NOT "$ENV{OPENSSL_ROOT_DIR}")
        execute_process(COMMAND ${BREW} --prefix openssl
                OUTPUT_VARIABLE BREW_OPENSSL_PREFIX
                RESULT_VARIABLE BREW_OPENSSL_RESULT
                ERROR_QUIET
                OUTPUT_STRIP_TRAILING_WHITESPACE
                )
        if (BREW_OPENSSL_RESULT EQUAL 0)
            message(STATUS "Set OPENSSL_ROOT_DIR=${BREW_OPENSSL_PREFIX} (from brew)")
            set(OPENSSL_ROOT_DIR "${BREW_OPENSSL_PREFIX}" CACHE PATH "")
        endif ()
    endif ()

    find_package(OpenSSL REQUIRED)

    set(EVENT__HAVE_OPENSSL 1)

    message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL lib: ${OPENSSL_LIBRARIES}")

    include_directories(${OPENSSL_INCLUDE_DIR})

    list(APPEND SRC_OPENSSL
            ${libevent_source_dir}/bufferevent_openssl.c
            ${libevent_source_dir}/bufferevent_ssl.c)
    list(APPEND HDR_PUBLIC
            ${libevent_source_dir}/include/event2/bufferevent_ssl.h)
    list(APPEND LIB_APPS ${OPENSSL_LIBRARIES})
endif ()

#if (NOT EVENT__DISABLE_MBEDTLS)
#    find_package(MbedTLS REQUIRED)
#
#    set(EVENT__HAVE_MBEDTLS 1)
#
#    message(STATUS "mbed TLS include: ${MBEDTLS_INCLUDE_DIR}")
#    message(STATUS "mbed TLS lib: ${MBEDTLS_LIBRARIES}")
#
#    include_directories(${MBEDTLS_INCLUDE_DIR})
#
#    list(APPEND SRC_MBEDTLS
#            ${libevent_source_dir}/bufferevent_mbedtls.c
#            ${libevent_source_dir}/bufferevent_ssl.c)
#    list(APPEND HDR_PUBLIC
#            ${libevent_source_dir}/include/event2/bufferevent_ssl.h)
#    list(APPEND LIB_APPS ${MBEDTLS_LIBRARIES})
#endif ()

#if (NOT EVENT__DISABLE_TESTS)
#    # Zlib is only used for testing.
#    find_package(ZLIB)
#
#    if (ZLIB_LIBRARY AND ZLIB_INCLUDE_DIR)
#        include_directories(${ZLIB_INCLUDE_DIRS})
#
#        set(EVENT__HAVE_LIBZ 1)
#        list(APPEND LIB_APPS ${ZLIB_LIBRARIES})
#    endif ()
#endif ()

set(SRC_EXTRA
        ${libevent_source_dir}/event_tagging.c
        ${libevent_source_dir}/http.c
        ${libevent_source_dir}/evdns.c
        ${libevent_source_dir}/evrpc.c)

add_definitions(-DHAVE_CONFIG_H)

# We use BEFORE here so we don't accidentally look in system directories
# first for some previous versions of the headers that are installed.
include_directories(BEFORE ${libevent_source_dir}
        ${libevent_source_dir}/compat
        ${libevent_source_dir}/include)

if (WIN32)
    list(APPEND SRC_CORE
            ${libevent_source_dir}/buffer_iocp.c
            ${libevent_source_dir}/bufferevent_async.c
            ${libevent_source_dir}/event_iocp.c
            ${libevent_source_dir}/win32select.c)

    list(APPEND HDR_PRIVATE WIN32-Code/getopt.h)

    set(EVENT__DNS_USE_FTIME_FOR_ID 1)
    set(LIB_PLATFORM ws2_32 shell32 advapi32 bcrypt)
    add_definitions(
            -D_CRT_SECURE_NO_WARNINGS
            -D_CRT_NONSTDC_NO_DEPRECATE)

    include_directories(./WIN32-Code)
endif ()

if (SOLARIS)
    list(APPEND LIB_PLATFORM socket nsl)
endif ()

source_group("Headers Private" FILES ${HDR_PRIVATE})
source_group("Header Compat" FILES ${HDR_COMPAT})
source_group("Headers Public" FILES ${HDR_PUBLIC})
source_group("Source Core" FILES ${SRC_CORE})
source_group("Source Extra" FILES ${SRC_EXTRA})

# Generate the configure headers.
# (Place them in the build dir so we don't polute the source tree with generated files).
include_directories(BEFORE ${libevent_binary_dir}/include)

if (${GNUC})
    set(EVENT_SHARED_FLAGS -fvisibility=hidden)
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "SunPro")
    set(EVENT_SHARED_FLAGS -xldscope=hidden)
endif ()

configure_file(
        ${libevent_source_dir}/event-config.h.cmake
        ${libevent_binary_dir}/include/event2/event-config.h
        NEWLINE_STYLE UNIX)

configure_file(
        ${libevent_source_dir}/evconfig-private.h.cmake
        ${libevent_binary_dir}/include/evconfig-private.h)

#
# Create the libraries.
#
include(AddEventLibrary)
add_event_library(event_core SOURCES ${SRC_CORE})
add_event_library(event_extra
        INNER_LIBRARIES event_core
        SOURCES ${SRC_EXTRA})

add_library(third_party::event_core ALIAS event_core)
add_library(third_party::event_extra ALIAS event_extra)

if (NOT EVENT__DISABLE_OPENSSL)
    add_event_library(event_openssl
            INNER_LIBRARIES event_core
            OUTER_INCLUDES ${OPENSSL_INCLUDE_DIR}
            LIBRARIES ${OPENSSL_LIBRARIES}
            SOURCES ${SRC_OPENSSL})
    add_library(third_party::event_openssl ALIAS event_openssl)
endif ()

#if (NOT EVENT__DISABLE_MBEDTLS)
#    add_event_library(event_mbedtls
#            INNER_LIBRARIES event_core
#            OUTER_INCLUDES ${MBEDTLS_INCLUDE_DIR}
#            LIBRARIES ${MBEDTLS_LIBRARIES}
#            SOURCES ${SRC_MBEDTLS})
#    add_library(third_party::event_mbedtls ALIAS event_mbedtls)
#endif ()

if (EVENT__HAVE_PTHREADS)
    set(SRC_PTHREADS ${libevent_source_dir}/evthread_pthread.c)
    add_event_library(event_pthreads
            INNER_LIBRARIES event_core
            SOURCES ${SRC_PTHREADS})
    add_library(third_party::event_pthreads ALIAS event_pthreads)
endif ()

# library exists for historical reasons; it contains the contents of
# both libevent_core and libevent_extra. You shouldn’t use it; it may
# go away in a future version of Libevent.
add_event_library(event SOURCES ${SRC_CORE} ${SRC_EXTRA})
add_library(third_party::libevent ALIAS event)

cmake_minimum_required(VERSION 3.16)

PROJECT(lsquic C)

OPTION(LSQUIC_FIU "Use Fault Injection in Userspace (FIU)" OFF)
OPTION(LSQUIC_BIN "Compile example binaries that use the library" ON)
OPTION(LSQUIC_TESTS "Compile library unit tests" ON)
OPTION(LSQUIC_SHARED_LIB "Compile as shared librarry" OFF)
OPTION(LSQUIC_DEVEL "Compile in development mode" OFF)

INCLUDE(GNUInstallDirs)

IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # If using older glibc, need to link with -lrt.  See clock_getres(2).
    include(CheckSymbolExists)
    check_symbol_exists(clock_getres "time.h" HAS_clock_getres_WITHOUT_LIBRT)

    if (NOT HAS_clock_getres_WITHOUT_LIBRT)
        find_library(RT_LIBRARY rt)
        set(NEED_LIBRT_FOR_clock_getres ON)
    endif ()
ELSEIF (CMAKE_SYSTEM_NAME STREQUAL "Android")
    # for android-ndk >= r19b
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY "BOTH")
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE "BOTH")
    set(CMAKE_FIND_ROOT_PATH_MODE_PATH "BOTH")
ENDIF ()

IF ("${CMAKE_BUILD_TYPE}" STREQUAL "")
    SET(CMAKE_BUILD_TYPE Debug)
ENDIF ()

MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

IF (NOT "$ENV{EXTRA_CFLAGS}" MATCHES "-DLSQUIC_DEBUG_NEXT_ADV_TICK")
    SET(MY_CMAKE_FLAGS "-DLSQUIC_DEBUG_NEXT_ADV_TICK=1")
ENDIF ()

IF (NOT "$ENV{EXTRA_CFLAGS}" MATCHES "-DLSQUIC_CONN_STATS=")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_CONN_STATS=1")
ENDIF ()

IF (NOT MSVC)

    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wall -Wextra -Wno-unused-parameter")
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fno-omit-frame-pointer")

    IF (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9.3)
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Wno-missing-field-initializers")
    ENDIF ()

    IF (LSQUIC_FIU)
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DFIU_ENABLE=1")
        SET(LIBS ${LIBS} fiu)
    ENDIF ()

    IF (CMAKE_BUILD_TYPE STREQUAL "Debug")
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O0 -g3")
        IF (CMAKE_C_COMPILER MATCHES "clang" AND
                NOT "$ENV{TRAVIS}" MATCHES "^true$" AND
                NOT "$ENV{EXTRA_CFLAGS}" MATCHES "-fsanitize")
            SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fsanitize=address")
            SET(LIBS ${LIBS} -fsanitize=address)
        ENDIF ()
        # Uncomment to enable cleartext protocol mode (no crypto):
        #SET (MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_ENABLE_HANDSHAKE_DISABLE=1")
    ELSE ()
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -O3 -g0")
        # Comment out the following line to compile out debug messages:
        #SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_INFO")
    ENDIF ()

    IF (LSQUIC_DEVEL)
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_DEVEL=1")
    ENDIF ()

    IF (LSQUIC_PROFILE EQUAL 1)
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -g -pg")
    ENDIF ()

    IF (LSQUIC_COVERAGE EQUAL 1)
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fprofile-arcs -ftest-coverage")
    ENDIF ()

    IF (MY_CMAKE_FLAGS MATCHES "fsanitize=address")
        MESSAGE(STATUS "AddressSanitizer is ON")
    ELSE ()
        MESSAGE(STATUS "AddressSanitizer is OFF")
    ENDIF ()

    #MSVC
ELSE ()
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4100") # unreferenced formal parameter
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4115") # unnamed type definition in parentheses
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4116") # named type definition in parentheses
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4146") # unary minus operator applied to unsigned type, result still unsigned
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4132") # const initialization
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4200") # zero-sized array
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4204") # non-constant aggregate initializer
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4244") # integer conversion
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4245") # conversion from 'int' to 'unsigned int', signed/unsigned mismatch
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4267") # integer conversion
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4214") # nonstandard extension used: bit field types other than int
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4295") # array is too small to include a terminating null character
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4334") # result of 32-bit shift implicitly converted to 64 bits (was 64-bit shift intended?)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4456") # hide previous local declaration
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4459") # hide global declaration
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4706") # assignment within conditional expression
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4090") # different 'const' qualifier (TODO: debug ls-sfparser.c)
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} /wd4305") # truncation from double to float
    SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -W4 -WX -Zi -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_CRT_SECURE_NO_WARNINGS -I${CMAKE_CURRENT_SOURCE_DIR}/wincompat")
    IF (LSQUIC_SHARED_LIB)
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_SHARED_LIB")
    ENDIF ()
    IF (CMAKE_BUILD_TYPE STREQUAL "Debug")
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Od")
        #SET (MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DFIU_ENABLE=1")
        #SET(LIBS ${LIBS} fiu)
    ELSE ()
        SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -Ox")
        # Comment out the following line to compile out debug messages:
        #SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -DLSQUIC_LOWEST_LOG_LEVEL=LSQ_LOG_INFO")
    ENDIF ()

ENDIF () #MSVC

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  ${MY_CMAKE_FLAGS} $ENV{EXTRA_CFLAGS}")

MESSAGE(STATUS "Compiler flags: ${CMAKE_C_FLAGS}")

set(LIBRARY_SOURCE_DIR ${test_quic_SOURCE_DIR}/third_party/lsquic)
set(LIBRARY_BINARY_DIR ${test_quic_BINARY_DIR}/third_party/lsquic)

INCLUDE_DIRECTORIES(${LIBRARY_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${LIBRARY_SOURCE_DIR}/src/liblsquic)
INCLUDE_DIRECTORIES(${LIBRARY_SOURCE_DIR}/src/liblsquic/ls-qpack)
INCLUDE_DIRECTORIES(${LIBRARY_SOURCE_DIR}/src/lshpack)

set(LIBRARY_SRCS
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/ls-qpack/lsqpack.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_adaptive_cc.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_alarmset.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_arr.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_attq.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_bbr.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_bw_sampler.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_cfcw.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_chsk_stream.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_conn.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_crand.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_crt_compress.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_crypto.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_cubic.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_di_error.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_di_hash.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_di_nocopy.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_enc_sess_common.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_enc_sess_ietf.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_eng_hist.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_engine.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_ev_log.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_frab_list.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_frame_common.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_frame_reader.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_frame_writer.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_full_conn.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_full_conn_ietf.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_global.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_handshake.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_hash.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_hcsi_reader.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_hcso_writer.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_headers_stream.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_hkdf.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_hpi.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_hspack_valid.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_http.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_http1x_if.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_logger.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_malo.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_min_heap.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_mini_conn.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_mini_conn_ietf.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_minmax.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_mm.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_pacer.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_packet_common.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_packet_gquic.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_packet_in.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_packet_out.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_packet_resize.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_parse_Q046.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_parse_Q050.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_parse_common.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_parse_gquic_be.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_parse_gquic_common.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_parse_ietf_v1.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_parse_iquic_common.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_pr_queue.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_purga.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_qdec_hdl.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_qenc_hdl.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_qlog.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_qpack_exp.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_rechist.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_rtt.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_send_ctl.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_senhist.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_set.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_sfcw.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_shsk_stream.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_spi.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_stock_shi.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_str.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_stream.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_tokgen.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_trans_params.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_trechist.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_util.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_varint.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_version.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_xxhash.c
        ${LIBRARY_SOURCE_DIR}/src/liblsquic/ls-sfparser.c
        ${LIBRARY_SOURCE_DIR}/src/lshpack/lshpack.c
        )

IF (NOT MSVC)
    SET(QPACK_FLAGS "-Wno-uninitialized")
    INCLUDE(CheckCCompilerFlag)
    CHECK_C_COMPILER_FLAG(-Wno-implicit-fallthrough HAS_NO_IMPLICIT_FALLTHROUGH)
    IF (HAS_NO_IMPLICIT_FALLTHROUGH)
        SET(QPACK_FLAGS "${QPACK_FLAGS} -Wno-implicit-fallthrough")
    ENDIF ()
    set_source_files_properties(${LIBRARY_SOURCE_DIR}/src/liblsquic/ls-qpack/lsqpack.c PROPERTIES COMPILE_FLAGS ${QPACK_FLAGS})
ENDIF ()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DXXH_HEADER_NAME=\\\"${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_xxhash.h\\\"")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLSQPACK_ENC_LOGGER_HEADER=\\\"${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_qpack_enc_logger.h\\\"")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLSQPACK_DEC_LOGGER_HEADER=\\\"${LIBRARY_SOURCE_DIR}/src/liblsquic/lsquic_qpack_dec_logger.h\\\"")


add_library(_lsquic ${LIBRARY_SRCS})

TARGET_LINK_LIBRARIES(_lsquic PRIVATE third_party::boringssl third_party::zlib)

target_include_directories(_lsquic SYSTEM BEFORE PUBLIC ${LIBRARY_SOURCE_DIR}/include)

add_library(third_party::lsquic ALIAS _lsquic)

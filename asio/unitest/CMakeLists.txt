# 项目名称
project(asio_quic_test)

find_package(GTest REQUIRED)

include_directories(../public)

aux_source_directory(. DIR_EXE_SRCS)

add_executable(asio_quic_test ${DIR_EXE_SRCS})

target_link_libraries(asio_quic_test
        GTest::gtest GTest::gtest_main
        asio_quic
        third_party::lsquic
        boost::headers_only
        third_party::boringssl
        )
target_include_directories(asio_quic_test PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME asio_quic_test COMMAND $<TARGET_FILE:asio_quic_test>)
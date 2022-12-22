# 项目名称
project(asio_server)

include_directories(../include)
include_directories(../public)

# 将 src 目录下的所有源文件加入后面的变量之中
aux_source_directory(. DIR_EXE_SRCS)
aux_source_directory(../public/global SRCS_GLOBAL)
aux_source_directory(../public/h3 SRCS_H3)
aux_source_directory(../public/quic SRCS_QUIC)
aux_source_directory(../public/quic/detail SRCS_QUIC_DETAIL)

# 构建可执行文件
add_executable(${PROJECT_NAME}
        ${DIR_EXE_SRCS}
        ${SRCS_GLOBAL}
        ${SRCS_H3}
        ${SRCS_QUIC}
        ${SRCS_QUIC_DETAIL}
        )

# 指定目标链接的库
target_link_libraries(
        ${PROJECT_NAME}
        PRIVATE
        third_party::lsquic
        third_party::boringssl
        boost::headers_only
        dl
        rt
)

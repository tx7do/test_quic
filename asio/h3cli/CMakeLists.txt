# 项目名称
project(h3cli)

include_directories(../public)

# 将 src 目录下的所有源文件加入后面的变量之中
aux_source_directory(. DIR_EXE_SRCS)

# 构建可执行文件
add_executable(${PROJECT_NAME}
        ${DIR_EXE_SRCS}
        )

# 指定目标链接的库
target_link_libraries(
        ${PROJECT_NAME}
        PRIVATE
        asio_quic
        boost::headers_only
        third_party::boringssl
        dl
        rt
)

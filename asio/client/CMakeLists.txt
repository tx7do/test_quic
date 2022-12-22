# 项目名称
project(asio_client)

include_directories(../include)

# 将 src 目录下的所有源文件加入后面的变量之中
aux_source_directory(. DIR_EXE_SRCS)
aux_source_directory(../public DIR_PUBLIC_SRCS)

# 构建可执行文件
add_executable(${PROJECT_NAME} ${DIR_EXE_SRCS} ${DIR_PUBLIC_SRCS})

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

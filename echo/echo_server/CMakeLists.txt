# CMake 最低版本号要求
cmake_minimum_required(VERSION 3.0)

# 项目名称
project(echo_server)

# C++版本
set(CMAKE_CXX_STANDARD 20)


# 将 src 目录下的所有源文件加入后面的变量之中
aux_source_directory(. DIR_EXE_SRCS)

# 构建可执行文件
add_executable(${PROJECT_NAME} ${DIR_EXE_SRCS})

# 指定目标链接的库
target_link_libraries(
        ${PROJECT_NAME}
        PRIVATE
        third_party::lsquic
        third_party::libevent
        boost::headers_only
        dl
        rt
)

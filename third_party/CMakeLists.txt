set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w")

set_property(DIRECTORY PROPERTY EXCLUDE_FROM_ALL 1)

function(add_third_party cmake_folder)
    if (ARGN)
        set(base_folders ${ARGN})
    else ()
        set(base_folders ${cmake_folder})
    endif ()

    foreach (base_folder ${base_folders})
        # some typos in the code
        if (NOT IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${base_folder}")
            message(FATAL_ERROR "No such base folder '${base_folder}' (for '${cmake_folder}' cmake folder). Typo in the base folder name?")
        endif ()

        file(GLOB third_party_files "${base_folder}/*")
        if (NOT third_party_files)
            message(STATUS "submodule ${base_folder} is missing or empty. to fix try run:")
            message(STATUS "    git submodule update --init")
            return()
        endif ()
    endforeach ()

    message(STATUS "Adding third_party module ${base_folders} (configuring with ${cmake_folder})")
    add_subdirectory(${cmake_folder})
endfunction()

add_third_party(libuv-cmake libuv)
add_third_party(libevent-cmake libevent)
add_third_party(boringssl-cmake boringssl)
add_third_party(zlib-cmake zlib-ng)
add_third_party(boost-cmake boost)
add_third_party(lsquic-cmake lsquic)

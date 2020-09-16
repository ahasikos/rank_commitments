ExternalProject_Add(
        libntl
        URL http://www.shoup.net/ntl/ntl-11.4.3.tar.gz
        DEPENDS libgf2x
        DOWNLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}
        BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/libntl-prefix/src/libntl/src
            ./configure NTL_GMP_LIP=off NTL_GF2X_LIB=on GF2X_PREFIX=${LIBGF2X_LIBRARY_PATH} DEF_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/libntl
        BUILD_COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/libntl-prefix/src/libntl/src/ make
        INSTALL_COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/libntl-prefix/src/libntl/src/ make install
)

add_library(ntl IMPORTED STATIC)
set(NTL_LIBRARY_PATH ${CMAKE_CURRENT_BINARY_DIR}/libntl/lib)
set(NTL_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/libntl/include)
set(NTL_LIBRARY ${NTL_LIBRARY_PATH}/${CMAKE_STATIC_LIBRARY_PREFIX}ntl${CMAKE_STATIC_LIBRARY_SUFFIX})
set_target_properties(ntl PROPERTIES IMPORTED_LOCATION ${NTL_LIBRARY})
install(DIRECTORY ${NTL_LIBRARY_PATH} DESTINATION lib FILES_MATCHING PATTERN "${CMAKE_STATIC_LIBRARY_PREFIX}*")
link_directories(${NTL_LIBRARY_PATH})

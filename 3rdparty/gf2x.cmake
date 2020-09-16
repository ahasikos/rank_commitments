ExternalProject_Add(
        libgf2x
        URL https://gforge.inria.fr/frs/download.php/file/36934/gf2x-1.2.tar.gz
        DOWNLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}
        BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/libgf2x-prefix/src/libgf2x
        ./configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/libgf2x
        BUILD_COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/libgf2x-prefix/src/libgf2x make
        INSTALL_COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/libgf2x-prefix/src/libgf2x make install
)

add_library(gf2x IMPORTED STATIC)
add_dependencies(gf2x libgf2x)
set(LIBGF2X_LIBRARY_PATH ${CMAKE_CURRENT_BINARY_DIR}/libgf2x/)
set(GF2X_LIBRARY_PATH ${CMAKE_CURRENT_BINARY_DIR}/libgf2x/lib)
set(GF2X_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/libgf2x/include)
set(GF2X_LIBRARY ${GF2X_LIBRARY_PATH}/${CMAKE_STATIC_LIBRARY_PREFIX}gf2x${CMAKE_STATIC_LIBRARY_SUFFIX})
set_target_properties(gf2x PROPERTIES IMPORTED_LOCATION ${GF2X_LIBRARY})
install(DIRECTORY ${GF2X_LIBRARY_PATH} DESTINATION lib FILES_MATCHING PATTERN "${CMAKE_STATIC_LIBRARY_PREFIX}*")
link_directories(${GF2X_LIBRARY_PATH})

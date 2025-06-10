# Get all source files.
file(GLOB SOURCE_LIST CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/*.cpp")

# Make an automatic library - will be static or dynamic based on user setting.
add_library(BP ${SOURCE_LIST})

# Include the header directory.
target_include_directories(BP PUBLIC ${PROJECT_SOURCE_DIR}/include)

# Include the tongsuo library and link it.
target_include_directories(BP PUBLIC /opt/tongsuo/include/)
target_link_directories(BP PUBLIC /opt/tongsuo/lib64)
target_link_libraries(BP PUBLIC crypto)

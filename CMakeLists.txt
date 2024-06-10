cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

project(fty-email
    VERSION 1.0.0
    DESCRIPTION "fty-email service"
)

find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR}/fty-cmake)

##############################################################################################################

add_subdirectory(lib)
add_subdirectory(agent)
add_subdirectory(cli)

##############################################################################################################

set(res resources)

# Agent config
etn_configure_file(
    ${res}/${PROJECT_NAME}.cfg.in
    TARGET      ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME}
)

# systemd service
etn_configure_file(
    ${res}/${PROJECT_NAME}.service.in
    TARGET      ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/
)

# .conf > lib/tmpfiles.d/
install(
    FILES ${res}/${PROJECT_NAME}.conf
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/tmpfiles.d/
)

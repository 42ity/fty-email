cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

project(fty-email
    VERSION 1.0.0
    DESCRIPTION "Email transport for 42ity (based on msmtp)"
)

##############################################################################################################
find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR}/fty-cmake)
##############################################################################################################

##############################################################################################################
etn_target(static ${PROJECT_NAME}-static
    SOURCES
        src/email.cc
        src/emailconfiguration.cc
        src/fty_sendmail.cc
    USES
        czmq
        cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
        fty_common_logging
        fty_common
        fty_proto
        fty_common_mlm
        fty_common_translation
        mlm
        magic
    PRIVATE
)

##############################################################################################################
etn_target(exe ${PROJECT_NAME}-server
    SOURCES
        src/fty_email_server.cc
        src/fty_email.cc
    USES
        ${PROJECT_NAME}-static
        czmq
        cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
        fty_common
        fty_common_logging
        fty_proto
        fty_common_mlm
        fty_common_translation
        mlm
        magic
)

#systemd-tmpfiles
etn_configure_file(
    ${PROJECT_SOURCE_DIR}/src/fty-email.service.in
    TARGET      ${PROJECT_NAME}-server
    DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/systemd/system/"
)

##############################################################################################################

#if(BUILD_TESTING)
#    enable_testing()
#
#    # Create a target for the tests
#    etn_test(${PROJECT_NAME}-test
#        SOURCES
#            src/fty_discovery_server.cc
#            test/fty_discovery_selftest.cc
#            test/fty_discovery_private_selftest.cc
#        INCLUDE_DIRS
#            src
#        USES
#            ${PROJECT_NAME}-static
#            cidr
#            czmq
#            cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
#            fty-asset-accessor
#            fty_common
#            fty_common_db
#            fty_common_logging
#            fty_common_nut
#            fty_common_socket
#            fty_proto
#            fty_security_wallet
#            fty-utils
#            mlm
#            tntdb
#    )
#    
#endif()

##############################################################################################################

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
        fty-utils
)

#systemd-tmpfiles
etn_configure_file(
    ${PROJECT_SOURCE_DIR}/src/fty-email.service.in
    TARGET      ${PROJECT_NAME}-server
    DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/systemd/system/"
)

etn_configure_file(
    ${PROJECT_SOURCE_DIR}/src/conf/fty-email.cfg.in
    TARGET      ${PROJECT_NAME}-server
    DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME}
)

##############################################################################################################

if(BUILD_TESTING)
    enable_testing()

    # Create a target for the tests
    etn_test(${PROJECT_NAME}-test
        SOURCES
            test/fty_email_private_selftest.cc
            test/fty_email_selftest.cc
            src/fty_email_server.cc
        CONFIGS
            test/conf/smtp-test-10.cfg
            test/conf/test_en_US.json
        INCLUDE_DIRS
            src
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
            fty-utils
    )

    
endif()

##############################################################################################################

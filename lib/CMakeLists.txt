cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

etn_target(static ${PROJECT_NAME}-static
    PRIVATE
    SOURCES
        src/email.h
        src/email.cc
        src/emailconfiguration.h
        src/emailconfiguration.cc
        src/audit_log.h
        src/audit_log.cc
        src/fty_email.h
        src/fty_email_server.h
        src/fty_email_server.cc
    PUBLIC_INCLUDE_DIR
        src/
#    PUBLIC
#        src/*.h
    USES
        czmq
        mlm
        magic
        cxxtools
        fty-utils
        fty_proto
        fty_common
        fty_common_mlm
        fty_common_logging
        fty_common_translation
)

add_subdirectory(test)

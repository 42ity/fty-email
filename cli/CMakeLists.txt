cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

etn_target(exe fty-sendmail
    SOURCES
        src/fty_sendmail.cc
    USES
        ${PROJECT_NAME}-static
)

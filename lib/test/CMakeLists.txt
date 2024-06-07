cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

etn_test_target(${PROJECT_NAME}-static
    CONFIGS
        conf/*
    SOURCES
        src/main.cpp
        src/email.cpp
        src/emailconfiguration.cpp
        src/fty_email_server.cpp
    USES
        ${PROJECT_NAME}-static
)

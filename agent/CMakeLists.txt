cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

etn_target(exe ${PROJECT_NAME}
    SOURCES
        src/fty_email.cc
    USES
        ${PROJECT_NAME}-static
)

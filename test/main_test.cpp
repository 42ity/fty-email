#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_DISABLE_EXCEPTIONS

#include <catch2/catch.hpp>
#include <filesystem>
#include "fty_email_private_selftest.h"

TEST_CASE("All the stuff of before") {
    REQUIRE(true);

    std::cout << "Current path is " << std::filesystem::current_path() << std::endl;
    // Execute all self tests
    fty_email_private_selftest(true, "$ALL");
}
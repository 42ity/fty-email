#include <catch2/catch.hpp>

#include "src/emailconfiguration.h"
#include <fty_log.h>
#include <fty_common_translation.h>
#include <string>

TEST_CASE("emailconfiguration test")
{
    {
        int rv = translation_initialize("emailconfiguration-test", "test/conf", "test_");
        if (rv != TE_OK) {
            log_warning("Translation not initialized");
        }
    }

    if (1) {
        logDebug("==== generate_subject");

        REQUIRE_NOTHROW(generate_subject(NULL, "P1", "extname"));
        REQUIRE(generate_subject(NULL, "P1", "extname").empty());

        zmsg_t* msg = fty_proto_encode_alert(NULL, 42, 60, "rule", "iname", "RESOLVED", "severity", "descripttion", NULL);
        fty_proto_t* alert = fty_proto_decode(&msg);
        fty_proto_print(alert);

        REQUIRE_NOTHROW(generate_subject(alert, "1", "extname"));
        std::string s = generate_subject(alert, "1", "extname");
        logInfo("== 1:\n{}", s);
        REQUIRE(!s.empty());

        fty_proto_set_state(alert, "%s", "HIGH_WARNING");

        REQUIRE_NOTHROW(generate_subject(alert, "1", "extname"));
        s = generate_subject(alert, "1", "extname");
        logInfo("== 2:\n{}", s);
        REQUIRE(!s.empty());

        fty_proto_destroy(&alert);
    }

    if (1) {
        logDebug("==== generate_body");

        REQUIRE_NOTHROW(generate_body(NULL, "P1", "extname"));
        REQUIRE(generate_body(NULL, "P1", "extname").empty());

        zmsg_t* msg = fty_proto_encode_alert(NULL, 42, 60, "rule", "iname", "RESOLVED", "severity", "descripttion", NULL);
        fty_proto_t* alert = fty_proto_decode(&msg);

        REQUIRE_NOTHROW(generate_body(alert, "1", "extname"));
        std::string s = generate_body(alert, "1", "extname");
        logInfo("== 1:\n{}", s);
        REQUIRE(!s.empty());

        fty_proto_set_state(alert, "%s", "HIGH_WARNING");

        REQUIRE_NOTHROW(generate_body(alert, "1", "extname"));
        s = generate_body(alert, "1", "extname");
        logInfo("== 2:\n{}", s);
        REQUIRE(!s.empty());

        fty_proto_destroy(&alert);
    }

    if (1) {
        logDebug("==== getIpAddr");
        std::string s = getIpAddr();
        CHECK(!s.empty());
        logInfo("\nAddr: '{}'", s);
    }
}

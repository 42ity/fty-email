#include "src/email.h"
#include "src/emailconfiguration.h"
#include "src/fty_email_server.h"
#include "src/fty_email_audit_log.h"

#include <catch2/catch.hpp>
#include <fstream>
#include <fty_log.h>

TEST_CASE("email_test")
{
    ManageFtyLog::setInstanceFtylog("email_test", FTY_COMMON_LOGGING_DEFAULT_CFG);
    AuditLogManager::init();

    // test case 01 - normal operation
    std::string to = sms_email_address("0#####@hyper.mobile", "+79 (0) 123456");
    CHECK(to == "023456@hyper.mobile");

    // test case 02 - not enough numbers
    try {
        to = sms_email_address("0#####@hyper.mobile", "456");
        CHECK(false); // <<< due exception throwed up, we should not reach this place
    } catch (std::logic_error& e) {
    }

    // test case 03 - no # in template
    to = sms_email_address("0^^^^^@hyper.mobile", "456");
    CHECK(to == "0^^^^^@hyper.mobile");

    // test case 04 empty template
    to = sms_email_address("", "+79 (0) 123456");
    CHECK(to.empty());

    // test case 05 empty number
    try {
        to = sms_email_address("0#####@hyper.mobile", "");
        CHECK(false); // <<< due exception throwed up, we should not reach this place
    } catch (std::logic_error& e) {
    }

    // test of msmtp_stderr2code
    // test case 3 DNSFailed
    CHECK(msmtp_stderr2code("msmtp: cannot locate host NOTmail.etn.com: Name or service not known\nmsmtp: could not "
                              "send mail (account default from config)") == SmtpError::DNSFailed);

    zhash_t* headers = zhash_new();
    {
        const char* s = "bar";
        zhash_update(headers, "Foo", static_cast<void*>(const_cast<char*>(s)));
    }
    zmsg_t* email_msg = fty_email_encode("uuid", "to", "subject", headers, "body", "file1", "file2.txt", NULL);
    REQUIRE(email_msg);
    zhash_destroy(&headers);
    std::ofstream ofile1{"file1", std::ios::binary};
    ofile1.write("MZ\0\0\0\0\0\0", 8);
    ofile1.flush();
    ofile1.close();

    std::ofstream ofile2{"file2.txt"};
    ofile2 << ("file2.txt");
    ofile2.flush();
    ofile2.close();

    Smtp  smtp{};
    char* uuid = zmsg_popstr(email_msg);
    zstr_free(&uuid);
    std::string email = smtp.msg2email(&email_msg);
    log_debug("E M A I L:=\n%s\n", email.c_str());

    AuditLogManager::deinit();
}

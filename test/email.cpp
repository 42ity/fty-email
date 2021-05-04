#include "email.h"
#include "emailconfiguration.h"
#include "fty_email_server.h"
#include <catch2/catch.hpp>
#include <fstream>

TEST_CASE("email_test")
{
    printf(" * email: ");

    //  @selftest

    // Note: If your selftest reads SCMed fixture data, please keep it in
    // src/selftest-ro; if your test creates filesystem objects, please
    // do so under src/selftest-rw. They are defined below along with a
    // usecase for the variables (REQUIRE) to make compilers happy.
    const char* SELFTEST_DIR_RO = "src/selftest-ro";
    const char* SELFTEST_DIR_RW = "src/selftest-rw";
    REQUIRE(SELFTEST_DIR_RO);
    REQUIRE(SELFTEST_DIR_RW);
    // Uncomment these to use C++ strings in C++ selftest code:
    std::string str_SELFTEST_DIR_RO = std::string(SELFTEST_DIR_RO);
    std::string str_SELFTEST_DIR_RW = std::string(SELFTEST_DIR_RW);
    REQUIRE((str_SELFTEST_DIR_RO != ""));
    REQUIRE((str_SELFTEST_DIR_RW != ""));
    // NOTE that for "char*" context you need (str_SELFTEST_DIR_RO + "/myfilename").c_str()

    // test case 01 - normal operation
    std::string to = sms_email_address("0#####@hyper.mobile", "+79 (0) 123456");
    REQUIRE(to == "023456@hyper.mobile");

    // test case 02 - not enough numbers
    try {
        to = sms_email_address("0#####@hyper.mobile", "456");
        REQUIRE(false); // <<< due exception throwed up, we should not reach this place
    } catch (std::logic_error& e) {
    }

    // test case 03 - no # in template
    to = sms_email_address("0^^^^^@hyper.mobile", "456");
    REQUIRE(to == "0^^^^^@hyper.mobile");

    // test case 04 empty template
    to = sms_email_address("", "+79 (0) 123456");
    REQUIRE(to.empty());

    // test case 05 empty number
    try {
        to = sms_email_address("0#####@hyper.mobile", "");
        REQUIRE(false); // <<< due exception throwed up, we should not reach this place
    } catch (std::logic_error& e) {
    }

    // test of msmtp_stderr2code
    // test case 3 DNSFailed
    REQUIRE(msmtp_stderr2code("msmtp: cannot locate host NOTmail.etn.com: Name or service not known\nmsmtp: could not "
                             "send mail (account default from config)") == SmtpError::DNSFailed);

    zhash_t* headers = zhash_new();
    {
        const char * s = "bar";
        zhash_update(headers, "Foo", static_cast<void*>(const_cast<char*>(s)));
    }
    zmsg_t* email_msg = fty_email_encode("uuid", "to", "subject", headers, "body",
        (str_SELFTEST_DIR_RW + "/file1").c_str(), (str_SELFTEST_DIR_RW + "/file2.txt").c_str(), NULL);
    REQUIRE(email_msg);
    zhash_destroy(&headers);
    std::ofstream ofile1{str_SELFTEST_DIR_RW + "/file1", std::ios::binary};
    ofile1.write("MZ\0\0\0\0\0\0", 8);
    ofile1.flush();
    ofile1.close();

    std::ofstream ofile2{str_SELFTEST_DIR_RW + "/file2.txt"};
    ofile2 << (str_SELFTEST_DIR_RW + "/file2.txt");
    ofile2.flush();
    ofile2.close();

    Smtp  smtp{};
    char* uuid = zmsg_popstr(email_msg);
    zstr_free(&uuid);
    std::string email = smtp.msg2email(&email_msg);
    log_debug("E M A I L:=\n%s\n", email.c_str());

    //  @end
    printf("OK\n");
}

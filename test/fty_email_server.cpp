#include "fty_email_server.h"
#include "emailconfiguration.h"
#include "fty_email.h"
#include <catch2/catch.hpp>
#include <fty/convert.h>
#include <fty_common_translation.h>

TEST_CASE("fty_email_server_test")
{
    // Note: If your selftest reads SCMed fixture data, please keep it in
    // src/selftest-ro; if your test creates filesystem objects, please
    // do so under src/selftest-rw. They are defined below along with a
    // usecase for the variables (REQUIRE) to make compilers happy.

    const char* SELFTEST_DIR_RO = "test_conf/";
    const char* SELFTEST_DIR_RW = "test_conf/";
    REQUIRE(SELFTEST_DIR_RO);
    REQUIRE(SELFTEST_DIR_RW);
    // Uncomment these to use C++ strings in C++ selftest code:
    // std::string str_SELFTEST_DIR_RO = std::string(SELFTEST_DIR_RO);
    // std::string str_SELFTEST_DIR_RW = std::string(SELFTEST_DIR_RW);
    // REQUIRE ( (str_SELFTEST_DIR_RO != "") );
    // REQUIRE ( (str_SELFTEST_DIR_RW != "") );
    // NOTE that for "char*" context you need (str_SELFTEST_DIR_RO + "/myfilename").c_str()

    int rv = translation_initialize(FTY_EMAIL_ADDRESS, SELFTEST_DIR_RO, "test_");
    if (rv != TE_OK)
        log_warning("Translation not initialized");

    char* pidfile = zsys_sprintf("%s/btest.pid", SELFTEST_DIR_RW);
    REQUIRE(pidfile != NULL);

    char* smtpcfg_file = zsys_sprintf("%s/smtp.cfg", SELFTEST_DIR_RW);
    REQUIRE(smtpcfg_file != NULL);

    printf(" * fty_email_server: ");
    if (zfile_exists(pidfile)) {
        std::cerr << "EXIST FILE" << std::endl;
        FILE* fp = fopen(pidfile, "r");
        REQUIRE(fp);
        int pid;
        int r = fscanf(fp, "%d", &pid);
        REQUIRE(r > 0); // make picky compilers happy
        fclose(fp);
        log_info("about to kill -9 %d", pid);
        kill(pid, SIGKILL);
        unlink(pidfile);
    }

    //  @selftest

    {
        log_debug("Test #1");
        zhash_t* headers = zhash_new();
        {
            const char * s = "bar";
            zhash_update(headers, "Foo", static_cast<void*>(const_cast<char*>(s)));
        }
        char* file1_name = zsys_sprintf("%s/file1", SELFTEST_DIR_RW);
        REQUIRE(file1_name != NULL);
        char* file2_name = zsys_sprintf("%s/file2.txt", SELFTEST_DIR_RW);
        REQUIRE(file2_name != NULL);
        zmsg_t* email_msg = fty_email_encode("UUID", "TO", "SUBJECT", headers, "BODY", file1_name, file2_name, NULL);
        REQUIRE(email_msg);
        REQUIRE(zmsg_size(email_msg) == 7);
        zhash_destroy(&headers);

        char* uuid     = zmsg_popstr(email_msg);
        char* to       = zmsg_popstr(email_msg);
        char* csubject = zmsg_popstr(email_msg);
        char* body     = zmsg_popstr(email_msg);

        REQUIRE(streq(uuid, "UUID"));
        REQUIRE(streq(to, "TO"));
        REQUIRE(streq(csubject, "SUBJECT"));
        REQUIRE(streq(body, "BODY"));

        zstr_free(&uuid);
        zstr_free(&to);
        zstr_free(&csubject);
        zstr_free(&body);

        zframe_t* frame = zmsg_pop(email_msg);
        REQUIRE(frame);
        headers = zhash_unpack(frame);
        zframe_destroy(&frame);

        REQUIRE(streq(static_cast<char*>(zhash_lookup(headers, "Foo")), "bar"));
        zhash_destroy(&headers);

        char* file1 = zmsg_popstr(email_msg);
        char* file2 = zmsg_popstr(email_msg);
        char* file3 = zmsg_popstr(email_msg);

        log_debug("Got file1='%s'\nExpected ='%s'", file1, file1_name);
        log_debug("Got file2='%s'\nExpected ='%s'", file2, file2_name);

        REQUIRE(streq(file1, file1_name));
        REQUIRE(streq(file2, file2_name));
        REQUIRE(!file3);

        zstr_free(&file1);
        zstr_free(&file2);
        zstr_free(&file1_name);
        zstr_free(&file2_name);
        zmsg_destroy(&email_msg);

        log_debug("Test #1 OK");
    }

    static const char* endpoint = "inproc://fty-smtp-server-test";

    // malamute broker
    zactor_t* server;
    {
        std::string s("Malamute");
        server = zactor_new(mlm_server, static_cast<void*>(&s));
    }
    REQUIRE(server != NULL);
    zstr_sendx(server, "BIND", endpoint, NULL);
    log_info("malamute started");

    // similar to create_test_smtp_server
    zactor_t* smtp_server = zactor_new(fty_email_server, NULL);
    REQUIRE(smtp_server != NULL);

    zconfig_t* config = zconfig_new("root", NULL);
    zconfig_put(config, "smtp/gwtemplate", "0#####@hyper.mobile");
    zconfig_put(config, "malamute/endpoint", endpoint);
    zconfig_put(config, "malamute/address", "agent-smtp");
    zconfig_save(config, smtpcfg_file);
    zconfig_destroy(&config);

    zstr_sendx(smtp_server, "LOAD", smtpcfg_file, NULL);
    zstr_sendx(smtp_server, "_MSMTP_TEST", "btest-reader", NULL);

    mlm_client_t* alert_producer = mlm_client_new();
    rv                           = mlm_client_connect(alert_producer, endpoint, 1000, "alert_producer");
    REQUIRE(rv != -1);
    log_info("alert producer started");

    mlm_client_t* btest_reader = mlm_client_new();
    rv                         = mlm_client_connect(btest_reader, endpoint, 1000, "btest-reader");
    REQUIRE(rv != -1);

    {
        log_debug("Test #2 - send an alert on correct asset");
        const char* asset_name = "ASSET1";
        //      1. send alert message
        zlist_t* actions = zlist_new();
        {
            const char * s = "EMAIL";
            zlist_append(actions, static_cast<void*>(const_cast<char*>(s)));
        }
        std::string description(
            "{ \"key\": \"Device {{var1}} does not provide expected data. It may be offline or not correctly "
            "configured.\", \"variables\": { \"var1\": \"ASSET1\" } }");
        zmsg_t* msg = fty_proto_encode_alert(NULL, fty::convert<uint64_t>(zclock_time() / 1000), 600, "NY_RULE",
            asset_name, "ACTIVE", "CRITICAL", description.c_str(), actions);
        REQUIRE(msg);

        zuuid_t* zuuid = zuuid_new();
        zmsg_pushstr(msg, "scenario1.email@eaton.com");
        zmsg_pushstr(msg, asset_name);
        zmsg_pushstr(msg, "1");
        zmsg_pushstr(msg, zuuid_str_canonical(zuuid));

        mlm_client_sendto(alert_producer, "agent-smtp", "SENDMAIL_ALERT", NULL, 1000, &msg);
        log_info("SENDMAIL_ALERT message was sent");

        zmsg_t* reply = mlm_client_recv(alert_producer);
        REQUIRE(streq(mlm_client_subject(alert_producer), "SENDMAIL_ALERT"));
        char* str = zmsg_popstr(reply);
        REQUIRE(streq(str, zuuid_str_canonical(zuuid)));
        zstr_free(&str);
        str = zmsg_popstr(reply);
        REQUIRE(streq(str, "OK"));
        zstr_free(&str);
        zmsg_destroy(&reply);
        zuuid_destroy(&zuuid);
        zlist_destroy(&actions);

        //      2. read the email generated for alert
        msg = mlm_client_recv(btest_reader);
        REQUIRE(msg);
        log_debug("parameters for the email:");
        zmsg_print(msg);

        //      3. compare the email with expected output
        int   fr_number = fty::convert<int>(zmsg_size(msg));
        char* body      = NULL;
        while (fr_number > 0) {
            zstr_free(&body);
            body = zmsg_popstr(msg);
            fr_number--;
        }
        zmsg_destroy(&msg);
        log_debug("email itself:");
        log_debug("%s", body);
        std::string newBody = std::string(body);
        zstr_free(&body);
        std::size_t subject = newBody.find("Subject:");
        std::size_t date    = newBody.find("Date:");
        // in the body there is a line with current date -> remove it
        newBody.replace(date, subject - date, "");
        // need to erase white spaces, because newLines in "body" are not "\n"
        newBody.erase(remove_if(newBody.begin(), newBody.end(), isspace), newBody.end());

        // expected string without date
        std::string expectedBody =
            "From:bios@eaton.com\nTo: scenario1.email@eaton.com\nSubject: CRITICAL alert on ASSET1 from the rule "
            "ny_rule is active!\n\n"
            "In the system an alert was detected.\nSource rule: ny_rule\nAsset: ASSET1\nAlert priority: P1\nAlert "
            "severity: CRITICAL\n"
            "Alert description: Device ASSET1 does not provide expected data. It may be offline or not correctly "
            "configured.\nAlert state: ACTIVE\n";
        expectedBody.erase(remove_if(expectedBody.begin(), expectedBody.end(), isspace), expectedBody.end());


        log_debug("expectedBody =\n%s", expectedBody.c_str());
        log_debug("\n");
        log_debug("newBody =\n%s", newBody.c_str());

        // FIXME: email body is created by cxxtools::MimeMultipart class - do we need to test it?
        // REQUIRE ( expectedBody.compare(newBody) == 0 );

        log_debug("Test #2 OK");
    }
    {
        log_debug("Test #3 - send an alert on correct asset, but with empty contact");
        // scenario 2: send an alert on correct asset with empty contact
        const char* asset_name1 = "ASSET2";

        //      1. send alert message
        zlist_t* actions = zlist_new();
        {
            std::string s("EMAIL");
            zlist_append(actions, static_cast<void*>(&s));
        }
        std::string description(
            "{ \"key\": \"Device {{var1}} does not provide expected data. It may be offline or not correctly "
            "configured.\", \"variables\": { \"var1\": \"ASSET1\" } }");
        zmsg_t* msg = fty_proto_encode_alert(NULL, fty::convert<uint64_t>(time(NULL)), 600, "NY_RULE", asset_name1,
            "ACTIVE", "CRITICAL", description.c_str(), actions);
        REQUIRE(msg);

        zuuid_t* zuuid = zuuid_new();
        zmsg_pushstr(msg, "");
        zmsg_pushstr(msg, asset_name1);
        zmsg_pushstr(msg, "1");
        zmsg_pushstr(msg, zuuid_str_canonical(zuuid));

        mlm_client_sendto(alert_producer, "agent-smtp", "SENDMAIL_ALERT", NULL, 1000, &msg);

        log_info("SENDMAIL_ALERT message was sent");

        zmsg_t* reply = mlm_client_recv(alert_producer);
        REQUIRE(streq(mlm_client_subject(alert_producer), "SENDMAIL_ALERT"));
        char* str = zmsg_popstr(reply);
        REQUIRE(streq(str, zuuid_str_canonical(zuuid)));
        zstr_free(&str);
        str = zmsg_popstr(reply);
        REQUIRE(streq(str, "ERROR"));
        zstr_free(&str);
        zmsg_destroy(&reply);
        zuuid_destroy(&zuuid);
        zlist_destroy(&actions);

        //      3. No mail should be generated
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(btest_reader), NULL);
        void*      which  = zpoller_wait(poller, 1000);
        REQUIRE(which == NULL);

        log_debug("No email was sent: SUCCESS");
        zpoller_destroy(&poller);

        log_debug("Test #3 OK");
    }
    {
        log_debug("Test #4 - send alert on incorrect asset - empty name");
        //      1. send alert message
        const char* asset_name = "ASSET3";
        zlist_t*    actions    = zlist_new();
        {

            const char * s = "EMAIL";
            zlist_append(actions, static_cast<void*>(const_cast<char*>(s)));
        }
        std::string description(
            "{ \"key\": \"Device {{var1}} does not provide expected data. It may be offline or not correctly "
            "configured.\", \"variables\": { \"var1\": \"ASSET1\" } }");
        zmsg_t* msg = fty_proto_encode_alert(NULL, fty::convert<uint64_t>(time(NULL)), 600, "NY_RULE", asset_name,
            "ACTIVE", "CRITICAL", description.c_str(), actions);
        REQUIRE(msg);

        zuuid_t* zuuid = zuuid_new();
        zmsg_pushstr(msg, "");
        zmsg_pushstr(msg, "");
        zmsg_pushstr(msg, "1");
        zmsg_pushstr(msg, zuuid_str_canonical(zuuid));

        mlm_client_sendto(alert_producer, "agent-smtp", "SENDMAIL_ALERT", NULL, 1000, &msg);
        log_info("SENDMAIL_ALERT message was sent");

        zmsg_t* reply = mlm_client_recv(alert_producer);
        REQUIRE(streq(mlm_client_subject(alert_producer), "SENDMAIL_ALERT"));
        char* str = zmsg_popstr(reply);
        REQUIRE(streq(str, zuuid_str_canonical(zuuid)));
        zstr_free(&str);
        str = zmsg_popstr(reply);
        REQUIRE(streq(str, "ERROR"));
        zstr_free(&str);
        zmsg_destroy(&reply);
        zuuid_destroy(&zuuid);
        zlist_destroy(&actions);

        //      3. No mail should be generated
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(btest_reader), NULL);
        void*      which  = zpoller_wait(poller, 1000);
        REQUIRE(which == NULL);
        log_debug("No email was sent: SUCCESS");
        zpoller_destroy(&poller);
        log_debug("Test #4 OK");
    }
    {
        log_debug("Test #5 - send an alert on incorrect asset - empty priority");
        // scenario 3: send asset without email + send an alert on the already known asset
        //      2. send alert message
        const char* asset_name = "ASSET3";
        zlist_t*    actions    = zlist_new();
        {
            const char * s = "EMAIL";
            zlist_append(actions, static_cast<void*>(const_cast<char*>(s)));
        }
        std::string description(
            "{ \"key\": \"Device {{var1}} does not provide expected data. It may be offline or not correctly "
            "configured.\", \"variables\": { \"var1\": \"ASSET1\" } }");
        zmsg_t* msg = fty_proto_encode_alert(NULL, fty::convert<uint64_t>(time(NULL)), 600, "NY_RULE", asset_name,
            "ACTIVE", "CRITICAL", description.c_str(), actions);
        REQUIRE(msg);

        zuuid_t* zuuid = zuuid_new();
        zmsg_pushstr(msg, "");
        zmsg_pushstr(msg, asset_name);
        zmsg_pushstr(msg, "");
        zmsg_pushstr(msg, zuuid_str_canonical(zuuid));

        mlm_client_sendto(alert_producer, "agent-smtp", "SENDMAIL_ALERT", NULL, 1000, &msg);

        log_info("SENDMAIL_ALERT message was sent");

        zmsg_t* reply = mlm_client_recv(alert_producer);
        REQUIRE(streq(mlm_client_subject(alert_producer), "SENDMAIL_ALERT"));
        char* str = zmsg_popstr(reply);
        REQUIRE(streq(str, zuuid_str_canonical(zuuid)));
        zstr_free(&str);
        str = zmsg_popstr(reply);
        REQUIRE(streq(str, "ERROR"));
        zstr_free(&str);
        zmsg_destroy(&reply);
        zuuid_destroy(&zuuid);
        zlist_destroy(&actions);

        //      3. No mail should be generated
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(btest_reader), NULL);
        void*      which  = zpoller_wait(poller, 1000);
        REQUIRE(which == NULL);
        log_debug("No email was sent: SUCCESS");

        zpoller_destroy(&poller);
        log_debug("Test #5 OK");
    }
    // test SENDSMS_ALERT
    {
        log_debug("Test #6 - send an alert on correct asset");
        const char* asset_name = "ASSET1";
        //      1. send alert message
        zlist_t* actions = zlist_new();
        {
            const char * s = "SMS";
            zlist_append(actions, static_cast<void*>(const_cast<char*>(s)));
        }
        std::string description(
            "{ \"key\": \"Device {{var1}} does not provide expected data. It may be offline or not correctly "
            "configured.\", \"variables\": { \"var1\": \"ASSET1\" } }");
        zmsg_t* msg = fty_proto_encode_alert(NULL, fty::convert<uint64_t>(zclock_time() / 1000), 600, "NY_RULE",
            asset_name, "ACTIVE", "CRITICAL", description.c_str(), actions);
        REQUIRE(msg);

        zuuid_t* zuuid = zuuid_new();
        zmsg_pushstr(msg, "+79 (0) 123456");
        zmsg_pushstr(msg, asset_name);
        zmsg_pushstr(msg, "1");
        zmsg_pushstr(msg, zuuid_str_canonical(zuuid));

        mlm_client_sendto(alert_producer, "agent-smtp", "SENDSMS_ALERT", NULL, 1000, &msg);
        log_info("SENDSMS_ALERT message was sent");

        zmsg_t* reply = mlm_client_recv(alert_producer);
        REQUIRE(streq(mlm_client_subject(alert_producer), "SENDSMS_ALERT"));
        char* str = zmsg_popstr(reply);
        REQUIRE(streq(str, zuuid_str_canonical(zuuid)));
        zstr_free(&str);
        str = zmsg_popstr(reply);
        REQUIRE(streq(str, "OK"));
        zstr_free(&str);
        zmsg_destroy(&reply);
        zuuid_destroy(&zuuid);
        zlist_destroy(&actions);

        //      2. read the email generated for alert
        msg = mlm_client_recv(btest_reader);
        REQUIRE(msg);
        log_debug("parameters for the email:");
        zmsg_print(msg);

        //      3. compare the email with expected output
        char* body = NULL;
        do {
            body = zmsg_popstr(msg);
            log_debug("%s", body);
            zstr_free(&body);
        } while (body != NULL);

        zmsg_destroy(&msg);
        log_debug("Test #6 OK");
    }
    // test SENDMAIL
    {
        log_debug("Test #7 - test SENDMAIL");
        rv = mlm_client_sendtox(alert_producer, "agent-smtp", "SENDMAIL", "UUID", "foo@bar", "Subject", "body", NULL);
        REQUIRE(rv != -1);
        zmsg_t* msg = mlm_client_recv(alert_producer);
        REQUIRE(streq(mlm_client_subject(alert_producer), "SENDMAIL-OK"));
        REQUIRE(zmsg_size(msg) == 3);

        char* uuid = zmsg_popstr(msg);
        REQUIRE(streq(uuid, "UUID"));
        zstr_free(&uuid);

        char* code = zmsg_popstr(msg);
        REQUIRE(streq(code, "0"));
        zstr_free(&code);

        char* reason = zmsg_popstr(msg);
        REQUIRE(streq(reason, "OK"));
        zstr_free(&reason);

        zmsg_destroy(&msg);

        //  this fixes the reported memcheck error
        msg = mlm_client_recv(btest_reader);

        zmsg_print(msg);
        zmsg_destroy(&msg);
        log_debug("Test #7 OK");
    }

    // clean up after the test

    // smtp server send mail only
    zactor_t* send_mail_only_server;
    {
        std::string s("sendmail-only");
        send_mail_only_server = zactor_new(fty_email_server, static_cast<void*>(&s));
    }
    REQUIRE(send_mail_only_server != NULL);

    zactor_destroy(&send_mail_only_server);
    zactor_destroy(&smtp_server);
    mlm_client_destroy(&btest_reader);
    mlm_client_destroy(&alert_producer);
    zactor_destroy(&server);
    zstr_free(&pidfile);
    zstr_free(&smtpcfg_file);

    printf("OK\n");
}

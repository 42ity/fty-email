/*  =========================================================================
    fty_email_server - Email actor

    Copyright (C) 2014 - 2017 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/

/*
@header
    fty_email_server - Email actor
@discuss
@end
*/

int agent_smtp_verbose = true;

#define zsys_debug1(...) \
    do { if (agent_smtp_verbose) zsys_debug (__VA_ARGS__); } while (0);

#include "fty_email_classes.h"

#include <set>
#include <tuple>
#include <string>
#include <functional>
#include <algorithm>

#include "email.h"
#include "emailconfiguration.h"

static void
s_notify (
          Smtp& smtp,
          const std::string& priority,
          const std::string& extname,
          const std::string& contact,
          fty_proto_t *alert)
{
    if (priority.empty ())
        throw std::runtime_error ("Empty priority");
    else if (extname.empty ())
        throw std::runtime_error ("Empty asset name");
    else if (contact.empty ())
        throw std::runtime_error ("Empty contact");
    else
        smtp.sendmail(
                contact,
                generate_subject (alert, priority, extname),
                generate_body (alert, priority, extname)
                );
}

// return dfl is item is NULL or empty string!!
// smtp
//  user
//  password = ""
//
// will be treated the same way
static const char*
s_get (zconfig_t *config, const char* key, const char* dfl) {
    assert (config);

    char *ret = zconfig_get (config, key, dfl);
    if (!ret || streq (ret, ""))
        return dfl;
    return ret;
}

zmsg_t *
fty_email_encode (
        const char *uuid,
        const char *to,
        const char *subject,
        zhash_t *headers,
        const char *body,
        ...)
{

    assert (uuid);
    assert (to);
    assert (subject);
    assert (body);

    zmsg_t *msg = zmsg_new ();
    if (!msg)
        return NULL;

    zmsg_addstr (msg, uuid);
    zmsg_addstr (msg, to);
    zmsg_addstr (msg, subject);
    zmsg_addstr (msg, body);

    if (!headers) {
        zhash_t *headers = zhash_new ();
        zframe_t *frame = zhash_pack(headers);
        zmsg_append (msg, &frame);
        zhash_destroy (&headers);
    }
    else {
        zframe_t *frame = zhash_pack(headers);
        zmsg_append (msg, &frame);
    }

    va_list args;
    va_start (args, body);
    const char* path = va_arg (args, const char*);

    while (path) {
        zmsg_addstr (msg, path);
        path = va_arg (args, const char*);
    }

    va_end (args);

    return msg;
}

void
fty_email_server (zsock_t *pipe, void* args)
{
    bool sendmail_only = (args && streq ((char*) args, "sendmail-only"));
    bool verbose = false;
    char* name = NULL;
    char *endpoint = NULL;
    char *test_reader_name = NULL;
    char *sms_gateway = NULL;

    mlm_client_t *test_client = NULL;
    mlm_client_t *client = mlm_client_new ();
    bool client_connected = false;

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);

    Smtp smtp;

    std::set <std::tuple <std::string, std::string>> streams;
    bool producer = false;

    zsock_signal (pipe, 0);
    while ( !zsys_interrupted ) {

        void *which = zpoller_wait (poller, -1);

        if (which == pipe) {
            zsys_debug1 ("%s:\twhich == pipe", name);
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);
            zsys_debug1 ("%s:\tactor command=%s", name, cmd);

            if (streq (cmd, "$TERM")) {
                zsys_info ("Got $TERM");
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                break;
            }
            else
            if (streq (cmd, "VERBOSE")) {
                verbose = true;
                agent_smtp_verbose = true;
                zstr_free (&cmd);
            }
            else
            if (streq (cmd, "LOAD")) {
                char * config_file = zmsg_popstr (msg);
                zsys_debug1 ("(agent-smtp):\tLOAD: %s", config_file);

                zconfig_t *config = zconfig_load (config_file);
                if (!config) {
                    zsys_error ("Failed to load config file %s", config_file);
                    zstr_free (&config_file);
                    zstr_free (&cmd);
                    break;
                }

                // VERBOSE
                if (streq (zconfig_get (config, "server/verbose", "false"), "true")) {
                    verbose = true;
                    agent_smtp_verbose = true;
                }
                else {
                    verbose = false;
                    agent_smtp_verbose = false;
                }
                // SMS_GATEWAY
                if (s_get (config, "smtp/smsgateway", NULL)) {
                    sms_gateway = strdup (s_get (config, "smtp/smsgateway", NULL));
                }
                // MSMTP_PATH
                if (s_get (config, "smtp/msmtppath", NULL)) {
                    smtp.msmtp_path (s_get (config, "smtp/msmtppath", NULL));
                }

                // smtp
                if (s_get (config, "smtp/server", NULL)) {
                    smtp.host (s_get (config, "smtp/server", NULL));
                }
                if (s_get (config, "smtp/port", NULL)) {
                    smtp.port (s_get (config, "smtp/port", NULL));
                }

                const char* encryption = zconfig_get (config, "smtp/encryption", "NONE");
                if (   strcasecmp (encryption, "none") == 0
                    || strcasecmp (encryption, "tls") == 0
                    || strcasecmp (encryption, "starttls") == 0)
                    smtp.encryption (encryption);
                else
                    zsys_warning ("(agent-smtp): smtp/encryption has unknown value, got %s, expected (NONE|TLS|STARTTLS)", encryption);

                if (streq (s_get (config, "smtp/use_auth", "false"), "true")) {
                    if (s_get (config, "smtp/user", NULL)) {
                        smtp.username (s_get (config, "smtp/user", NULL));
                    }
                    if (s_get (config, "smtp/password", NULL)) {
                        smtp.password (s_get (config, "smtp/password", NULL));
                    }
                }

                if (s_get (config, "smtp/from", NULL)) {
                    smtp.from (s_get (config, "smtp/from", NULL));
                }

                // turn on verify_ca only if smtp/verify_ca is true
                smtp.verify_ca (streq (zconfig_get (config, "smtp/verify_ca", "false"), "true"));

                // malamute
                if (zconfig_get (config, "malamute/verbose", NULL)) {
                    const char* foo = zconfig_get (config, "malamute/verbose", "false");
                    bool mlm_verbose = foo[0] == '1' ? true : false;
                    mlm_client_set_verbose (client, mlm_verbose);
                }
                if (!client_connected) {
                    if (   zconfig_get (config, "malamute/endpoint", NULL)
                        && zconfig_get (config, "malamute/address", NULL)) {

                        zstr_free (&endpoint);
                        endpoint = strdup (zconfig_get (config, "malamute/endpoint", NULL));
                        zstr_free (&name);
                        name = strdup (zconfig_get (config, "malamute/address", "fty-email"));
                        if (sendmail_only) {
                            char *oldname = name;
                            name = zsys_sprintf ("%s-sendmail-only", oldname);
                            zstr_free (&oldname);
                        }
                        uint32_t timeout = 1000;
                        sscanf ("%" SCNu32, zconfig_get (config, "malamute/timeout", "1000"), &timeout);

                        zsys_debug1 ("%s: mlm_client_connect (%s, %" PRIu32 ", %s)", name, endpoint, timeout, name);
                        int r = mlm_client_connect (client, endpoint, timeout, name);
                        if (r == -1)
                            zsys_error ("%s: mlm_client_connect (%s, %" PRIu32 ", %s) = %d FAILED", name, endpoint, timeout, name, r);
                        else
                            client_connected = true;
                    }
                    else
                        zsys_warning ("(agent-smtp): malamute/endpoint or malamute/address not in configuration, NOT connected to the broker!");
                }

                // skip if sendmail_only
                if (!sendmail_only)
                {
                    if (zconfig_locate (config, "malamute/consumers"))
                    {
                        if (mlm_client_connected (client))
                        {
                            zconfig_t *consumers = zconfig_locate (config, "malamute/consumers");
                            for (zconfig_t *child = zconfig_child (consumers);
                                 child != NULL;
                                 child = zconfig_next (child))
                            {
                                const char* stream = zconfig_name (child);
                                const char* pattern = zconfig_value (child);
                                zsys_debug1 ("%s:\tstream/pattern=%s/%s", name, stream, pattern);

                                // check if we're already connected to not let replay log to explode :)
                                if (streams.count (std::make_tuple (stream, pattern)) == 1)
                                    continue;

                                int r = mlm_client_set_consumer (client, stream, pattern);
                                if (r == -1)
                                    zsys_warning ("%s:\tcannot subscribe on %s/%s", name, stream, pattern);
                                else
                                    streams.insert (std::make_tuple (stream, pattern));
                            }
                        }
                        else
                            zsys_warning ("(agent-smtp): client is not connected to broker, can't subscribe to the stream!");
                    }
                }

                if (zconfig_get (config, "malamute/producer", NULL)) {
                    if (!mlm_client_connected (client))
                        zsys_warning ("(agent-smtp): client is not connected to broker, can't publish on the stream!");
                    else
                    if (!producer) {
                        const char* stream = zconfig_get (config, "malamute/producer", NULL);
                        int r = mlm_client_set_producer (
                                client,
                                stream);
                        if (r == -1)
                            zsys_warning ("%s:\tcannot publish on %s", name, stream);
                        else
                            producer = true;
                    }
                }

                zconfig_destroy (&config);
                zstr_free (&config_file);
            }
            else
            if (streq (cmd, "_MSMTP_TEST")) {
                test_reader_name = zmsg_popstr (msg);
                test_client = mlm_client_new ();
                assert (test_client);
                assert (endpoint);
                int rv = mlm_client_connect (test_client, endpoint, 1000, "smtp-test-client");
                if (rv == -1) {
                    zsys_error ("%s\t:can't connect on test_client, endpoint=%s", name, endpoint);
                }
                std::function <void (const std::string &)> cb = \
                    [test_client, test_reader_name] (const std::string &data) {
                        mlm_client_sendtox (test_client, test_reader_name, "btest", data.c_str (), NULL);
                    };
                smtp.sendmail_set_test_fn (cb);
            }
            else
            {
                zsys_error ("unhandled command %s", cmd);
            }
            zstr_free (&cmd);
            zmsg_destroy (&msg);
            continue;
        }

        zsys_debug1 ("%s:\twhich == mlm_client", name);
        zmsg_t *zmessage = mlm_client_recv (client);
        if ( zmessage == NULL ) {
            zsys_debug1 ("%s:\tzmessage is NULL", name);
            continue;
        }
        std::string topic = mlm_client_subject(client);
        zsys_debug1("%s:\tsubject='%s'", name, topic.c_str());

        // TODO add SMTP settings
        if (streq (mlm_client_command (client), "MAILBOX DELIVER")) {

            zsys_debug1 ("%s:\tMAILBOX DELIVER, subject=%s", name, mlm_client_subject (client));

            char *uuid = zmsg_popstr (zmessage);
            if (!uuid) {
                zsys_error ("UUID frame is missing from zmessage, ignoring");
                zmsg_destroy (&zmessage);
                continue;
            }

            zmsg_t *reply = zmsg_new ();
            zmsg_addstr (reply, uuid);
            zstr_free (&uuid);

            if (topic == "SENDMAIL") {
                bool sent_ok = false;
                try {
                    if (zmsg_size (zmessage) == 1) {
                        char *body = zmsg_popstr (zmessage);
                        zsys_debug1 ("%s:\tsmtp.sendmail (%s)", name, body);
                        smtp.sendmail (body);
                        zstr_free (&body);
                    }
                    else {
                        if (verbose)
                            zmsg_print (zmessage);
                        auto mail = smtp.msg2email (&zmessage);
                        if (verbose)
                            zsys_debug (mail.c_str ());
                        smtp.sendmail (mail);
                    }
                    zmsg_addstr (reply, "0");
                    zmsg_addstr (reply, "OK");
                    sent_ok = true;
                }
                catch (const std::runtime_error &re) {
                    zsys_debug1 ("%s:\tgot std::runtime_error, e.what ()=%s", name, re.what ());
                    sent_ok = false;
                    uint32_t code = static_cast <uint32_t> (msmtp_stderr2code (re.what ()));
                    zmsg_addstrf (reply, "%" PRIu32, code);
                    zmsg_addstr (reply, re.what ());
                }

                int r = mlm_client_sendto (
                        client,
                        mlm_client_sender (client),
                        sent_ok ? "SENDMAIL-OK" : "SENDMAIL-ERR",
                        NULL,
                        1000,
                        &reply);
                if (r == -1)
                    zsys_error ("Can't send a reply for SENDMAIL to %s", mlm_client_sender (client));
            }
            else if (topic == "SENDMAIL_ALERT") {
                char *priority = zmsg_popstr (zmessage);
                char *extname = zmsg_popstr (zmessage);
                char *contact = zmsg_popstr (zmessage);
                fty_proto_t *alert = fty_proto_decode (&zmessage);
                try {
                    s_notify (smtp, priority, extname, contact, alert);
                    zmsg_addstr (reply, "OK");
                }
                catch (const std::runtime_error &re) {
                    zsys_error ("Sending of e-mail/SMS alert failed : %s", re.what ());
                    zmsg_addstr (reply, "ERROR");
                    zmsg_addstr (reply, re.what ());
                }
                int r = mlm_client_sendto (
                        client,
                        mlm_client_sender (client),
                        "SENDMAIL_ALERT",
                        NULL,
                        1000,
                        &reply);
                if (r == -1)
                    zsys_error ("Can't send a reply for SENDMAIL_ALERT to %s", mlm_client_sender (client));
                fty_proto_destroy (&alert);
                zstr_free (&contact);
                zstr_free (&extname);
                zstr_free (&priority);
            }
            else
                zsys_warning ("%s:\tUnknown subject %s", name, topic.c_str ());

            zmsg_destroy (&reply);
            zmsg_destroy (&zmessage);
            continue;
        }
    }

    zstr_free (&name);
    zstr_free (&endpoint);
    zstr_free (&test_reader_name);
    zstr_free (&sms_gateway);
    zpoller_destroy (&poller);
    mlm_client_destroy (&client);
    mlm_client_destroy (&test_client);
    zclock_sleep(1000);
}

//  Self test of this class
void
fty_email_server_test (bool verbose)
{
    // Note: If your selftest reads SCMed fixture data, please keep it in
    // src/selftest-ro; if your test creates filesystem objects, please
    // do so under src/selftest-rw. They are defined below along with a
    // usecase for the variables (assert) to make compilers happy.
    const char *SELFTEST_DIR_RO = "src/selftest-ro";
    const char *SELFTEST_DIR_RW = "src/selftest-rw";
    assert (SELFTEST_DIR_RO);
    assert (SELFTEST_DIR_RW);
    // Uncomment these to use C++ strings in C++ selftest code:
    // std::string str_SELFTEST_DIR_RO = std::string(SELFTEST_DIR_RO);
    // std::string str_SELFTEST_DIR_RW = std::string(SELFTEST_DIR_RW);
    // assert ( (str_SELFTEST_DIR_RO != "") );
    // assert ( (str_SELFTEST_DIR_RW != "") );
    // NOTE that for "char*" context you need (str_SELFTEST_DIR_RO + "/myfilename").c_str()

    char *pidfile = zsys_sprintf ("%s/btest.pid", SELFTEST_DIR_RW);
    assert (pidfile!=NULL);

    char *smtpcfg_file = zsys_sprintf ("%s/smtp.cfg", SELFTEST_DIR_RW);
    assert (smtpcfg_file!=NULL);

    printf (" * fty_email_server: ");
    if (zfile_exists (pidfile))
    {
        FILE *fp = fopen (pidfile, "r");
        assert (fp);
        int pid;
        int r = fscanf (fp, "%d", &pid);
        assert (r > 0); // make picky compilers happy
        fclose (fp);
        zsys_info ("about to kill -9 %d", pid);
        kill (pid, SIGKILL);
        unlink (pidfile);
    }

    //  @selftest

    {
        zsys_debug ("Test #1");
        zhash_t *headers = zhash_new ();
        zhash_update (headers, "Foo", (void*) "bar");
        char *file1_name = zsys_sprintf ("%s/file1", SELFTEST_DIR_RW);
        assert (file1_name!=NULL);
        char *file2_name = zsys_sprintf ("%s/file2.txt", SELFTEST_DIR_RW);
        assert (file2_name!=NULL);
        zmsg_t *email_msg = fty_email_encode (
                "UUID",
                "TO",
                "SUBJECT",
                headers,
                "BODY",
                file1_name,
                file2_name,
                NULL);
        assert (email_msg);
        assert (zmsg_size (email_msg) == 7);
        zhash_destroy (&headers);

        char *uuid = zmsg_popstr (email_msg);
        char *to = zmsg_popstr (email_msg);
        char *csubject = zmsg_popstr (email_msg);
        char *body = zmsg_popstr (email_msg);

        assert (streq (uuid, "UUID"));
        assert (streq (to, "TO"));
        assert (streq (csubject, "SUBJECT"));
        assert (streq (body, "BODY"));

        zstr_free (&uuid);
        zstr_free (&to);
        zstr_free (&csubject);
        zstr_free (&body);

        zframe_t *frame = zmsg_pop (email_msg);
        assert (frame);
        headers = zhash_unpack (frame);
        zframe_destroy (&frame);

        assert (streq ((char*)zhash_lookup (headers, "Foo"), "bar"));
        zhash_destroy (&headers);

        char *file1 = zmsg_popstr (email_msg);
        char *file2 = zmsg_popstr (email_msg);
        char *file3 = zmsg_popstr (email_msg);

        zsys_debug("Got file1='%s'\nExpected ='%s'", file1, file1_name );
        zsys_debug("Got file2='%s'\nExpected ='%s'", file2, file2_name );

        assert (streq (file1, file1_name ));
        assert (streq (file2, file2_name ));
        assert (!file3);

        zstr_free (&file1);
        zstr_free (&file2);
        zstr_free (&file1_name);
        zstr_free (&file2_name);
        zmsg_destroy (&email_msg);

        zsys_debug ("Test #1 OK");
    }

    static const char* endpoint = "inproc://fty-smtp-server-test";

    // malamute broker
    zactor_t *server = zactor_new (mlm_server, (void*) "Malamute");
    assert ( server != NULL );
    zstr_sendx (server, "BIND", endpoint, NULL);
    if ( verbose )
        zsys_info ("malamute started");

    // similar to create_test_smtp_server
    zactor_t *smtp_server = zactor_new (fty_email_server, NULL);
    assert ( smtp_server != NULL );

    zconfig_t *config = zconfig_new ("root", NULL);
    zconfig_put (config, "malamute/endpoint", endpoint);
    zconfig_put (config, "malamute/address", "agent-smtp");
    zconfig_save (config, smtpcfg_file);
    zconfig_destroy (&config);

    if (verbose)
        zstr_send (smtp_server, "VERBOSE");
    zstr_sendx (smtp_server, "LOAD", smtpcfg_file, NULL);
    zstr_sendx (smtp_server, "_MSMTP_TEST", "btest-reader", NULL);
    if ( verbose )
        zsys_info ("smtp server started");

    mlm_client_t *alert_producer = mlm_client_new ();
    int rv = mlm_client_connect (alert_producer, endpoint, 1000, "alert_producer");
    assert( rv != -1 );
    if ( verbose )
        zsys_info ("alert producer started");

    mlm_client_t *btest_reader = mlm_client_new ();
    rv = mlm_client_connect (btest_reader, endpoint, 1000, "btest-reader");
    assert( rv != -1 );

    {
        zsys_debug ("Test #2 - send an alert on correct asset");
        const char *asset_name = "ASSET1";
        //      1. send alert message
        zlist_t *actions = zlist_new ();
        zlist_add_end (actions, "EMAIL");
        zmsg_t *msg = fty_proto_encode_alert (NULL, zclock_time ()/1000, 600, "NY_RULE", asset_name, \
                                      "ACTIVE","CRITICAL","ASDFKLHJH", actions);
        assert (msg);

        zuuid_t *zuuid = zuuid_new ();
        zmsg_pushstr (msg, "scenario1.email@eaton.com");
        zmsg_pushstr (msg, asset_name);
        zmsg_pushstr (msg, "1");
        zmsg_pushstr (msg, zuuid_str_canonical (zuuid));

        mlm_client_sendto (alert_producer, "agent-smtp", "SENDMAIL_ALERT", NULL, 1000, &msg);
        if (verbose)
            zsys_info ("SENDMAIL_ALERT message was sent");

        zmsg_t *reply = mlm_client_recv (alert_producer);
        assert (streq (mlm_client_subject (alert_producer), "SENDMAIL_ALERT"));
        char *str = zmsg_popstr (reply);
        assert (streq (str, zuuid_str_canonical (zuuid)));
        zstr_free (&str);
        str = zmsg_popstr (reply);
        assert (streq (str, "OK"));
        zstr_free (&str);
        zmsg_destroy (&reply);
        zuuid_destroy (&zuuid);
        zlist_destroy (&actions);

        //      2. read the email generated for alert
        msg = mlm_client_recv (btest_reader);
        assert (msg);
        if ( verbose ) {
            zsys_debug ("parameters for the email:");
            zmsg_print (msg);
        }
        //      3. compare the email with expected output
        int fr_number = zmsg_size(msg);
        char *body = NULL;
        while ( fr_number > 0 ) {
            zstr_free(&body);
            body = zmsg_popstr(msg);
            fr_number--;
        }
        zmsg_destroy (&msg);
        if ( verbose ) {
            zsys_debug ("email itself:");
            zsys_debug ("%s", body);
        }
        std::string newBody = std::string (body);
        zstr_free(&body);
        std::size_t subject = newBody.find ("Subject:");
        std::size_t date = newBody.find ("Date:");
        // in the body there is a line with current date -> remove it
        newBody.replace (date, subject - date, "");
        // need to erase white spaces, because newLines in "body" are not "\n"
        newBody.erase(remove_if(newBody.begin(), newBody.end(), isspace), newBody.end());

        // expected string without date
        std::string expectedBody = "From:bios@eaton.com\nTo: scenario1.email@eaton.com\nSubject: CRITICAL alert on ASSET1 from the rule ny_rule is active!\n\n"
        "In the system an alert was detected.\nSource rule: ny_rule\nAsset: ASSET1\nAlert priority: P1\nAlert severity: CRITICAL\n"
        "Alert description: ASDFKLHJH\nAlert state: ACTIVE\n";
        expectedBody.erase(remove_if(expectedBody.begin(), expectedBody.end(), isspace), expectedBody.end());

        if (verbose) {
            zsys_debug ("expectedBody =\n%s", expectedBody.c_str ());
            zsys_debug ("\n");
            zsys_debug ("newBody =\n%s", newBody.c_str ());
        }
        //FIXME: email body is created by cxxtools::MimeMultipart class - do we need to test it?
        //assert ( expectedBody.compare(newBody) == 0 );

        zsys_debug ("Test #2 OK");
    }
    {
        zsys_debug ("Test #3 - send an alert on correct asset, but with empty contact");
        // scenario 2: send an alert on correct asset with empty contact
        const char *asset_name1 = "ASSET2";

        //      1. send alert message
        zlist_t *actions = zlist_new ();
        zlist_add_end (actions, "EMAIL");
        zmsg_t *msg = fty_proto_encode_alert (NULL, time (NULL), 600, "NY_RULE", asset_name1, \
                                      "ACTIVE","CRITICAL","ASDFKLHJH", actions);
        assert (msg);

        zuuid_t *zuuid = zuuid_new ();
        zmsg_pushstr (msg, "");
        zmsg_pushstr (msg, asset_name1);
        zmsg_pushstr (msg, "1");
        zmsg_pushstr (msg, zuuid_str_canonical (zuuid));

        mlm_client_sendto (alert_producer, "agent-smtp", "SENDMAIL_ALERT", NULL, 1000, &msg);
        if (verbose)
            zsys_info ("SENDMAIL_ALERT message was sent");

        zmsg_t *reply = mlm_client_recv (alert_producer);
        assert (streq (mlm_client_subject (alert_producer), "SENDMAIL_ALERT"));
        char *str = zmsg_popstr (reply);
        assert (streq (str, zuuid_str_canonical (zuuid)));
        zstr_free (&str);
        str = zmsg_popstr (reply);
        assert (streq (str, "ERROR"));
        zstr_free (&str);
        zmsg_destroy (&reply);
        zuuid_destroy (&zuuid);
        zlist_destroy (&actions);

        //      3. No mail should be generated
        zpoller_t *poller = zpoller_new (mlm_client_msgpipe(btest_reader), NULL);
        void *which = zpoller_wait (poller, 1000);
        assert ( which == NULL );
        if ( verbose ) {
            zsys_debug ("No email was sent: SUCCESS");
        }
        zpoller_destroy (&poller);

        zsys_debug ("Test #3 OK");
    }
    {
        zsys_debug ("Test #4 - send alert on incorrect asset - empty name");
        //      1. send alert message
        const char *asset_name = "ASSET3";
        zlist_t *actions = zlist_new ();
        zlist_add_end (actions, "EMAIL");
        zmsg_t *msg = fty_proto_encode_alert (NULL, time (NULL), 600, "NY_RULE", asset_name, \
                                      "ACTIVE","CRITICAL","ASDFKLHJH", actions);
        assert (msg);

        zuuid_t *zuuid = zuuid_new ();
        zmsg_pushstr (msg, "");
        zmsg_pushstr (msg, "");
        zmsg_pushstr (msg, "1");
        zmsg_pushstr (msg, zuuid_str_canonical (zuuid));

        mlm_client_sendto (alert_producer, "agent-smtp", "SENDMAIL_ALERT", NULL, 1000, &msg);
        if (verbose)
            zsys_info ("SENDMAIL_ALERT message was sent");

        zmsg_t *reply = mlm_client_recv (alert_producer);
        assert (streq (mlm_client_subject (alert_producer), "SENDMAIL_ALERT"));
        char *str = zmsg_popstr (reply);
        assert (streq (str, zuuid_str_canonical (zuuid)));
        zstr_free (&str);
        str = zmsg_popstr (reply);
        assert (streq (str, "ERROR"));
        zstr_free (&str);
        zmsg_destroy (&reply);
        zuuid_destroy (&zuuid);
        zlist_destroy (&actions);

        //      3. No mail should be generated
        zpoller_t *poller = zpoller_new (mlm_client_msgpipe(btest_reader), NULL);
        void *which = zpoller_wait (poller, 1000);
        assert ( which == NULL );
        if ( verbose ) {
            zsys_debug ("No email was sent: SUCCESS");
        }
        zpoller_destroy (&poller);
        zsys_debug ("Test #4 OK");
    }
    {
        zsys_debug ("Test #5 - send an alert on incorrect asset - empty priority");
        // scenario 3: send asset without email + send an alert on the already known asset
        //      2. send alert message
        const char *asset_name = "ASSET3";
        zlist_t *actions = zlist_new ();
        zlist_add_end (actions, "EMAIL");
        zmsg_t *msg = fty_proto_encode_alert (NULL, time (NULL), 600, "NY_RULE", asset_name, \
                                      "ACTIVE","CRITICAL","ASDFKLHJH", actions);
        assert (msg);

        zuuid_t *zuuid = zuuid_new ();
        zmsg_pushstr (msg, "");
        zmsg_pushstr (msg, asset_name);
        zmsg_pushstr (msg, "");
        zmsg_pushstr (msg, zuuid_str_canonical (zuuid));

        mlm_client_sendto (alert_producer, "agent-smtp", "SENDMAIL_ALERT", NULL, 1000, &msg);
        if (verbose)
            zsys_info ("SENDMAIL_ALERT message was sent");

        zmsg_t *reply = mlm_client_recv (alert_producer);
        assert (streq (mlm_client_subject (alert_producer), "SENDMAIL_ALERT"));
        char *str = zmsg_popstr (reply);
        assert (streq (str, zuuid_str_canonical (zuuid)));
        zstr_free (&str);
        str = zmsg_popstr (reply);
        assert (streq (str, "ERROR"));
        zstr_free (&str);
        zmsg_destroy (&reply);
        zuuid_destroy (&zuuid);
        zlist_destroy (&actions);

        //      3. No mail should be generated
        zpoller_t *poller = zpoller_new (mlm_client_msgpipe(btest_reader), NULL);
        void *which = zpoller_wait (poller, 1000);
        assert ( which == NULL );
        if ( verbose ) {
            zsys_debug ("No email was sent: SUCCESS");
        }
        zpoller_destroy (&poller);
        zsys_debug ("Test #5 OK");
    }
    //test SENDMAIL
    {
        zsys_debug ("Test #6 - test SENDMAIL");
        rv = mlm_client_sendtox (alert_producer, "agent-smtp", "SENDMAIL", "UUID", "foo@bar", "Subject", "body", NULL);
        assert (rv != -1);
        zmsg_t *msg = mlm_client_recv (alert_producer);
        assert (streq (mlm_client_subject (alert_producer), "SENDMAIL-OK"));
        assert (zmsg_size (msg) == 3);

        char *uuid = zmsg_popstr (msg);
        assert (streq (uuid, "UUID"));
        zstr_free (&uuid);

        char *code = zmsg_popstr (msg);
        assert (streq (code, "0"));
        zstr_free (&code);

        char *reason = zmsg_popstr (msg);
        assert (streq (reason, "OK"));
        zstr_free (&reason);

        zmsg_destroy (&msg);

        //  this fixes the reported memcheck error
        msg = mlm_client_recv (btest_reader);
        if (verbose)
            zmsg_print (msg);
        zmsg_destroy (&msg);
        zsys_debug ("Test #6 OK");
    }

    // clean up after the test

    // smtp server send mail only
    zactor_t *send_mail_only_server = zactor_new (fty_email_server, (void*) "sendmail-only");
    assert ( send_mail_only_server != NULL );

    if (verbose)
    {
        zsys_info ("smtp-sedmail-only server started");
        zstr_send (send_mail_only_server, "VERBOSE");
    }

    zactor_destroy(&send_mail_only_server);
    zactor_destroy (&smtp_server);
    mlm_client_destroy (&btest_reader);
    mlm_client_destroy (&alert_producer);
    zactor_destroy (&server);
    zstr_free (&pidfile);
    zstr_free (&smtpcfg_file);

    printf ("OK\n");
}

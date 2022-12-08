/*  =========================================================================
    fty_email_server - Email actor

    Copyright (C) 2014 - 2020 Eaton

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

/// Email actor

#include "fty_email_server.h"
#include "email.h"
#include "emailconfiguration.h"
#include "fty_email.h"
#include "fty_email_audit_log.h"
#include <fty_common_quote_codec.h>
#include <algorithm>
#include <fty/convert.h>
#include <fty_common_macros.h>
#include <fty_common_mlm.h>
#include <fty_common_translation.h>
#include <set>
#include <tuple>

static void s_notify(
    Smtp& smtp, const std::string& priority, const std::string& extname, const std::string& contact, fty_proto_t* alert)
{
    if (priority.empty())
        throw std::runtime_error("Empty priority");
    else if (extname.empty())
        throw std::runtime_error("Empty asset name");
    else if (contact.empty())
        throw std::runtime_error("Empty contact");
    else
        smtp.sendmail(contact, generate_subject(alert, priority, extname), generate_body(alert, priority, extname));
}

/// return dfl is item is NULL or empty string!!
/// smtp
///  user
///  password = ""
///
/// will be treated the same way
static const char* s_get(zconfig_t* config, const char* key, const char* dfl)
{
    assert(config);

    char* ret = zconfig_get(config, key, dfl);
    if (!ret || streq(ret, ""))
        return dfl;

    return ret;
}

zmsg_t* fty_email_encode(const char* uuid, const char* to, const char* subject, zhash_t* headers, const char* body, ...)
{
    assert(uuid);
    assert(to);
    assert(subject);
    assert(body);

    zmsg_t* msg = zmsg_new();
    if (!msg)
        return NULL;

    zmsg_addstr(msg, uuid);
    zmsg_addstr(msg, to);
    zmsg_addstr(msg, subject);
    zmsg_addstr(msg, body);

    if (!headers) {
        headers         = zhash_new();
        zframe_t* frame = zhash_pack(headers);
        zmsg_append(msg, &frame);
        zhash_destroy(&headers);
    } else {
        zframe_t* frame = zhash_pack(headers);
        zmsg_append(msg, &frame);
    }

    va_list args;
    va_start(args, body);
    const char* path = va_arg(args, const char*);

    while (path) {
        zmsg_addstr(msg, path);
        path = va_arg(args, const char*);
    }

    va_end(args);

    return msg;
}

// make the message more human readable (displayed in UI)
static std::string humanReadableErrorMessage(const std::string& msg)
{
    // tokens substitution (in order)
    struct {
        std::string occurency;
        std::string substitute;
    } const tokens[] = {
        {"\n\n", ". "},
        {"\n", ""},
        {"stderr: ", ""},
        {"/usr/bin/msmtp", "msmtp"},
        {"msmtp", " Command"},
    };

    std::string aux{msg};
    for (auto& token : tokens) {
        std::size_t pos;
        while((pos = aux.find(token.occurency)) != std::string::npos) {
            aux.replace(pos, token.occurency.length(), token.substitute);
        }
    }

    return aux;
}

void fty_email_server(zsock_t* pipe, void* args)
{
    bool  sendmail_only    = (args && streq(static_cast<char*>(args), "sendmail-only"));
    char* name             = NULL;
    char* endpoint         = NULL;
    char* test_reader_name = NULL;
    char* sms_gateway      = NULL;
    char* gw_template      = NULL;
    char* language         = NULL;

    mlm_client_t* test_client      = NULL;
    mlm_client_t* client           = mlm_client_new();
    bool          client_connected = false;

    zpoller_t* poller = zpoller_new(pipe, mlm_client_msgpipe(client), NULL);

    Smtp smtp;

    std::set<std::tuple<std::string, std::string>> streams;
    bool                                           producer = false;

    log_info("fty_email_server started (sendmail_only: %s)", (sendmail_only ? "true" : "false"));

    zsock_signal(pipe, 0);
    while (!zsys_interrupted) {

        void* which = zpoller_wait(poller, -1);

        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char*   cmd = zmsg_popstr(msg);
            log_debug("%s:\tactor command=%s", name, cmd);

            if (streq(cmd, "$TERM")) {
                log_info("Got $TERM");
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                break;
            } else if (streq(cmd, "LOAD")) {
                char* config_file = zmsg_popstr(msg);
                log_debug("(agent-smtp):\tLOAD: %s", config_file);

                zconfig_t* config = zconfig_load(config_file);
                if (!config) {
                    log_error("Failed to load config file %s", config_file);
                    zstr_free(&config_file);
                    zstr_free(&cmd);
                    break;
                }

                // reset SMTP server to default
                smtp.initialize();

                if (s_get(config, "server/language", DEFAULT_LANGUAGE)) {
                    zstr_free(&language);
                    language = strdup(s_get(config, "server/language", DEFAULT_LANGUAGE));
                    int rv   = translation_change_language(language);
                    if (rv != TE_OK)
                        log_warning("Language not changed to %s, continuing in %s", language, DEFAULT_LANGUAGE);
                }
                // SMS_GATEWAY
                if (s_get(config, "smtp/smsgateway", NULL)) {
                    zstr_free(&sms_gateway);
                    sms_gateway = strdup(s_get(config, "smtp/smsgateway", NULL));
                }
                if (s_get(config, "smtp/gwtemplate", NULL)) {
                    zstr_free(&gw_template);
                    gw_template = strdup(s_get(config, "smtp/gwtemplate", ""));
                }
                // MSMTP_PATH
                if (s_get(config, "smtp/msmtppath", NULL)) {
                    smtp.msmtp_path(s_get(config, "smtp/msmtppath", NULL));
                }

                // smtp
                if (s_get(config, "smtp/server", NULL)) {
                    smtp.host(s_get(config, "smtp/server", NULL));
                }
                if (s_get(config, "smtp/port", NULL)) {
                    smtp.port(s_get(config, "smtp/port", NULL));
                }

                const char* encryption = zconfig_get(config, "smtp/encryption", "NONE");
                if (strcasecmp(encryption, "none") == 0 || strcasecmp(encryption, "tls") == 0 ||
                    strcasecmp(encryption, "starttls") == 0) {
                    smtp.encryption(encryption);
                }
                else {
                    log_warning("(agent-smtp): smtp/encryption has unknown value, got %s, expected (NONE|TLS|STARTTLS)",
                        encryption);
                    log_warning("(agent-smtp): smtp/encryption set to 'NONE'");
                    smtp.encryption("none");
                }

                if (streq(s_get(config, "smtp/use_auth", "false"), "true")) {
                    if (s_get(config, "smtp/user", NULL)) {
                        std::string user(s_get(config, "smtp/user", NULL));
                        smtp.username(quotecodec::quoteDecode(user));
                    }
                    if (s_get(config, "smtp/password", NULL)) {
                        std::string pass(s_get(config, "smtp/password", NULL));
                        smtp.password(quotecodec::quoteDecode(pass));
                    }
                }

                if (s_get(config, "smtp/from", NULL)) {
                    smtp.from(s_get(config, "smtp/from", NULL));
                }

                // turn on verify_ca only if smtp/verify_ca is true
                smtp.verify_ca(streq(zconfig_get(config, "smtp/verify_ca", "false"), "true"));

                // malamute
                if (zconfig_get(config, "malamute/verbose", NULL)) {
                    const char* foo         = zconfig_get(config, "malamute/verbose", "false");
                    bool        mlm_verbose = foo[0] == '1' ? true : false;
                    mlm_client_set_verbose(client, mlm_verbose);
                }
                if (!client_connected) {
                    if (zconfig_get(config, "malamute/endpoint", NULL) &&
                        zconfig_get(config, "malamute/address", NULL)) {

                        zstr_free(&endpoint);
                        endpoint = strdup(zconfig_get(config, "malamute/endpoint", NULL));
                        zstr_free(&name);
                        name = strdup(zconfig_get(config, "malamute/address", "fty-email"));
                        if (sendmail_only) {
                            char* oldname = name;
                            name          = zsys_sprintf("%s-sendmail-only", oldname);
                            zstr_free(&oldname);
                        }
                        uint32_t timeout = fty::convert<uint32_t>(zconfig_get(config, "malamute/timeout", "1000"));
                        // sscanf("%" SCNu32, zconfig_get(config, "malamute/timeout", "1000"), &timeout);

                        log_debug("%s: mlm_client_connect (%s, %" PRIu32 ", %s)", name, endpoint, timeout, name);
                        int r = mlm_client_connect(client, endpoint, timeout, name);
                        if (r == -1)
                            log_error("%s: mlm_client_connect (%s, %" PRIu32 ", %s) = %d FAILED", name, endpoint,
                                timeout, name, r);
                        else
                            client_connected = true;
                    } else
                        log_warning(
                            "(agent-smtp): malamute/endpoint or malamute/address not in configuration, NOT connected "
                            "to the broker!");
                }

                // skip if sendmail_only
                if (!sendmail_only) {
                    if (zconfig_locate(config, "malamute/consumers")) {
                        if (mlm_client_connected(client)) {
                            zconfig_t* consumers = zconfig_locate(config, "malamute/consumers");
                            for (zconfig_t* child = zconfig_child(consumers); child != NULL;
                                 child            = zconfig_next(child)) {
                                const char* stream  = zconfig_name(child);
                                const char* pattern = zconfig_value(child);
                                log_debug("%s:\tstream/pattern=%s/%s", name, stream, pattern);

                                // check if we're already connected to not let replay log to explode :)
                                if (streams.count(std::make_tuple(stream, pattern)) == 1)
                                    continue;

                                int r = mlm_client_set_consumer(client, stream, pattern);
                                if (r == -1)
                                    log_warning("%s:\tcannot subscribe on %s/%s", name, stream, pattern);
                                else
                                    streams.insert(std::make_tuple(stream, pattern));
                            }
                        } else
                            log_warning(
                                "(agent-smtp): client is not connected to broker, can't subscribe to the stream!");
                    }
                }

                if (zconfig_get(config, "malamute/producer", NULL)) {
                    if (!mlm_client_connected(client))
                        log_warning("(agent-smtp): client is not connected to broker, can't publish on the stream!");
                    else if (!producer) {
                        const char* stream = zconfig_get(config, "malamute/producer", NULL);
                        int         r      = mlm_client_set_producer(client, stream);
                        if (r == -1)
                            log_warning("%s:\tcannot publish on %s", name, stream);
                        else
                            producer = true;
                    }
                }

                zconfig_destroy(&config);
                zstr_free(&config_file);
            } else if (streq(cmd, "_MSMTP_TEST")) {
                test_reader_name = zmsg_popstr(msg);
                test_client      = mlm_client_new();
                assert(test_client);
                assert(endpoint);
                int rv = mlm_client_connect(test_client, endpoint, 1000, "smtp-test-client");
                if (rv == -1) {
                    log_error("%s\t:can't connect on test_client, endpoint=%s", name, endpoint);
                }
                std::function<void(const std::string&)> cb = [test_client, test_reader_name](const std::string& data) {
                    mlm_client_sendtox(test_client, test_reader_name, "btest", data.c_str(), NULL);
                };
                smtp.sendmail_set_test_fn(cb);
            } else {
                log_error("unhandled command %s", cmd);
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg);
            continue;
        }

        zmsg_t* zmessage = mlm_client_recv(client);
        if (zmessage == NULL) {
            log_debug("%s:\tzmessage is NULL", name);
            continue;
        }
        std::string from = mlm_client_sender(client);
        std::string topic = mlm_client_subject(client);

        // TODO add SMTP settings
        if (streq(mlm_client_command(client), "MAILBOX DELIVER"))
        {
            log_debug("%s:\tMAILBOX DELIVER, from=%s, subject=%s", name, from.c_str(), topic.c_str());

            char* uuid = zmsg_popstr(zmessage);
            if (!uuid) {
                log_error("UUID frame is missing from zmessage, ignoring");
                zmsg_destroy(&zmessage);
                continue;
            }

            zmsg_t* reply = zmsg_new();
            zmsg_addstr(reply, uuid); // common first frame of reply
            zstr_free(&uuid);

            if (topic == "SENDMAIL")
            {
                bool sent_ok = false;
                try {
                    if (zmsg_size(zmessage) == 1) {
                        std::string body = getIpAddr();
                        ZstrGuard   bodyTemp(zmsg_popstr(zmessage));
                        body += bodyTemp.get();
                        log_debug("%s:\tsmtp.sendmail (%s)", name, body.c_str());
                        log_debug_email_audit("%s: Send email: %s", name, body.c_str());
                        smtp.sendmail(body);
                    } else {
                        zmsg_print(zmessage);
                        auto mail = smtp.msg2email(&zmessage);
                        log_debug("%s:\tSend email: %s", name, mail.c_str());
                        log_debug_email_audit("%s: Send email: %s", name, mail.c_str());
                        smtp.sendmail(mail);
                    }

                    zmsg_addstr(reply, "0");
                    zmsg_addstr(reply, "OK");
                    sent_ok = true;
                }
                catch (const std::runtime_error& re) {
                    log_debug("%s:\tgot std::runtime_error, e.what ()=%s", name, re.what());
                    log_error_email_audit("%s: Send email error: %s", name, re.what ());

                    uint32_t code = static_cast<uint32_t>(msmtp_stderr2code(re.what()));
                    auto errMsg = humanReadableErrorMessage(re.what());

                    zmsg_addstrf(reply, "%" PRIu32, code);
                    zmsg_addstr(reply, UTF8::escape(errMsg.c_str()).c_str());
                    sent_ok = false;
                }

                log_debug("%s:\t%s Send mail %s", name, topic.c_str(), (sent_ok ? "SUCCESS" : "FAILED"));
                if (sent_ok) {
                    log_info_email_audit("%s: Send email ok", name);
                }

                int r = mlm_client_sendto(client, mlm_client_sender(client),
                    sent_ok ? "SENDMAIL-OK" : "SENDMAIL-ERR", NULL, 1000, &reply);
                if (r == -1) {
                    log_error("Can't send a reply for SENDMAIL to %s", mlm_client_sender(client));
                }
            }
            else if (topic == "SENDMAIL_ALERT" || topic == "SENDSMS_ALERT")
            {
                char*        priority          = zmsg_popstr(zmessage);
                char*        extname           = zmsg_popstr(zmessage);
                char*        contact           = zmsg_popstr(zmessage);
                fty_proto_t* alert             = fty_proto_decode(&zmessage);
                const char*  rule              = alert ? fty_proto_rule(alert) : "";

                log_debug("alert (rule: %s, extname: %s, contact: %s)", rule, extname, contact);

                std::string  gateway           = gw_template == NULL ? "" : gw_template;
                std::string  converted_contact = contact ? contact : "";
                std::string audit_contact = converted_contact;
                bool sent_ok = false;
                try {
                    if (topic == "SENDSMS_ALERT") {
                        log_debug("gw_template = %s", gw_template);
                        log_debug("contact = %s", contact);
                        std::string _contact = sms_email_address(gateway, converted_contact);
                        audit_contact = _contact;
                        s_notify(smtp, priority, extname, _contact, alert);
                    } else {
                        s_notify(smtp, priority, extname, converted_contact, alert);
                    }

                    zmsg_addstr(reply, "OK");
                    sent_ok = true;
                }
                catch (const std::exception& re) {
                    log_error("Sending of e-mail/SMS alert failed : %s", re.what());
                    if (!audit_contact.empty()) {
                        // Workaround for unwanted logs: log audit only if contact is not empty
                        log_error_email_audit("%s: Send email/SMS alert error (gateway=%s contact=%s extname=%s alert=%s): %s",
                            name, gateway.c_str(), audit_contact.c_str(), (extname ? extname : ""), rule, re.what ());
                    }

                    zmsg_addstr(reply, "ERROR");
                    zmsg_addstr(reply, re.what());
                    sent_ok = false;
                }

                log_debug("%s:\t%s Send mail %s", name, topic.c_str(), (sent_ok ? "SUCCESS" : "FAILED"));
                if (sent_ok) {
                    log_info_email_audit("%s: Send email/SMS alert OK: (gateway=%s contact=%s extname=%s alert=%s)",
                        name, gateway.c_str(), audit_contact.c_str(), (extname ? extname : ""), rule);
                }

                int r = mlm_client_sendto(client, mlm_client_sender(client), topic.c_str(), NULL, 1000, &reply);
                if (r == -1) {
                    log_error("Can't send a reply for SENDMAIL_ALERT to %s", mlm_client_sender(client));
                }

                fty_proto_destroy(&alert);
                zstr_free(&contact);
                zstr_free(&extname);
                zstr_free(&priority);
            }
            else
            {
                log_warning("%s:\tUnknown subject %s", name, topic.c_str());
            }

            zmsg_destroy(&reply);
            zmsg_destroy(&zmessage);
            continue;
        }

        zmsg_destroy(&zmessage);
    }

    log_info("%s:\tfty_email_server ended", name);

    zstr_free(&name);
    zstr_free(&endpoint);
    zstr_free(&test_reader_name);
    zstr_free(&sms_gateway);
    zstr_free(&gw_template);
    zstr_free(&language);
    zpoller_destroy(&poller);
    mlm_client_destroy(&client);
    mlm_client_destroy(&test_client);
    zclock_sleep(1000);
}

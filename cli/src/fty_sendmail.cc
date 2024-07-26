/*  =========================================================================
    fty_sendmail - Sendmail-like interface for 42ity

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

/*
@header
    fty_sendmail - Sendmail-like interface for 42ity
@discuss

    Usage:
    printf 'From:myself\nSubject:subject\n\nbody' | fty-sendmail joe@example.com\n

    Tools needs fty-email configured and running. See man fty_email_server and fty-email

@end
*/

#include "fty_email.h"
#include "fty_email_server.h"

#include <fty_log.h>
#include <fty_common_mlm.h>
#include <getopt.h>
#include <vector>
#include <string>
#include <iostream>

void usage()
{
    puts(
        "Usage: fty-sendmail [options] addr < message\n"
        "  -c|--config           path to fty-email config file\n"
        "  -s|--subject          mail subject\n"
        "  -a|--attachment       path to file to be attached to email\n"
        "Send email through fty-email to given recipients in email body.\n"
        "Email body is read from stdin\n"
        "\n"
        "echo -e \"This is a testing email.\\n\\nyour team\" | fty-sendmail -s text -a ./myfile.tgz joe@example.com\n");
}

int main(int argc, char** argv)
{
    int help    = 0;
    int verbose = 0;
    std::string config_file;

    std::string              subject;
    std::vector<std::string> attachments;
    const char*              recipient = nullptr;

    ManageFtyLog::setInstanceFtylog(FTY_EMAIL_ADDRESS_SENDMAIL_ONLY, FTY_COMMON_LOGGING_DEFAULT_CFG);

    // get options

// Some systems define struct option with non-"const" "char *"
#if defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
#endif
    static const char* short_options  = "vc:s:a:";
    static struct option long_options[] = {
        {"help", no_argument, &help, 1},
        {"verbose", no_argument, &verbose, 1},
        {"config", required_argument, 0, 'c'},
        {"subject", required_argument, 0, 's'},
        {"attachment", required_argument, 0, 'a'},
        {NULL, 0, 0, 0}
    };
#if defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic pop
#endif

    while (true) {
        int option_index = 0;
        int c = getopt_long(argc, argv, short_options, long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'v':
                verbose = 1;
                break;
            case 'c':
                config_file = optarg;
                break;
            case 'a':
                char path[PATH_MAX + 1];
                if (!realpath(optarg, path)) {
                    log_error("Can't get absolute path for %s: %s", optarg, strerror(errno));
                    return EXIT_FAILURE;
                }
                attachments.push_back(path);
                break;
            case 's':
                subject = optarg;
                break;
            case 0:
                // just now walking trough some long opt
                break;
            case 'h':
            default:
                help = 1;
                break;
        }
    }

    if (optind < argc) {
        recipient = argv[optind];
        ++optind;
    }

    if (help || recipient == nullptr || optind < argc) {
        usage();
        return EXIT_FAILURE;
    }
    // end of the options

    char* endpoint = strdup(MLM_ENDPOINT); // mlm endpoint
    char* fty_email_address = strdup(FTY_EMAIL_ADDRESS); // fty-email agent
    char* address = zsys_sprintf("fty-sendmail.%d", getpid()); // client

    #define CLEANUP { \
        zstr_free(&address); \
        zstr_free(&endpoint); \
        zstr_free(&fty_email_address); \
    }

    if (!config_file.empty()) {
        log_debug("Loading conf. file (%s)", config_file.c_str());
        zconfig_t* config = zconfig_load(config_file.c_str());
        if (!config) {
            log_error("Failed to load %s: %m", config_file.c_str());
            CLEANUP;
            return EXIT_FAILURE;
        }

        char* aux = zconfig_get(config, "malamute/endpoint", nullptr);
        if (aux) {
            zstr_free(&endpoint);
            endpoint = strdup(aux);
        }
        aux = zconfig_get(config, "malamute/address", nullptr);
        if (aux) {
            zstr_free(&fty_email_address);
            fty_email_address = strdup(aux);
        }

        zconfig_destroy(&config);
    }

    if (verbose) {
        ManageFtyLog::getInstanceFtylog()->setVerboseMode();
    }

    log_debug("endpoint='%s', address='%s', fty_email_address='%s'", endpoint, address, fty_email_address);

    mlm_client_t* client = mlm_client_new();
    if (!client) {
        log_error("Failed to create client.");
        CLEANUP;
        return EXIT_FAILURE;
    }

    int r = mlm_client_connect(client, endpoint, 1000, address);
    if (r == -1) {
        log_error("Failed to connect.");
        mlm_client_destroy(&client);
        CLEANUP;
        return EXIT_FAILURE;
    }

    log_debug("Encoding email...");

    std::istreambuf_iterator<char> begin(std::cin), end;
    std::string body(begin, end);
    zmsg_t* mail = fty_email_encode("UUID", recipient, subject.c_str(), nullptr, body.c_str(), nullptr);

    for (const auto& file : attachments) {
        zmsg_addstr(mail, file.c_str());
    }
    zmsg_print(mail);

    log_debug("Sending email (fty_email_address: '%s')...", fty_email_address);

    r = mlm_client_sendto(client, fty_email_address, "SENDMAIL", nullptr, 5000, &mail);
    zmsg_destroy(&mail);

    log_trace("mlm_client_sendto(), r: %d", r);

    if (r != 0) {
        log_error("Failed to send the email (mlm_client_sendto() returned %d)", r);
        mlm_client_destroy(&client);
        CLEANUP;
        return EXIT_FAILURE;
    }

    log_trace("mlm_client_recv()...");

    zpoller_t* poller = zpoller_new(mlm_client_msgpipe(client), NULL);
    zmsg_t* msg = (poller && zpoller_wait(poller, 20000)) ? mlm_client_recv(client) : NULL;
    zpoller_destroy(&poller);

    if (!msg) {
        log_error("Recv response is NULL.");
        mlm_client_destroy(&client);
        CLEANUP;
        return EXIT_FAILURE;
    }

    char* uuid = zmsg_popstr(msg);
    zstr_free(&uuid); // ignored

    char* code = zmsg_popstr(msg);
    char* reason = zmsg_popstr(msg);
    zmsg_destroy(&msg);

    int exit_code = EXIT_SUCCESS; // default
    if (!code || (code[0] != '0')) {
        exit_code = EXIT_FAILURE;
    }

    log_debug("%s (subject: '%s', code: '%s',  reason: '%s')",
        (exit_code == EXIT_SUCCESS ? "Success" : "Failure"),
        mlm_client_subject(client),
        code,
        reason);

    zstr_free(&code);
    zstr_free(&reason);
    mlm_client_destroy(&client);
    CLEANUP;

    log_debug("Done");

    return exit_code;
}

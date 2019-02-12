/*  =========================================================================
    fty_email - Email transport for 42ity project

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
    fty_email - Email transport for 42ity project
@discuss
@end
*/

#include <getopt.h>
#include <fty_common_translation.h>
#include "fty_email_classes.h"

#define TRANSLATION_ROOT    "/usr/share/etn-translations"
#define TRANSLATION_PREFIX  "locale_"

// hack to allow reload of config file w/o the need to rewrite server to zloop and reactors
char *config_file = NULL;
zconfig_t *config = NULL;
char *language = NULL;
char *translation_path = NULL;
char *log_config = NULL;
void usage ()
{
    puts ("fty-email [options]\n"
          "  -v|--verbose          verbose output\n"
          "  -s|--server           smtp server name or address\n"
          "  -p|--port             smtp server port [25]\n"
          "  -u|--user             user for smtp authentication\n"
          "  -f|--from             mail from address\n"
          "  -e|--encryption       smtp encryption (none|tls|starttls) [none]\n"
          "  -c|--config           path to config file\n"
          "  -h|--help             print this information\n"
          "For security reasons, there is not option for password. Use environment variable.\n"
          "Environment variables for all paremeters are BIOS_SMTP_SERVER, BIOS_SMTP_PORT,\n"
          "BIOS_SMTP_USER, BIOS_SMTP_PASSWD, BIOS_SMTP_FROM and BIOS_SMTP_ENCRYPT\n"
          "Command line option takes precedence over variable.");
}


static int
s_timer_event (zloop_t *loop, int timer_id, void *output)
{
    if (zconfig_has_changed (config)) {
        log_info ("Content of %s have changed, reload it", config_file);
        zconfig_reload (&config);
        zstr_sendx (output, "LOAD", config_file, NULL);
    }
    return 0;
}

int main (int argc, char** argv)
{
    int verbose = 0;
    int help = 0;

    char *smtpserver   = getenv("BIOS_SMTP_SERVER");
    char *smtpport     = getenv("BIOS_SMTP_PORT");
    char *smtpuser     = getenv("BIOS_SMTP_USER");
    char *smtppassword = getenv("BIOS_SMTP_PASSWD");
    char *smtpfrom     = getenv("BIOS_SMTP_FROM");
    char *smtpencrypt  = getenv("BIOS_SMTP_ENCRYPT");
    char *msmtp_path   = getenv("_MSMTP_PATH_");
    char *smsgateway   = getenv("BIOS_SMTP_SMS_GATEWAY");
    char *smtpverify   = getenv ("BIOS_SMTP_VERIFY_CA");
    ManageFtyLog::setInstanceFtylog(FTY_EMAIL_ADDRESS);

    int rv = translation_initialize (FTY_EMAIL_ADDRESS, TRANSLATION_ROOT, TRANSLATION_PREFIX);
    if (rv != TE_OK)
        log_warning ("Translation not initialized");

    // get options
    int c;
// Some systems define struct option with non-"const" "char *"
#if defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wwrite-strings"
#endif
    static const char *short_options = "hvs:p:u:f:e:c:";
    static struct option long_options[] =
    {
        {"help",       no_argument,       &help,    1},
        {"verbose",    no_argument,       &verbose, 1},
        {"server",     required_argument, 0,'s'},
        {"port",       required_argument, 0,'p'},
        {"user",       required_argument, 0,'u'},
        {"from",       required_argument, 0,'f'},
        {"encryption", required_argument, 0,'e'},
        {"config", required_argument, 0,'c'},
        {NULL, 0, 0, 0}
    };
#if defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic pop
#endif

    while(true) {

        int option_index = 0;
        c = getopt_long (argc, argv, short_options, long_options, &option_index);
        if (c == -1) break;
        switch (c) {
        case 'v':
            verbose = 1;
            break;
        case 's':
            smtpserver = optarg;
            break;
        case 'p':
            smtpport = optarg;
            break;
        case 'u':
            smtpuser = optarg;
            break;
        case 'f':
            smtpfrom = optarg;
            break;
        case 'e':
            smtpencrypt = optarg;
            break;
        case 'c':
            config_file = strdup (optarg);
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
    if (help) { usage(); exit(1); }
    // end of the options

    if (!config_file) {
        log_info ("No config file specified, falling back to enviromental variables.\nNote this is deprecated and will be removed!");
        config = zconfig_new ("root", NULL);
        zconfig_put (config, "server/verbose", verbose? "1" : "0");
        zconfig_put (config, "server/language", DEFAULT_LANGUAGE);

        zconfig_put (config, "smtp/server", smtpserver);
        zconfig_put (config, "smtp/port", smtpport ? smtpport : "25");
        if (smtpuser)
            zconfig_put (config, "smtp/user", smtpuser);
        if (smtppassword)
            zconfig_put (config, "smtp/password", smtppassword);
        if (smtpfrom)
            zconfig_put (config, "smtp/from", smtpfrom);
        zconfig_put (config, "smtp/encryption", smtpencrypt ? smtpencrypt : "none");
        if (msmtp_path)
            zconfig_put (config, "smtp/msmtppath", msmtp_path);
        if (smsgateway)
            zconfig_put (config, "smtp/smsgateway", smsgateway);
        zconfig_put (config, "smtp/verify_ca", smtpverify ? "1" : "0");

        zconfig_put (config, "malamute/endpoint", FTY_EMAIL_ENDPOINT);
        zconfig_put (config, "malamute/address", FTY_EMAIL_ADDRESS);
        zconfig_put (config, "log/config", DEFAULT_LOG_CONFIG);
        log_config = (char *) DEFAULT_LOG_CONFIG;
        zconfig_print (config);

        config_file = strdup (FTY_EMAIL_CONFIG_FILE);
        int r = zconfig_save (config, config_file);
        if (r == -1) {
            log_error ("Error while saving config file %s: %m", config_file);
            exit (EXIT_FAILURE);
        }
    }
    else {
        config = zconfig_load (config_file);
        if (!config) {
            log_error ("Failed to load config file %s: %m", config_file);
            exit (EXIT_FAILURE);
        }
        else {
            language = zconfig_get (config, "server/language", DEFAULT_LANGUAGE);
            int rv = translation_change_language (language);
            if (rv != TE_OK)
                log_warning ("Language not changed to %s, continuing in %s", language, DEFAULT_LANGUAGE);
        }
    }
    if (language)
            log_config = zconfig_get (config, "log/config", DEFAULT_LOG_CONFIG);
    if (log_config)
        ManageFtyLog::getInstanceFtylog()->setConfigFile(std::string(log_config));

    if (verbose)
        ManageFtyLog::getInstanceFtylog()->setVeboseMode();

    puts ("START fty-email - Daemon that is responsible for email notification about alerts");

    zactor_t *smtp_server = zactor_new (fty_email_server, (void *) NULL);
    if ( !smtp_server ) {
        log_error ("smtp_server: cannot start the daemon");
        return -1;
    }

    // new actor with "sendmail-only"
    zactor_t *send_mail_only_server = zactor_new (fty_email_server, (void *) "sendmail-only");
    if ( !send_mail_only_server ) {
        log_error ("send_mail_only_server: cannot start the daemon");
        return -1;
    }

    zstr_sendx (smtp_server, "LOAD", config_file, NULL);
    zstr_sendx (send_mail_only_server, "LOAD", config_file, NULL);

    zloop_t *check_config = zloop_new();
    // as 5 minutes is the smallest possible reaction time
    zloop_timer (check_config, 1000, 0, s_timer_event, smtp_server);
    zloop_start (check_config);

    zloop_destroy (&check_config);
    zactor_destroy (&smtp_server);
    zactor_destroy (&send_mail_only_server);
    zstr_free (&translation_path);
    zconfig_destroy (&config);
    zstr_free (&config_file);
    return 0;
}

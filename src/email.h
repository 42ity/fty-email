/*  =========================================================================
    email - Smtp

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

/*! \file   email.h
    \brief  Simple wrapper on top of msmtp to send an email
    \author Michal Vyskocil <MichalVyskocil@Eaton.com>

Example:

    shared::Smtp smtp{"mail.example.com", "joe.doe@example.com"};

    try {
        smtp.sendmail(
            "agent.smith@matrix.gov",
            "The pill taken by Neo",
            "Dear Mr. Smith,\n......");
    }
    catch (const std::runtime_error& e) {
       // here we'll handle the error
    }

*/
#ifndef EMAIL_H_INCLUDED
#define EMAIL_H_INCLUDED


#include <string>
#include <vector>
#include <functional>
#include <fty_common_mlm_subprocess.h>

/**
 * \class security
 *
 * Security of SMTP connection
 */
enum class Encryption {
    NONE,
    TLS,
    STARTTLS
};

/*
 * \class SmtpError
 *
 * Specification of error codes from Genepi project
1: if no recipient is specified
2: if the smtp server is unreachable
3: if the hostname coundn't be resolved
4: if the Authentication method is not supported
5: if Authentication failed
6: if SSL is not supported by smtp server
7: if the CA of the smtp server certificate isn't known by the card
8: if SSL is requiered by the smtp server
9: if sender address is not specified
10: if the reason is unknown
*/

enum class SmtpError {
    Succeeded = 0,
    NoRecipient = 1,
    ServerUnreachable = 2,
    DNSFailed = 3,
    AuthMethodNotSupported = 4,
    AuthFailed = 5,
    SSLNotSupported = 6,
    UnknownCA = 7,
    SSLRequired = 8,
    NoSenderAddress = 9,
    Unknown = 10
};

/**
 * \class Smtp
 *
 * \brief Simple wrapper on top of msmtp
 *
 * This class contain some basic configuration for
 * msmtp (host/from) + provide sendmail methods.
 * It *DOES NOT* perform any additional transofmation
 * like uuencode or mime. IOW garbage-in, garbage-out.
 */
class Smtp
{
    public:
        /**
         * \brief Creates SMTP instance
         *
         */
        explicit Smtp();

        ~Smtp ();

        /** \brief set the SMTP server address */
        void host (const std::string& host) { _host = host; };

        /** \brief set the SMTP server port. Default is 25.*/
        void port (const std::string& port) { _port = port; };

        /** \brief set the "mail from" address */
        void from (const std::string& from) { _from = from; };

        /** \brief set username for smtp authentication */
        void username (const std::string& username) { _username = username; };

        /** \brief set password for smtp authentication */
        void password (const std::string& password) { _password = password; };

        /** \brief set the encryption for SMTP communication (NONE|TLS|STARTTLS) */
        void encryption (std::string enc);
        void encryption (Encryption enc) { _encryption = enc; };

        /** \brief turn on or of the CA verification */
        void verify_ca (bool verify) { _verify_ca = verify; }

        /**
         * \brief set alternative path for msmtp
         *
         * \param path  path to msmtp binary to be called
         *
         */
        void msmtp_path (const std::string& msmtp_path) { _msmtp = msmtp_path; };

        /**
         * \brief set sendmail testing function
         *
         * \param function to be used in sendmail instead of msmtp binary
         * This is for testing purposes of protocol only!
         */
        void sendmail_set_test_fn (std::function <void(const std::string&)> fn) {
            _has_fn = true;
            _fn = fn;
        }

        /**
         * \brief send the email
         *
         * Technically this put email to msmtp's outgoing queue
         * \param to        email header To: multiple recipient in vector
         * \param subject   email header Subject:
         * \param body      email body
         *
         * \throws std::runtime_error for msmtp invocation errors
         */
        void sendmail(
                const std::vector<std::string> &to,
                const std::string& subject,
                const std::string& body) const;

        /**
         * \brief send the email
         *
         * Technically this put email to msmtp's outgoing queue
         * \param to        email header To: single recipient
         * \param subject   email header Subject:
         * \param body      email body
         *
         * \throws std::runtime_error for msmtp invocation errors
         */
        void sendmail(
                const std::string& to,
                const std::string& subject,
                const std::string& body) const;

        /**
         * \brief send the email
         *
         * Technically this put email to msmtp's outgoing queue
         * \param data  email DATA (To/Subject are deduced
         *              from the fields in body, so body must be properly
         *              formatted email message).
         *
         * \throws std::runtime_error for msmtp invocation errors
         */
        void sendmail(
                const std::string& data) const;

        /**
         * \brief convert zmq message to email string
         *
         * Function creates a multipart message, which can be sent
         * Format of message is in bios_smtp_server
         *
         */
        std::string
            msg2email (zmsg_t **msg_p) const;

    protected:

        /**
         * \brief create msmtp config file
         */
        std::string createConfigFile() const;
        /**
         * \brief delete msmtp config file
         */
        void deleteConfigFile(std::string &filename) const;

        std::string _host;
        std::string _port;
        std::string _from;
        Encryption _encryption;
        std::string _username;
        std::string _password;
        std::string _msmtp;
        bool _has_fn;
        bool _verify_ca;
        std::function <void(const std::string&)> _fn;
        magic_t _magic;
};

/**
 *  \brief Ciprian's algorithm to obtain email address for given phone number
 *
 *  \param [in] gw_template     template for SMS gateway. The # characters are then replaced by
 *                              numbers from given
 *  \param [in] phone_number    phone number - free form string in whatever national convention
 *  \return email address for sending an email
 *  \throws std::logic_error if provided phone_number does not have sufficient number of
 *          digits
 *
 *  Example:
 *
 *       std::string to = sms_email_address ("0#####@hyper.mobile", "+79 (0) 123456");
 *       assert (to == "023456@hyper.mobile");
 *
 *  Ciprian's algorithm:
 *      1. Phone number is normalized to contain only digits (790123456)
 *      2. Then each last # in template is replaced by last digit from number
 *          0####6@hyper.mobile
 *          0###56@hyper.mobile
 *          ...
 *          023456@hyper.mobile
 *
 */

std::string
    sms_email_address (
        const std::string& gw_template,
        const std::string& phone_number);

/**
 * Convert msmtp stderr to error code
 */
SmtpError
    msmtp_stderr2code (
        const std::string &inp);

void email_test (bool verbose);

#endif

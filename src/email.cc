/*  =========================================================================
    email - Smtp

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
    email - Smtp
@discuss
@end
*/

#include "email.h"
#include "emailconfiguration.h"
#include "fty_email_server.h"
#include <ctime>
#include <fstream>
//#include <fty_common_mlm.h>
#include <fty_log.h>
#include <sstream>
#include <stdio.h>

// to ensure POSIX basename!!!
// DO NOT REMOVE otherwise GNU basename can be used
#include <cxxtools/mime.h>
#include <fty/process.h>
#include <libgen.h>
#include <regex>

Smtp::Smtp()
    : _host{}
    , _port{"25"}
    , _from{"EatonProductFeedback@eaton.com"}
    , _encryption{Encryption::NONE}
    , _username{}
    , _password{}
    , _msmtp{"/usr/bin/msmtp"}
    , _has_fn{false}
    , _verify_ca{false}
{
    _magic = magic_open(MAGIC_MIME | MAGIC_ERROR | MAGIC_NO_CHECK_COMPRESS | MAGIC_NO_CHECK_TAR);
    if (!_magic)
        throw std::runtime_error("Cannot open magic_cookie");

    int r = magic_load(_magic, nullptr);
    if (r == -1) {
        magic_close(_magic);
        throw std::runtime_error("Cannot load magic database");
    }
}

Smtp::~Smtp()
{
    magic_close(_magic);
}

std::string Smtp::createConfigFile() const
{
    char        filename[] = "/tmp/bios-msmtp-XXXXXX.cfg";
    int         handle     = mkstemps(filename, 4);
    std::string line;

    line                        = "defaults\n";
    const std::string verify_ca = _verify_ca ? "on" : "off";

    switch (_encryption) {
        case Encryption::NONE:
            line +=
                "tls off\n"
                "tls_starttls off\n";
            break;
        case Encryption::TLS:
            line +=
                "tls on\n"
                "tls_certcheck " +
                verify_ca + "\n";
            break;
        case Encryption::STARTTLS:
            // TODO: check if this is correct!
            line +=
                "tls off\n"
                "tls_certcheck " +
                verify_ca +
                "\n"
                "tls_starttls on\n";
            break;
    }
    if (_username.empty()) {
        line += "auth off\n";
    } else {
        line +=
            "auth on\n"
            "user " +
            _username +
            "\n"
            "password " +
            _password + "\n";
    }

    line += "account default\n";
    line += "host " + _host + "\n";
    line += "port " + _port + "\n";
    line += "from " + _from + "\n";
    ssize_t r = write(handle, line.c_str(), line.size());
    if (r > 0 && static_cast<size_t>(r) != line.size())
        log_error("write to %s was truncated, expected %zu, written %zd", filename, line.size(), r);
    if (r == -1)
        log_error("write to %s failed: %s", filename, strerror(errno));
    close(handle);
    log_debug("msmtp configuration:\n%s", line.c_str());
    return std::string(filename);
}

void Smtp::deleteConfigFile(std::string& filename) const
{
    unlink(filename.c_str());
}

void Smtp::encryption(std::string enc)
{
    if (strcasecmp("starttls", enc.c_str()) == 0)
        encryption(Encryption::STARTTLS);
    else if (strcasecmp("tls", enc.c_str()) == 0)
        encryption(Encryption::TLS);
    else
        encryption(Encryption::NONE);
}

void Smtp::sendmail(const std::vector<std::string>& to, const std::string& subject, const std::string& body) const
{

    for (const auto& it : to) {
        zuuid_t* uuid = zuuid_new();
        zmsg_t*  msg =
            fty_email_encode(zuuid_str_canonical(uuid), it.c_str(), subject.c_str(), nullptr, body.c_str(), nullptr);
        zuuid_destroy(&uuid);

        // MVY: this is weird, horrible, ugly and hard to use.
        //      Need to rething API for smtp_encode
        //      BUT .. NEVER pass message with first uuid frame to msg2email
        //      or BAD things will happen
        char* cuuid = zmsg_popstr(msg);
        zstr_free(&cuuid);
        sendmail(msg2email(&msg));
    }
}

void Smtp::sendmail(const std::string& to, const std::string& subject, const std::string& body) const
{
    std::vector<std::string> recip;
    recip.push_back(to);
    return sendmail(recip, subject, body);
}


void Smtp::sendmail(const std::string& data) const
{
    using namespace fmt::literals;

    // for testing
    if (_has_fn) {
        _fn(data);
        return;
    }

    std::string cfg = createConfigFile();
    if (_host.empty()) {
        return;
    }
    fty::Process proc(_msmtp, {"-t", "-C", cfg});
    auto         bret = proc.run();
    if (!bret) {
        throw std::runtime_error("{} failed with '{}'"_format(_msmtp, bret.error()));
    }

    bool wr = proc.write(data);
    if (!wr) {
        log_warning("Email truncated");
    }

    auto ret = proc.wait(50000);
    deleteConfigFile(cfg);
    if (!ret) {
        throw std::runtime_error("{} wait with '{}'"_format(_msmtp, ret.error()));
    }

    if (*ret != 0) {
        throw std::runtime_error(
            "{} failed with exit code '{}'\nstderr: {}\n"_format(_msmtp, *ret, proc.readAllStandardError()));
    }
}

static bool s_is_text(const char* mime)
{
    assert(mime);
    return !strncmp(mime, "text", 4);
}

static std::string popString(zmsg_t* msg)
{
    char*       it = zmsg_popstr(msg);
    std::string ret(it);
    zstr_free(&it);
    return ret;
}

std::string Smtp::msg2email(zmsg_t** msg_p) const
{
    assert(msg_p && *msg_p);
    zmsg_t* msg = *msg_p;

    std::stringstream       buff;
    cxxtools::MimeMultipart mime;

    std::string to      = popString(msg);
    std::string subject = popString(msg);
    std::string body    = getIpAddr();
    body += popString(msg);

    mime.setHeader("To", to);
    
    if(subject.empty()) {
        subject = "No Subject";
    }
    mime.setHeader("Subject", subject);
    mime.addObject(body);

    // new protocol have more frames
    if (zmsg_size(msg) != 0) {
        zframe_t* frame   = zmsg_pop(msg);
        zhash_t*  headers = zhash_unpack(frame);
        zframe_destroy(&frame);
        zhash_autofree(headers);

        for (char* value = static_cast<char*>(zhash_first(headers)); value != nullptr;
             value       = static_cast<char*>(zhash_next(headers))) {
            const char* key = zhash_cursor(headers);
            mime.setHeader(key, value);
        }
        zhash_destroy(&headers);


        // NOTE: setLocale(LC_DATE, "C") should be called in outer scope
        time_t     t   = ::time(nullptr);
        struct tm* tmp = ::localtime(&t);
        char       buf[256];
        strftime(buf, sizeof(buf), "%a, %d %b %Y %T %z\n", tmp);
        mime.setHeader("Date", buf);

        while (zmsg_size(msg) != 0) {
            char*       path      = zmsg_popstr(msg);
            const char* mime_type = magic_file(_magic, path);
            if (!mime_type) {
                log_warning("Can't guess type for %s, using application/octet-stream", path);
                mime_type = "application/octet-stream; charset=binary";
            }

            std::ifstream ipath{path};

            if (s_is_text(mime_type))
                mime.attachTextFile(ipath, basename(path), mime_type);
            else
                mime.attachBinaryFile(ipath, basename(path), mime_type);

            ipath.close();
            zstr_free(&path);
        }
    }
    zmsg_destroy(&msg);
    *msg_p = nullptr;

    buff << mime;
    return buff.str();
}

std::string sms_email_address(const std::string& gw_template, const std::string& phone_number)
{
    std::string ret = gw_template;
    std::string clean_phone_number;
    for (const char ch : phone_number) {
        if (::isdigit(ch))
            clean_phone_number.push_back(ch);
    }

    ssize_t idx = static_cast<ssize_t>(clean_phone_number.size() - 1);
    for (;;) {
        auto it = ret.find_last_of('#');
        if (it == std::string::npos)
            break;
        if (idx < 0)
            throw std::logic_error("Cannot apply number '" + phone_number + "' onto template '" + gw_template +
                                   "'. Not enough numbers in phone number");
        ret[it] = clean_phone_number[static_cast<size_t>(idx)];
        idx--;
    }

    return ret;
}

SmtpError msmtp_stderr2code(const std::string& inp)
{
    if (inp.size() == 0)
        return SmtpError::Succeeded;

    static std::regex ServerUnreachable{"cannot connect to .*, port .*"};
    static std::regex DNSFailed{
        ".*(cannot locate host.*: Name or service not known|the server does not support DNS).*", std::regex::extended};
    static std::regex SSLNotSupported{
        ".*(the server does not support TLS via the STARTTLS command|command STARTTLS failed|cannot use a secure "
        "authentication method).*"};
    static std::regex AuthMethodNotSupported{
        ".*(the server does not support authentication|authentication method .* not supported|cannot find a usable "
        "authentication method).*"};
    static std::regex AuthFailed{"(authentication failed|(AUTH LOGIN|AUTH CRAM-MD5|AUTH EXTERNAL) failed)"};
    static std::regex UnknownCA{
        ".*(no certificate was founderror gettint .* fingerprint|the certificate fingerprint does not match|the "
        "certificate has been revoked|the certificate hasn't got a known issuer|the certificate is not trusted).*"};

    if (std::regex_match(inp, ServerUnreachable))
        return SmtpError::ServerUnreachable;

    if (std::regex_match(inp, DNSFailed))
        return SmtpError::DNSFailed;

    if (std::regex_match(inp, AuthMethodNotSupported))
        return SmtpError::AuthMethodNotSupported;

    if (std::regex_match(inp, AuthFailed))
        return SmtpError::AuthFailed;

    if (std::regex_match(inp, SSLNotSupported))
        return SmtpError::SSLNotSupported;

    if (std::regex_match(inp, UnknownCA))
        return SmtpError::UnknownCA;

    return SmtpError::Unknown;
}

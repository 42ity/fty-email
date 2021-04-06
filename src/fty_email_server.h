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

#ifndef FTY_EMAIL_SERVER_H_INCLUDED
#define FTY_EMAIL_SERVER_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

//  @interface

//  Main actor sending emails (and sms2email)
//  Configuration format
//  ====================
//
//  server
//      verbose             1 turns verbose mode on, 0 off
//      assets              path to state file for assets
//      alerts              path to state file for alerts
//  smtp
//      server              address of smtp server
//      port                port number
//      user                name of user for login
//      password            password of user
//      from                From: header of email
//      encryption          encryption, can be (none|tls|starttls)
//      msmtppath           path to msmtp command
//      smsgateway          email to sms gateway
//      verify_ca           1 turns on CA verification, 0 off
//  malamute
//      verbose             1 setup verbose mode of mlm_client, 0 turn it off
//      endpoint            malamute endpoint address
//      address             mailbox address of agent-smtp
//      consumers
//          ALERTS  .*      consume all messages on ALERTS stream
//          ASSETS  .*      consume all messages on ASSETS stream
//
//  Actor commands
//  ==============
//
//  LOAD    path            load and apply configuration from zpl file
//                          see Configuration format section
//
//  Malamute protocol (mailbox agent-smtp)
//  ======================================
//
//  REQ: subject=SENDMAIL
//
//      [$uuid|$to|$subject|$body|$headers:zhash_t|attachment1|attachment2|...]
//      sends email to $to, with subject $subject and body $body
//      $headers state additional headers to be passed to email
//      $attachment1, $attachment2, ... are names of files to be attached
//      see fty_email_encode to handy way to encode such message
//
//      [$uuid|$to|$subject|$body]
//      sends emails via configured environment to address $to, with subject $subject and body $body
//  REP: subject=SENDMAIL-OK [$uuid|0|OK]
//      if email was sent
//  REP: subject=SENDMAIL-ERR [$uuid|$error code|$error message]
//      if email wasn't sent, or there was improper number of arguments
//      error message comes from msmtp stderr and is NOT normalized!
//
//  args:
//      "sendmail-only"      : ignore consumer/ part, connect as $(malamute/address)-sendmail-only
FTY_EMAIL_EXPORT void
   fty_email_server (zsock_t *pipe, void* args);

//  Self test of this class
FTY_EMAIL_EXPORT void
    fty_email_server_test (bool verbose);

// encode email message to zmsg_t
//  uuid - uuid of the message
//  to   - email address to
//  subject - email subject
//  headers - additional headers to be passed (optional)
//  body - email body
//  ... list of files to attach (files with .txt suffix will be added as text files, otherwise binary)
//  parameter list must be closed by NULL
FTY_EMAIL_EXPORT zmsg_t *
    fty_email_encode (
        const char *uuid,
        const char *to,
        const char *subject,
        zhash_t *headers,
        const char *body,
        ...);

//  @end

#ifdef __cplusplus
}
#endif

#endif

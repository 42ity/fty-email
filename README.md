# fty-email

fty-email is an agent which sends e-mail/SMS notifications about alarms.

## How to build

To build fty-email project run:

```bash
./autogen.sh
./configure
make
make check # to run self-test
```
Compilation of fty-email creates two binaries - fty-email, which is run by systemd service, and fty-sendmail, which is a CLI utility.

Distributed together with them is a shell script fty-device-scan, which scans SNMP-capable power devices and reports the result via e-mail.

## How to run

To run fty-email project:

* from within the source tree, run:

```bash
./src/fty-email
```

For the other options available, refer to the manual page of fty-email

* from an installed base, using systemd, run:

```bash
systemctl start fty-email
```

### Configuration file

To configure fty-email, a configuration file exists: fty-email.cfg

Beside from the standard configuration directives, under the server and malamute
sections, agent has the following configuration options:

* under smtp section:
    * server - SMTP server
    * port - port of SMTP server (default value 25)
    * user - SMTP user name
    * password - SMTP user password
    * from - From: header
    * msmtppath - path to msmtp binary
    * encryption - available values: NONE | TLS | STARTTLS (default value NONE)
    * smsgateway - SMS gateway
    * verify\_ca - whether to verify CA
    * use\_auth - whether to use username and password

* under malamute section:
    * consumers/<stream> - subscribe fty-email to specified streams and use regular expression filtering on them.
        Unused by default.
    * producer - set fty-email to publish on specified stream. Unused by default.
    * timeout - set timeout for connecting to Malamute broker (default value is 1 second)

Values read from configuration file can be overwritten by setting the following environment variables:

* BIOS\_LOG\_LEVEL for server/verbose
* BIOS\_SMTP\_SERVER for smtp/server
* BIOS\_SMTP\_PORT for smtp/port
* BIOS\_SMTP\_USER for smtp/user
* BIOS\_SMTP\_PASSWD for smtp/password
* BIOS\_SMTP\_FROM for smtp/from
* \_MSMTP\_PATH for smtp/msmtp
* BIOS\_SMTP\_ENCRYPT for smtp/encryption
* BIOS\_SMTP\_SMS\_GATEWAY for smtp/smsgateway
* BIOS\_SMTP\_VERIFY\_CA for smtp/verify\_ca

## Architecture

### Overview

fty-email is composed of 1 actor and 1 timer.

Actor is a server actor: handles e-mail configuration, notification via e-mail/SMS and requests to send e-mail in general.

This actor can be run in full, or in sendmail-only mode (when it doesn't connect to the Malamute broker).

Timer runs every second and checks whether the config file changes - if it did, it issues the LOAD command to the actor.

## Protocols

### Published metrics

In default configuration, agent doesn't publish any metrics.

### Published alerts

In default configuration, agent doesn't publish any alerts.

### Sending e-mails

Sending of e-mails is handled by class email, which implements a wrapper for msmtp binary.

NB: configuration is loaded once at the start of the server actor. Agent then checks for config changes every time the timer runs.

### Mailbox requests

It is possible to request the fty-email agent for:

* sending e-mail with default headers

* sending e-mail with user-specified headers

* sending e-mail notification for specified alert

* sending SMS notification for specified alert

#### Sending e-mail with default headers

The USER peer sends the following messages using MAILBOX SEND to
FTY-EMAIL-AGENT ("fty-email") peer:

* correlation\-id/body - send e-mail with default headers with the body 'body'

where
* '/' indicates a multipart string message
* 'correlation\-id' is a zuuid identifier provided by the caller
* 'body' MUST be valid body of e-mail
* subject of the message MUST be "SENDMAIL".

The FTY-EMAIL-AGENT peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* correlation\-id/0/OK
* correlation\-id/error\-code/reason

where
* '/' indicates a multipart frame message
* 'correlation\-id' is a zuuid identifier provided by the caller
* 'error\-code' is error code from msmtp
* 'reason' is string detailing reason for error (just what() for the thrown runtime error)
* subject of the message must be SENDMAIL-OK for OK message and SENDMAIL-ERROR for error message

#### Sending e-mail with user-specified headers

The USER peer sends the following messages using MAILBOX SEND to
FTY-EMAIL-AGENT ("fty-email") peer:

* correlation\-id/to/subject/body/header\-1/.../header\-n/path\-1/.../path\-m - send this e-mail

where
* '/' indicates a multipart string message
* 'correlation\-id' is a zuuid identifier provided by the caller
* 'to' MUST be valid To: header
* 'subject' MUST be valid Subject: header
* 'body' MUST be valid body of e-mail
* 'header-1',...,'header-n' MAY be other headers
* 'path-1',...,'path-m' MAY be present and MUST be, if present, paths to text OR binary files
* subject of the message MUST be "SENDMAIL".

The FTY-EMAIL-AGENT peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* correlation\-id/0/OK
* correlation\-id/error\-code/reason

where
* '/' indicates a multipart frame message
* 'correlation\-id' is a zuuid identifier provided by the caller
* 'error\-code' is error code from msmtp
* 'reason' is string detailing reason for error (just what() for the thrown runtime error)
* subject of the message must be SENDMAIL-OK for OK message and SENDMAIL-ERROR for error message

#### Sending e-mail notification for specified alert

The USER peer sends the following messages using MAILBOX SEND to
FTY-EMAIL-AGENT ("fty-email") peer:

* correlation\-id/priority/extname/contact/fty\_proto ALERT message
    - send notification for asset 'extname' with priority 'priority' to 'contact',
    where content of the notification is specified by the ALERT message

where
* '/' indicates a multipart string message
* 'correlation\-id' is a zuuid identifier provided by the caller
* 'priority' MUST be valid asset priority (1 - 5)
* 'extname' MUST be valid user-friendly asset name
* 'contact' MUST be empty string OR valid e-mail
* 'fty\_proto ALERT message' must be valid fty\_proto message of the type ALERT
* subject of the message MUST be "SENDMAIL\_ALERT".

The FTY-EMAIL-AGENT peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* correlation\-id/OK
* correlation\-id/ERROR/reason

where
* '/' indicates a multipart frame message
* 'correlation\-id' is a zuuid identifier provided by the caller
* 'reason' is string detailing reason for error (just what() for the thrown runtime error)
* subject of the message must be "SENDMAIL\_ALERT"

#### Sending SMS notification for specified alert

The USER peer sends the following messages using MAILBOX SEND to
FTY-EMAIL-AGENT ("fty-email") peer:

* correlation\-id/priority/extname/contact/fty\_proto ALERT message
    - send notification for asset 'extname' with priority 'priority' to 'contact',
    where content of the notification is specified by the ALERT message

where
* '/' indicates a multipart string message
* 'correlation\-id' is a zuuid identifier provided by the caller
* 'priority' MUST be valid asset priority (1 - 5)
* 'extname' MUST be valid user-friendly asset name
* 'contact' MUST be empty string OR valid phone number
* 'fty\_proto ALERT message' must be valid fty\_proto message of the type ALERT
* subject of the message MUST be "SENDSMS\_ALERT".

The FTY-EMAIL-AGENT peer MUST respond with one of the messages back to USER
peer using MAILBOX SEND.

* correlation\-id/OK
* correlation\-id/ERROR/reason

where
* '/' indicates a multipart frame message
* 'correlation\-id' is a zuuid identifier provided by the caller
* 'reason' is string detailing reason for error (just what() for the thrown runtime error)
* subject of the message must be "SENDSMS\_ALERT"

### Stream subscriptions

In default configuration, agent isn't subscribed to any streams.

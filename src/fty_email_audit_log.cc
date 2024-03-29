/*  =========================================================================
    fty_email_audit_log - Manage audit log

    Copyright (C) 2014 - 2021 Eaton

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
    fty_email_audit_log - Manage audit log
@discuss
@end
*/

#include "fty_email_audit_log.h"

Ftylog* AuditLogManager::_auditLogger = nullptr;

//  init audit logger
void AuditLogManager::init(const std::string& serviceName)
{
    if (!_auditLogger) {
        const char* loggerName = "audit/email";
        const char* confFileName = FTY_COMMON_LOGGING_DEFAULT_CFG;

        _auditLogger = ftylog_new(loggerName, confFileName);
        if (!_auditLogger) {
            log_error("Audit logger initialization failed (%s, %s)", loggerName, confFileName);
        }
        else {
            log_info("Audit logger initialization succeeded (%s, %s)", loggerName, confFileName);
            log_info_email_audit("Audit logger initialization (%s)", serviceName.c_str());
        }
    }
}

//  deinit audit logger
void AuditLogManager::deinit()
{
    if (_auditLogger) {
        ftylog_delete(_auditLogger);
        _auditLogger = nullptr;
    }
}

//  return audit logger instance
Ftylog* AuditLogManager::getInstance()
{
    return _auditLogger;
}

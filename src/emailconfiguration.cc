/*  =========================================================================
    emailconfiguration - Class that is responsible for email configuration

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
    emailconfiguration - Class that is responsible for email configuration
@discuss
@end
*/

#include <fty_common_macros.h>
#include <fty_common_translation.h>
#include "fty_email_classes.h"

/* This is what this code is intended to do:
 * - calling TRANSLATE_ME on template returns this kind of JSON:
 *   { "key" : "{{var1}} alert on {{var2}}\nfrom the rule {{var3}} is active!", "variables" : {"var1" : "__severity__", "var2" : "__assetname__", "var3" : "__rulename__"}}
 * - this JSON is fed into translation_get_translated_text(), which returns (for English language):
 *   "__severity__ alert on __assetname__\nfrom the rule __rulename__ is active!"
 * - replace_tokens() then replaces __string__ patterns with corresponding values
 */

#define BODY_ACTIVE \
TRANSLATE_ME ("In the system an alert was detected.\n\
Source rule: %s\n\
Asset: %s\n\
Alert priority: P%s\n\
Alert severity: %s\n\
Alert description: %s\n\
Alert state: %s", \
"__rulename__", "__assetname__", "__priority__", "__severity__", "__description__", "__state__")

#define SUBJECT_ACTIVE \
TRANSLATE_ME ("%s alert on %s\n\
from the rule %s is active!", \
"__severity__", "__assetname__", "__rulename__")

#define BODY_RESOLVED \
TRANSLATE_ME ("In the system an alert was resolved.\n\
Source rule: %sn\
Asset: %s\n\
Alert description: %s", \
"__rulename__", "__assetname__", "__description__")

#define SUBJECT_RESOLVED \
TRANSLATE_ME ("Alert on %s \n\
from the rule %s was resolved", \
"__assetname__", "__rulename__")


// ----------------------------------------------------------------------------
// static helper functions

static std::string
replace_tokens (
        const std::string& text,
        const std::string& pattern,
        const std::string& replacement)
{
    std::string result = text;
    size_t pos = 0;
    while( ( pos = result.find(pattern, pos) ) != std::string::npos){
        result.replace(pos, pattern.length(), replacement);
        pos += replacement.length();
    }
    return result;
}

static std::string
s_generateEmailBodyResolved (fty_proto_t *alert, const std::string& extname)
{
    char *result_char = translation_get_translated_text (BODY_RESOLVED.c_str ());
    std::string result (result_char);
    zstr_free (&result_char);
    result = replace_tokens (result, "__rulename__", fty_proto_rule (alert));
    result = replace_tokens (result, "__assetname__", extname);
    char *description_char = translation_get_translated_text (fty_proto_description (alert));
    std::string description (description_char);
    zstr_free (&description_char);
    result = replace_tokens (result, "__description__", description.c_str ());
    return result;
}

static std::string
s_generateEmailBodyActive (fty_proto_t *alert, const std::string& priority, const std::string& extname)
{
    char *result_char = translation_get_translated_text (BODY_ACTIVE.c_str ());
    std::string result (result_char);
    zstr_free (&result_char);
    result = replace_tokens (result, "__rulename__", fty_proto_rule (alert));
    result = replace_tokens (result, "__assetname__", extname);
    char *description_char = translation_get_translated_text (fty_proto_description (alert));
    std::string description (description_char);
    zstr_free (&description_char);
    result = replace_tokens (result, "__description__", description.c_str ());
    result = replace_tokens (result, "__priority__", priority);
    result = replace_tokens (result, "__severity__", fty_proto_severity (alert));
    result = replace_tokens (result, "__state__", fty_proto_state (alert));
    return result;
}

static std::string
s_generateEmailSubjectResolved (fty_proto_t *alert, const std::string &extname)
{
    char *result_char = translation_get_translated_text (SUBJECT_RESOLVED.c_str ());
    std::string result (result_char);
    zstr_free (&result_char);
    result = replace_tokens (result, "__rulename__", fty_proto_rule (alert));
    result = replace_tokens (result, "__assetname__", extname);
    return result;
}

static std::string
s_generateEmailSubjectActive (fty_proto_t *alert, const std::string& priority, const std::string& extname)
{
    char *result_char = translation_get_translated_text (SUBJECT_ACTIVE.c_str ());
    std::string result (result_char);
    zstr_free (&result_char);
    result = replace_tokens (result, "__rulename__", fty_proto_rule (alert));
    result = replace_tokens (result, "__assetname__", extname);
    char *description_char = translation_get_translated_text (fty_proto_description (alert));
    std::string description (description_char);
    zstr_free (&description_char);
    result = replace_tokens (result, "__description__", description.c_str ());
    result = replace_tokens (result, "__priority__", priority);
    result = replace_tokens (result, "__severity__", fty_proto_severity (alert));
    result = replace_tokens (result, "__state__", fty_proto_state (alert));
    return result;
}

// ----------------------------------------------------------------------------
// header functions

std::string
generate_body (fty_proto_t *alert, const std::string& priority, const std::string& extname)
{
    if (streq (fty_proto_state (alert), "RESOLVED")) {
        return s_generateEmailBodyResolved (alert, extname);
    }
    return s_generateEmailBodyActive (alert, priority, extname);
}

std::string
generate_subject (fty_proto_t *alert, const std::string& priority, const std::string& extname)
{
    if (streq (fty_proto_state (alert), "RESOLVED")) {
        return s_generateEmailSubjectResolved (alert, extname);
    }
    return s_generateEmailSubjectActive (alert, priority, extname);
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
emailconfiguration_test (bool verbose)
{
    printf (" * emailconfiguration: ");
    // TODO
    //  * replace_tokens
    //  * generate_subject
    //  * generate_body
    printf ("OK\n");
}

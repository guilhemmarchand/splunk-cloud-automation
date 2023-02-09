#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
import csv
import sys
import log
import logging

# Map for possible property flags
property_flags = {
    "1": "SCRIPT",
    "2": "ACCOUNTDISABLE",
    "8": "HOMEDIR_REQUIRED",
    "16": "LOCKOUT",
    "32": "PASSWD_NOTREQD",
    "64": "PASSWD_CANT_CHANGE",
    "128": "ENCRYPTED_TEXT_PWD_ALLOWED",
    "256": "TEMP_DUPLICATE_ACCOUNT",
    "512": "NORMAL_ACCOUNT",
    "2048": "INTERDOMAIN_TRUST_ACCOUNT",
    "4096": "WORKSTATION_TRUST_ACCOUNT",
    "8192": "SERVER_TRUST_ACCOUNT",
    "65536": "DONT_EXPIRE_PASSWORD",
    "131072": "MNS_LOGON_ACCOUNT",
    "262144": "SMARTCARD_REQUIRED",
    "524288": "TRUSTED_FOR_DELEGATION",
    "1048576": "NOT_DELEGATED",
    "2097152": "USE_DES_KEY_ONLY",
    "4194304": "DONT_REQ_PREAUTH",
    "8388608": "PASSWORD_EXPIRED",
    "16777216": "TRUSTED_TO_AUTH_FOR_DELEGATION",
    "67108864": "PARTIAL_SECRETS_ACCOUNT",
}


def main():

    logger = log.Log().get_logger("user_account_control_property")
    logger.info("Lookup script started executing..")

    # prints usage of the lookup script if wrong number of arguments provided
    if len(sys.argv) != 3:
        logger.debug(
            "Usage: python user_account_control_property.py [userAccountControl] [userAccountPropertyFlag]"
        )
        logger.debug("Lookup script stopped..")
        sys.exit(1)

    # Lookup Field names
    userAccountControl = sys.argv[1]
    userAccountPropertyFlag = sys.argv[2]

    infile = sys.stdin
    outfile = sys.stdout

    r = csv.DictReader(infile)

    w = csv.DictWriter(outfile, fieldnames=r.fieldnames)

    w.writeheader()

    # Decode flags for every 'userAccountControl' attribute value present in a search result
    for result in r:
        try:
            if result[userAccountControl].isdigit():
                attribute_value = int(result[userAccountControl])
                bit_cnt = 0
                incorrect_result_flag = False
                flags = list()

                # Prepare flag list by decoding 'userAccountcontrol' decimal value
                # As 'userAccountControl' is decimal value, For each bit set to '1' a property flag can be denoted by using 'property_flags' map given above
                while attribute_value != 0:
                    if attribute_value & 1 == 1:
                        flags.append(str(1 << bit_cnt))
                    attribute_value = attribute_value >> 1
                    bit_cnt += 1

                # If flag not present in 'property_flags' map, The 'userAccountPropertyFlag' won't be populated in search result
                for flag in flags:
                    if flag not in list(property_flags.keys()):
                        logger.debug(
                            "'userAccountControl' attribute can not be decoded for value: {}".format(
                                result[userAccountControl]
                            )
                        )
                        incorrect_result_flag = True
                        break
                if incorrect_result_flag:
                    continue
                else:
                    for flag in flags:
                        result[userAccountPropertyFlag] = property_flags[flag]
                        w.writerow(result)
            else:
                logger.debug(
                    "'userAccountControl' attribute can not be decoded for value: {}".format(
                        result[userAccountControl]
                    )
                )
        except:
            logger.debug(
                "No results for 'userAccountControl' attribute value :{}".format(
                    result[userAccountControl]
                )
            )


if __name__ == "__main__":
    main()

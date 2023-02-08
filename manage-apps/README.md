# Purpose

The purpose of this is to build a custom restricted TA for parsing purposes for Cloud customers.

The logic is based on the following:

- A git repository contains the extracted version of a Splunk Base Add-on
- In the same git repository, a custom version of the app contains only the local configuration that override any conflicting stanza from the base Add-on
- The build.py generates a build release which is a controlled merged app from both using ksconf
- The build release can then be submitted to Appinspect

# Usage

At the root of the Git repo, stands a JSON configuration file:

{
"appAuthor": "My Company",
"appID": "org_Splunk_TA_windows",
"appLabel": "Splunk Add-on for Microsoft Windows",
"appDecription": "Splunk Add-on for Microsoft Windows",
"appMerge": "True",
"appSource": "Splunk_TA_windows",
"appVersion": "8.6.0"
}

This defines the app.conf generation and the behaviour.

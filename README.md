# pingish
ping measurement project for Raspberry Pi

This code is intended to identify a problem "WTF is up with netgear powerline adapters",
as in: how often do they have [unexplained outages and variable latency](https://www.amazon.co.uk/review/ROIU32WHZ60XP/ref=pe_1572281_66412651_cm_rv_eml_rv0_rv).

the cli command outputs the ping stats in CSV format to stdout (all other logging to stderr), so the saved output can be fed straight into analysis tooling (e.g. Apache Zeppelin), to get a view of what's going on.

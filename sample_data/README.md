# Scanner CSV samples

These small UTF-8 examples exercise the importer's generic, Nessus, Qualys, and
OpenVAS/Greenbone header adapters. They use illustrative host data and do not
represent real scanner output or vulnerabilities.

The importer accepts ISO dates, ISO datetimes, and slash dates in either
day/month/year or month/day/year order. When a slash date is ambiguous, it is
interpreted day-first. Asset matching is case-insensitive against the available
asset names; the sample hostname or IP must therefore match an inventory asset
unless "Create missing assets" is enabled.

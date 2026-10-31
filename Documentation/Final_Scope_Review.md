# Final scope review, October 31, 2026

The collector SUID list contains 17 paths and the SGID list nine, overlapping at Xorg.wrap. The bodyfile confirms 25 regular set-ID files and seven setgid directories. Common privilege-bearing utilities appear; no kit or libymv path appears in that list. This does not authenticate the binaries against a trusted baseline or prove a SUID exploit.

/etc/profile and five collected profile.d files were reviewed. Their visible content concerns shell setup, completion, desktop/input configuration and terminal integration. No case-specific launch was identified; no rc.local member was collected.

The collected resolv.conf names 208.67.222.222 and 9.9.9.9 as resolvers. Hosts maps vbox.fci.int/vbox to 127.0.1.1. These settings do not prove an observed mining-domain query or exfiltration destination.

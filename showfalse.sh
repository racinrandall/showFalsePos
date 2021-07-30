#!/bin/bash
# Created by Charles Randall chrandal@redhat.com
# Date 29 July 2021
# Purpose of script is to give an output that can be used to verify false findings from Nessus Scans dated 29 July 2021

printf "\n"
echo -e "RHEL-08-010030 - All RHEL 8 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection."
echo -e "Command:"
echo "blkid"
echo -e "Results:"
blkid
echo -e "STIG Requirement:"
echo "Every persistent disk partition present must be of type "crypto_LUKS". If any partitions other than pseudo file systems (such as /proc or /sys) are not type "crypto_LUKS", ask the administrator to indicate how the partitions are encrypted. If there is no evidence that all local disk partitions are encrypted, this is a finding."
echo -e "Notes related to scan:"
echo "Manual Review.  The disks on the VM are not encrypted due to the physical disks on the underlying hardware being encrypted."

printf "\n"
echo -e "RHEL-08-010140 - RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) implemented must require authentication upon booting into single-user mode and maintenance."
echo -e "Command:"
echo "grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg"
echo -e "Results:"
grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg
echo -e "STIG Requirement:"
echo "If the root password does not begin with "grub.pbkdf2.sha512", this is a finding."
echo -e "Command:"
echo "grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg"
echo -e "Results:"
grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg
echo -e "STIG Requirement:"
echo "If "superusers" is not set to a unique name or is missing a name, this is a finding"

printf "\n"
echo -e "RHEL-08-010360 - The RHEL 8 file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered within an organizationally defined frequency."
echo -e "Command:"
echo "yum list installed aide"
echo -e "Results:"
yum list installed aide
echo -e "STIG Requirement:"
echo "If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system."
echo -e "Command:"
echo "ls -al /etc/cron.* | grep aide"
echo -e "Results:"
ls -al /etc/cron.* | grep aide
echo -e "Command:"
echo "grep aide /etc/crontab /var/spool/cron/root"
echo -e "Results:"
grep aide /etc/crontab /var/spool/cron/root
echo -e "Command:"
echo "more /etc/cron.d/aide"
echo -e "Results:"
more /etc/cron.d/aide
echo -e "STIG Requirement:"
echo "If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, or the file integrity application does not notify designated personnel of changes, this is a finding."

printf "\n"
echo -e "RHEL-08-010580 - RHEL 8 must prevent special devices on non-root local partitions."
echo -e "Command:"
echo "mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'"
echo -e "Results:"
mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'
echo -e "STIG Requirement:"
echo "If any output is produced, this is a finding."
echo -e "Notes related to scan:"
echo "The output from the scan shows the root partition"

printf "\n"
echo -e "RHEL-08-010600 - RHEL 8 must prevent special devices on file systems that are used with removable media."
echo -e "Command:"
echo "more /etc/fstab"
echo -e "Results:"
more /etc/fstab
echo -e "STIG Requirement:"
echo "If a file system found in "/etc/fstab" refers to removable media and it does not have the "nodev" option set, this is a finding."
echo -e "Notes related to scan:"
echo "No listed filesystems are removable media"

printf "\n"
echo -e "RHEL-08-010610 - RHEL 8 must prevent code from being executed on file systems that are used with removable media"
echo -e "Command:"
echo "more /etc/fstab"
echo -e "Results:"
more /etc/fstab
echo -e "STIG Requirement:"
echo "If a file system found in "/etc/fstab" refers to removable media and it does not have the "noexec" option set, this is a finding."
echo -e "Notes related to scan:"
echo "No listed filesystems are removable media"

printf "\n"
echo -e "RHEL-08-010620 - RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media."
echo -e "Command:"
echo "more /etc/fstab"
echo -e "Results:"
more /etc/fstab
echo -e "STIG Requirement:"
echo "If a file system found in "/etc/fstab" refers to removable media and it does not have the "nosuid" option set, this is a finding."
echo -e "Notes related to scan:"
echo "No listed filesystems are removable media"

printf "\n"
echo -e "RHEL-08-010630 - RHEL 8 must prevent code from being executed on file systems that are imported via Network File System (NFS)."
echo -e "Command:"
echo "grep nfs /etc/fstab | grep noexec"
echo -e "Results:"
grep nfs /etc/fstab | grep noexec
echo -e "STIG Requirement:"
echo "If a file system found in "/etc/fstab" refers to NFS and it does not have the "noexec" option set, this is a finding."
echo -e "Notes related to scan:"
echo "There are no NFS mounted filesystems"

printf "\n"
echo -e "RHEL-08-010640 - RHEL 8 must prevent special devices on file systems that are imported via Network File System (NFS)."
echo -e "Command:"
echo "grep nfs /etc/fstab | grep nodev"
echo -e "Results:"
grep nfs /etc/fstab | grep noexec
echo -e "STIG Requirement:"
echo "If a file system found in "/etc/fstab" refers to NFS and it does not have the "nodev" option set, this is a finding."
echo -e "Notes related to scan:"
echo "There are no NFS mounted filesystems"

printf "\n"
echo -e "RHEL-08-010650 - RHEL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are imported via Network File System (NFS)."
echo -e "Command:"
echo "grep nfs /etc/fstab | grep nosuid"
echo -e "Results:"
grep nfs /etc/fstab | grep noexec
echo -e "STIG Requirement:"
echo "If a file system found in "/etc/fstab" refers to NFS and it does not have the "nosuid" option set, this is a finding."
echo -e "Notes related to scan:"
echo "There are no NFS mounted filesystems"

printf "\n"
echo -e "RHEL-08-010660 - Local RHEL 8 initialization files must not execute world-writable programs."
echo -e "Command:"
echo 'for x in `df | tail -n +2 | awk '{print $NF}' | grep -v '/run\|/dev/shm\|/sys'`; do find $x -xdev -type f -perm -0002 -print; done'
echo -e "Results:"
for x in `df | tail -n +2 | awk '{print $NF}' | grep -v '/run\|/dev/shm\|/sys'`; do find $x -xdev -type f -perm -0002 -print; done
echo -e "STIG Requirement:"
printf "For all files listed, check for their presence in the local initialization files with the following commands:\nNote: The example will be for a system that is configured to create user home directories in the "/home" directory.\n$ sudo grep <file> /home/*/.*\n"
echo -e "Notes related to scan:"
echo "Manual Review No Files found."

printf "\n"
echo -e "RHEL-08-010680 - For RHEL 8 systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured."
echo -e "Command:"
echo "grep hosts /etc/nsswitch.conf"
echo -e "Results:"
grep hosts /etc/nsswitch.conf
echo -e "STIG Requirement:"
echo "If the DNS entry is missing from the host's line in the "/etc/nsswitch.conf" file, the "/etc/resolv.conf" file must be empty."
echo -e "Command:"
echo "ls -al /etc/resolv.conf"
echo -e "Results:"
ls -al /etc/resolv.conf
echo -e "STIG Requirement:"
echo "If local host authentication is being used and the "/etc/resolv.conf" file is not empty, this is a finding."
echo -e "Command:"
echo "grep nameserver /etc/resolv.conf"
echo -e "Results:"
grep nameserver /etc/resolv.conf
echo -e "STIG Requirement:"
echo "If less than two lines are returned that are not commented out, this is a finding."
echo -e "Notes related to scan:"
echo "Scanner appears to be looking specifically for a nameserver at IP address 192.168.200.1 and 192.168.300.1"

printf "\n"
echo -e "RHEL-08-010690 - Executable search paths within the initialization files of all local interactive RHEL 8 users must only contain paths that resolve to the system default or the users home directory."
echo -e "Command:"
echo "grep -i path /home/*/.*"
echo -e "Results:"
grep -i path /home/*/.*
echo -e "STIG Requirement:"
echo "If any local interactive user initialization files have executable search path statements that include directories outside of their home directory and is not documented with the ISSO as an operational requirement, this is a finding."
echo -e "Notes related to scan:"
echo "Manual Review.  All initialization files search path is within their home directory"

printf "\n"
echo -e "RHEL-08-010770 - All RHEL 8 local initialization files must have mode 0740 or less permissive."
echo -e "Command:"
echo "ls -al /home/*/.[^.]*"
echo -e "Results:"
ls -al /home/*/.[^.]*
echo -e "STIG Requirement:"
echo "If any local initialization files have a mode more permissive than '0740', this is a finding."
echo -e "Notes related to scan:"
echo "Scanner triggers on the root user's initialization files.  Will Fix with next command.  Previously fixed for only normal users."
echo -e "Command:"
echo "chmod o-r /root/.*"
chmod o-r /root/.*
echo -e "Command:"
echo "ls -al /home/*/.[^.]*"
echo -e "Results:"
ls -al /home/*/.[^.]*
echo -e "STIG Requirement:"
echo "If any local initialization files have a mode more permissive than '0740', this is a finding."
echo -e "Notes related to scan:"
echo "Verify there are no longer any files listed more permissive than '0740'"

printf "\n"
echo -e "RHEL-08-020000 - RHEL 8 temporary user accounts must be provisioned with an expiration time of 72 hours or less."
echo -e "Command:"
echo "'for x in `awk -F: '{if($3 >= 1000 && $7 !~ "nologin") print $1}' /etc/passwd`; do chage -l $x; done'"
echo -e "Results:"
for x in `awk -F: '{if($3 >= 1000 && $7 !~ "nologin") print $1}' /etc/passwd`; do chage -l $x; done
echo -e "STIG Requirement:"
echo "If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding."
echo -e "Notes related to scan:"
echo "Manual Review.  None of these accounts are Temp accounts"

printf "\n"
echo -e "RHEL-08-020050 - RHEL 8 must be able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed."
echo -e "Command:"
echo "grep -R removal-action /etc/dconf/db/*"
echo -e "Results:"
grep -R removal-action /etc/dconf/db/*
echo -e "STIG Requirement:"
echo "If the "removal-action='lock-screen'" setting is missing or commented out from the dconf database files, this is a finding."
echo -e "Notes related to scan:"
echo "Unable to determine exactly what scanner is looking for from results"

printf "\n"
echo -e "RHEL-08-020100 - RHEL 8 must ensure a password complexity module is enabled."
echo -e "Command:"
echo "cat /etc/pam.d/password-auth | grep pam_pwquality"
echo -e "Results:"
cat /etc/pam.d/password-auth | grep pam_pwquality
echo -e "Command:"
echo "cat /etc/pam.d/system-auth | grep pam_pwquality"
echo -e "Results:"
cat /etc/pam.d/system-auth | grep pam_pwquality
echo -e "STIG Requirement:"
printf "If both commands do not return a line containing the value 'pam_pwquality.so', or the line is commented out, this is a finding.\nIf the value of 'retry' is set to '0' or greater than '3', this is a finding.\n"
echo -e "Notes related to scan:"
echo "Both files contain the required retry.  The additional line may be tripping up the scanner, but does not nullify the STIG setting"

printf "\n"
echo -e "RHEL-08-020220 - RHEL 8 passwords must be prohibited from reuse for a minimum of five generations."
echo -e "Command:"
echo "grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth"
echo -e "Results:"
grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth
echo -e "STIG Requirement:"
echo "If the line containing 'pam_pwhistory.so' does not have the 'remember' module argument set, is commented out, or the value of the 'remember' module argument is set to less than '5', this is a finding."
echo -e "Notes related to scan:"
echo "Both files have the required remember setting"

printf "\n"
echo -e "RHEL-08-020270 - RHEL 8 emergency accounts must be automatically removed or disabled after the crisis is resolved or within 72 hours."
echo -e "Command:"
echo "'for x in `awk -F: '{if($3 >= 1000 && $7 !~ "nologin") print $1}' /etc/passwd`; do chage -l $x; done'"
echo -e "Results:"
for x in `awk -F: '{if($3 >= 1000 && $7 !~ "nologin") print $1}' /etc/passwd`; do chage -l $x; done
echo -e "STIG Requirement:"
printf "Verify each of these accounts has an expiration date set within 72 hours.\nIf any emergency accounts have no expiration date set or do not expire within 72 hours, this is a finding.\n"
echo -e "Notes related to scan:"
echo "Manual Review.  None of these accounts are Emergency accounts"

printf "\n"
echo -e "RHEL-08-020300 - RHEL 8 must prevent the use of dictionary words for passwords."
echo -e "Command:"
echo "grep dictcheck /etc/security/pwquality.conf /etc/pwquality.conf.d/*.conf"
echo -e "Results:"
grep dictcheck /etc/security/pwquality.conf /etc/pwquality.conf.d/*.conf
echo -e "STIG Requirement:"
echo "If the "dictcheck" parameter is not set to "1", or is commented out, this is a finding."
echo -e "Notes related to scan:"
echo "Scan failed due to no files in /etc/pwquality.conf.d/ They are not needed if the required setting is in /etc/security/pwquality.conf"

printf "\n"
echo -e "RHEL-08-020320 - RHEL 8 must not have unnecessary accounts."
echo -e "Command:"
echo "more /etc/passwd"
echo -e "Results:"
more /etc/passwd
echo -e "STIG Requirement:"
printf "Accounts such as "games" and "gopher" are not authorized accounts as they do not support authorized system functions.\nIf the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding.\n"
echo -e "Notes related to scan:"
echo "Manual Review.  Unnecessary accounts have been removed"

printf "\n"
echo -e "RHEL-08-030010 - Cron logging must be implemented in RHEL 8."
echo -e "Command:"
echo "grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
echo -e "Results:"
grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo -e "STIG Requirement:"
echo "If the command does not return a response, check for cron logging all facilities with the following command."
echo -e "Command:"
echo "grep -s /var/log/messages /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
echo -e "Results:"
grep -s /var/log/messages /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo -e "Notes related to scan:"
echo "All Cron messages are being sent to /var/log/cron per /etc/rsyslog.conf"

printf "\n"
echo -e "RHEL-08-030650 - RHEL 8 must use cryptographic mechanisms to protect the integrity of audit tools."
echo -e "Command:"
echo "egrep '(\/usr\/sbin\/(audit|au))' /etc/aide.conf"
echo -e "Results:"
egrep '(\/usr\/sbin\/(audit|au))' /etc/aide.conf
echo -e "STIG Requirement:"
echo "If any of the audit tools listed above do not have an appropriate selection line, ask the system administrator to indicate what cryptographic mechanisms are being used to protect the integrity of the audit tools. If there is no evidence of integrity protection, this is a finding."
echo -e "Notes related to scan:"
echo "The scanner is missing the 's' in the xattrs requirement in the regex search"

printf "\n"
echo -e "RHEL-08-030660 - RHEL 8 must allocate audit record storage capacity to store at least one week of audit records, when audit records are not immediately sent to a central audit record storage facility."
echo -e "Command:"
echo "grep log_file /etc/audit/auditd.conf"
echo -e "Results:"
grep log_file /etc/audit/auditd.conf
echo -e "STIG Requirement:"
echo "Check the size of the partition to which audit records are written (with the example being /var/log/audit/) with the following command:"
echo -e "Command:"
echo "df -h /var/log/audit/"
echo -e "Results:"
df -h /var/log/audit/
echo -e "STIG Requirement:"
echo "If the audit records are not written to a partition made specifically for audit records (/var/log/audit is a separate partition), determine the amount of space being used by other files in the partition with the following command:"
echo -e "Command:"
echo "du -sh /var/log/audit"
echo -e "Results:"
du -sh /var/log/audit
echo -e "STIG Requirement:"
printf "If the audit record partition is not allocated for sufficient storage capacity, this is a finding.\n\nNote: The partition size needed to capture a week of audit records is based on the activity level of the system and the total storage capacity available.\n"
echo -e "Notes related to scan:"
echo "Manual Review"

printf "\n"
echo -e "RHEL-08-030690 - The RHEL 8 audit records must be off-loaded onto a different system or storage media from the system being audited."
echo -e "Command:"
echo "grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
echo -e "Results:"
grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo -e "STIG Requirement:"
echo "If a remote server is not configured, or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media."
echo -e "Notes related to scan:"
echo "This is a temp placeholder.  A Splunk forwarder will be configured on final VMs built from this image"

printf "\n"
echo -e "RHEL-08-030700 - RHEL 8 must take appropriate action when the internal event queue is full."
echo -e "Command:"
echo "grep -i overflow_action /etc/audit/auditd.conf"
echo -e "Results:"
grep -i overflow_action /etc/audit/auditd.conf
echo -e "STIG Requirement:"
echo "If the value of the 'overflow_action' option is not set to 'syslog', 'single', 'halt', or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media."
echo -e "Notes related to scan:"
echo "Currently set to SYSLOG in all caps and that triggers scan.  Fixed in latest Ansible stig-update role"

printf "\n"
echo -e "RHEL-08-030710 - RHEL 8 must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited."
echo -e "Command:"
echo 'grep -i '$DefaultNetstreamDriver' /etc/rsyslog.conf /etc/rsyslog.d/*.conf'
echo -e "Results:"
grep -i '$DefaultNetstreamDriver' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo -e "STIG Requirement:"
echo "If the value of the '$DefaultNetstreamDriver' option is not set to 'gtls' or the line is commented out, this is a finding."
echo -e "Command:"
echo 'grep -i '$ActionSendStreamDriverMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf'
echo -e "Results:"
grep -i '$ActionSendStreamDriverMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo -e "STIG Requirement:"
printf "If the value of the "$ActionSendStreamDriverMode" option is not set to "1" or the line is commented out, this is a finding.\nIf either of the definitions above are set, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.\n"
echo -e "Notes related to scan:"
echo "Scanner triggers off of there not being any files in /etc/rsyslog.d/  The proper setting is in /etc/rsyslog.conf"

printf "\n"
echo -e "RHEL-08-030720 - grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
echo -e "Command:"
echo 'grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf'
echo -e "Results:"
grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
echo -e "STIG Requirement:"
printf "If the value of the "$ActionSendStreamDriverAuthMode" option is not set to "x509/name" or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.\nIf there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding.\n"
echo -e "Notes related to scan:"
echo "Scanner triggers off of there not being any files in /etc/rsyslog.d/  The proper setting is in /etc/rsyslog.conf"

printf "\n"
echo -e "RHEL-08-030740 - RHEL 8 must securely compare internal information system clocks at least every 24 hours with a server synchronized to an authoritative time source, such as the United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
echo -e "Command:"
echo 'grep maxpoll /etc/chrony.conf'
echo -e "Results:"
grep maxpoll /etc/chrony.conf
echo -e "STIG Requirement:"
printf "If the "maxpoll" option is set to a number greater than 16 or the line is commented out, this is a finding.\nVerify the "chrony.conf" file is configured to an authoritative DoD time source by running the following command:\n"
echo -e "Command:"
echo 'grep -i server /etc/chrony.conf'
echo -e "Results:"
grep -i server /etc/chrony.conf
echo -e "STIG Requirement:"
echo "If the parameter "server" is not set or is not set to an authoritative DoD time source, this is a finding."
echo -e "Notes related to scan:"
echo "Scan appars to be looking specifically for a ntp server at 0.us.pool.ntp.org rather than a local time source"

printf "\n"
echo -e "RHEL-08-040004 - RHEL 8 must enable mitigations against processor-based vulnerabilities."
echo -e "Command:"
echo 'grub2-editenv - list | grep pti'
echo -e "Results:"
grub2-editenv - list | grep pti
echo -e "STIG Requirement:"
echo "If the "pti" entry does not equal "on", is missing, or the line is commented out, this is a finding."
echo -e "Command:"
echo 'grep audit /etc/default/grub'
echo -e "Results:"
grep audit /etc/default/grub
echo -e "STIG Requirement:"
echo "If "pti" is not set to "on", is missing or commented out, this is a finding."
echo -e "Notes related to scan:"
echo "Correct output appears in scan output"

printf "\n"
echo -e "RHEL-08-040030 - RHEL 8 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments."
echo -e "Command:"
echo 'firewall-cmd --list-all-zones'
echo -e "Results:"
firewall-cmd --list-all-zones
echo -e "STIG Requirement:"
printf "Ask the System Administrator for the site or program Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA). Verify the services allowed by the firewall match the PPSM CLSA.\nIf there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding."
echo -e "Notes related to scan:"
echo "Scan shows firewall not running.  Must reboot VM after running hardening playbook to restart multiple services"

printf "\n"
echo -e "RHEL-08-040060"
echo -e "Notes related to scan:"
echo "This specific STIG ID was removed as of V1 R2 of the DISA RHEL8 STIG.  The scanner plugin in based upon V1 R1.  Current STIG is V1 R3 released 26 July 2021"

printf "\n"
echo -e "RHEL-08-040070 - The RHEL 8 file system automounter must be disabled unless required."
echo -e "Command:"
echo 'systemctl status autofs'
echo -e "Results:"
systemctl status autofs
echo -e "STIG Requirement:"
echo "If the "autofs" status is set to "active" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."
echo -e "Notes related to scan:"
echo "The autofs service is not installed and therefore can not be either enabled or disabled"

printf "\n"
echo -e "RHEL-08-040090 - A RHEL 8 firewall must employ a deny-all, allow-by-exception policy for allowing connections to other systems."
echo -e "Command:"
echo ' firewall-cmd --state'
echo -e "Results:"
firewall-cmd --state
echo -e "Command:"
echo 'firewall-cmd --get-active-zones'
echo -e "Results:"
firewall-cmd --get-active-zones
echo -e "Command:"
echo 'firewall-cmd --info-zone=mint| grep target'
echo -e "Results:"
firewall-cmd --info-zone=mint| grep target
echo -e "STIG Requirement:"
echo "If no zones are active on the RHEL 8 interfaces or if the target is set to a different option other than "DROP", this is a finding."
echo -e "Notes related to scan:"
echo "Scan shows firewall not running.  Must reboot VM after running hardening playbook to restart multiple services"

printf "\n"
echo -e "RHEL-08-040150 - A firewall must be able to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring RHEL 8 can implement rate-limiting measures on impacted network interfaces."
echo -e "Command:"
echo 'systemctl status nftables.service'
echo -e "Results:"
systemctl status nftables.service
echo -e "STIG Requirement:"
echo "Verify "firewalld" has "nftables" set as the default backend:"
echo -e "Command:"
echo 'grep -i firewallbackend /etc/firewalld/firewalld.conf'
echo -e "Results:"
grep -i firewallbackend /etc/firewalld/firewalld.conf
echo -e "STIG Requirement:"
echo "If the "nftables" is not active, running and set as the "firewallbackend" default, this is a finding."
echo -e "Notes related to scan:"
echo "Scan shows nftables not running.  Must reboot VM after running hardening playbook to restart multiple services"

printf "\n"
echo -e "RHEL-08-040300 - The RHEL 8 file integrity tool must be configured to verify extended attributes."
echo -e "Command:"
echo 'cat /etc/aide.conf'
echo -e "Results:"
cat /etc/aide.conf
echo -e "STIG Requirement:"
echo "Check the "aide.conf" file to determine if the "xattrs" rule has been added to the rule list being applied to the files and directories selection lists."
echo -e "Notes related to scan:"
echo "The aide.conf file uses variables to set what it checks for on files and directories.  The scan shows that the file use CONTENT_EX which maps to FIPSR.  The FIPSR variable is mapped to the actual attributes that enable specific aide checks.  This does include xattrs."

printf "\n"
echo -e "RHEL-08-040310 - The RHEL 8 file integrity tool must be configured to verify Access Control Lists (ACLs)."
echo -e "Command:"
echo 'cat /etc/aide.conf'
echo -e "Results:"
cat /etc/aide.conf
echo -e "STIG Requirement:"
echo "If the "acl" rule is not being used on all selection lines in the "/etc/aide.conf" file, is commented out, or ACLs are not being checked by another file integrity tool, this is a finding."
echo -e "Notes related to scan:"
echo "The aide.conf file uses variables to set what it checks for on files and directories.  The scan shows that the file use CONTENT_EX which maps to FIPSR.  The FIPSR variable is mapped to the actual attributes that enable specific aide checks.  This does include acl."

printf "\n"
echo -e "RHEL-08-040350 - If the Trivial File Transfer Protocol (TFTP) server is required, the RHEL 8 TFTP daemon must be configured to operate in secure mode."
echo -e "Command:"
echo 'yum list installed tftp-server'
echo -e "Results:"
yum list installed tftp-server
echo -e "STIG Requirement:"
printf "If a TFTP server is not installed, this is Not Applicable.\nIf a TFTP server is installed, check for the server arguments with the following command:\n"
echo -e "Command:"
echo 'grep server_args /etc/xinetd.d/tftp'
echo -e "Results:"
grep server_args /etc/xinetd.d/tftp
echo -e "STIG Requirement:"
echo "If the "server_args" line does not have a "-s" option, and a subdirectory is not assigned, this is a finding."
echo -e "Notes related to scan:"
echo "The tftp-server is not installed, so there will not bea /etc/xinitd.d/tftp file for the scanner to check."

printf "\n"
echo -e "RHEL-08-010100 - RHEL 8, for certificate-based authentication, must enforce authorized access to the corresponding private key."
echo -e "Command:"
echo 'ssh-keygen -y -f /path/to/file'
echo -e "Results:"
echo -e "STIG Requirement:"
echo "If the contents of the key are displayed, this is a finding."
echo -e "Notes related to scan:"
echo "This check can not be automated.  An individual Sysadmin/Security person must inspect the filesystem to find any priviate keys.  This system shouldn't have any private keys on it as no keys should have been generated there.  There are public keys that were installed to allow ansible to harden the system as well as allow access from the Nessus scanner without a password."

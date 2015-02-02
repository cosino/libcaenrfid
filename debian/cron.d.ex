#
# Regular cron jobs for the libcaenrfid package
#
0 4	* * *	root	[ -x /usr/bin/libcaenrfid_maintenance ] && /usr/bin/libcaenrfid_maintenance

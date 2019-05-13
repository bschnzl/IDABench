##############################################################################
#                                                                            #
#   idabench is public domain software and may be freely used and           #
#   distributed with or without modification.                                #
#                                                                            #
#   See file "idabench.terms" for DISCLAIMER OF ALL WARRANTIES.             #
#                                                                            #
##############################################################################
# site.ph        idabench-1.0

# Variables needed by the analyzer scripts. Tailor this file to define the 
# paths for different sensor sites.
#

use POSIX qw(strftime);
use Time::Local;

# $SITE is the name that the analyzer will use to refer to this source of
# packet capture data. It will be used to create subdirectories under the 
# analyzer directory and the web pages that IDABench creates to display the
# data. It need not be the same as the sensor SITEx_NAME

$SITE="site0";

# We need to know the account name that is used on the sensor for storage of
# the packet capture files. The analyzer will use this account name to ssh
# and scp files from the sensor.

$SENSOR_USER="idabench";

# Put here the name or address of the machine on which the idabench sensor is
# located. The analyzer fetches the raw data from the sensor hourly via crond.

$SENSOR="127.0.0.1";

# Change the following line to reflect the directory on your sensor in which
# the raw sensor data is stored. This is NOT the analyzer storage path.

$SENSOR_DIR="/var/log/idabench/site0";

# Set the following variable to the name you want to see for this site in
# cgi forms, or leave it as $SITE 

$SITE_FORM_LABEL="$SITE";

# The xSCAN_THRESHOLD settings are the number of different destination
# addressess or ports that a "foreign" machine can contact before it is listed
# as a possible scanner.

$HOSTSCAN_THRESHOLD="5";
$PORTSCAN_THRESHOLD="20";

# Should we attempt to resolve addresses to names in the hourly webpage output?
# Please note that this can be a tipoff to an attacker that you are running
# some kind of hourly logging process, should they be monitoring their incoming
# nameserver traffic. Additionally, resolving addresses can take quite a long
# time, especially if your analyzer is not connected to the outside world!

$resolve_names="no";

# Set the following variable to the number of days you want to keep the
# raw data files on your sensor's disks before the cleanup.pl script removes
# them. It depends on the sizes of your files, the amount of sensor disk 
# space, and your taste.

$CLEAN_TIME="3";

# Which search plugin would you like selected by default when first opening a
# new search window? This is optional and will default to the first appearing
# alphabetically in the site's config directory.

$SEDEFAULT = "tcpdump";


###############################################################################
# The following settings are relative to global paths set in idabench.conf    #
# It is advised that you do NOT change these unless you know exactly what you #
# are doing. The defaults will work for 99.9% of all installations, and       #
# changing them stands a very good chance of breaking things.                 #
###############################################################################


# The following line reflects the directory on your analyzer machine into 
# which the raw sensor data is fetched. The variable $IDABENCH_RAW_DATA_PATH
# is defined in /usr/local/idabench/etc/idabench.conf.
# Leave this alone unless you have good reason not to.

$ANALYZER_DIR="$IDABENCH_RAW_DATA_PATH/$SITE";

# The following line reflects the directory where web pages are created which
# hold the filtered data.  The variable $IDABENCH_WEB_PAGES_PATH is defined in 
# /usr/local/idabench/etc/idabench.conf.
# Leave this alone unless you have good reason not to.
 
$OUTPUT_WEB_DIR="$IDABENCH_WEB_PAGES_PATH/$SITE";

# The following variable reflects the relative path from the DocumentRoot 
# variable defined in the Apache configuration files to the actual html files.
# The variable $IDABENCH_REL_WEB_PAGES_ROOT is defined in 
# /usr/local/idabench/etc/idabench.conf.
# Leave this alone unless you have good reason not to.

$URL_OUTPUT_DIR="$IDABENCH_REL_WEB_PAGES_ROOT/$SITE";

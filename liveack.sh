#!/bin/sh

# Live Acquisition Script for Desktop Forensics
# Tested on Ubuntu, OSX
# can we pull up dns cache?


# ****************** Global Variables *****************************

$reportoutputpath = "$HOME/desktop/liveack"
$reportoutput = "$HOME/desktop/liveack/$HOSTNAME.txt"


# ********************** Functions ************************************

menu ()
{
clear
echo " *nix Live Forensic Acquisition Script"
echo " "
echo "	1.  Pull System Configuration Info"
echo "	2.  Pull Startup Info"
echo "	3.  Pull /Proc Info"
echo "	4.  Pull /Dev Info"
echo "	5.  Pull Running Process Info"
echo "	6.  Pull System Logs"
echo "	7.  Perform All Tasks Above"
echo "	8.  Image Drive/Partitions"
echo "	9.  List Files For A Particular User"
echo "	10. List Interesting Files"
echo "	11. List Files Created/Modified For Date Range"
echo "	12. Hash All Files For A Particular Directory"
echo "	13. Perform Memory Dump"
echo "	14. Perform Network Dump"
echo "	15. Quit"
echo

read choice
case "$choice" in
1)
	configinfo
;;
2)
	startupinfo
;;
3)
	procinfo
;;
4)
	devinfo
;;
5)
	processinfo 
;;
6)
	loginfo
;;
7)
	configinfo startupinfo procinfo devinfo processinfo loginfo
;;
8)
	imagedrive
;;
9)
	userinfo
;;
10)
	fileinfo
;;
11)
	filebydate
;;
12)
	hashdir
;;
13)
	memoryinfo
;;
14)
	networkinfo
;;
15)
	finish
;;
esac
}


configinfo ()
{
echo "**** Pulling System Configuration ****" >> $reportoutput 
echo date >> $reportoutput 
echo "Kernel Version:" >>$reportoutput
echo uname -a >>$reportoutput 
echo " " >>$reportoutput
if uname like "*debian*"
	then echo "OS Version:" >> $reportoutput
		cat /etc/issue >> $reportoutput
fi
echo " " >>$reportoutput
echo "System Uptime:" >>$reportoutput
echo w >>$reportoutput
echo " " >>$reportoutput
echo "Installed Packages:" >>$reportoutput
if uname like "*debian*"
	then echo dpkg --get-selections >>$reportoutput
elif uname like "*Darwin*"
	then echo ls -la /Applications >>$reportoutput
fi
echo " " >>$reportoutput
echo "/etc/hosts file:" >> $reportoutput
cat /etc/hosts >> $reportoutput
echo " " >>$reportoutput
echo "Users and Groups:" >>$reportoutput
echo last >>$reportoutput
if uname like "*debian*"
	then echo lastb >>$reportoutput
fi
cat /etc/passwd >>$reportoutput
if uname like "*debian*"
	then cat /etc/shadow >>$reportoutput
fi
cat /etc/group >>$reportoutput
echo " " >>$reportoutput
echo "Network Information:"
if uname like "*debian*"
	then echo netstat -anp >> $reportoutput
		echo route >> $reportoutput
elif uname like "*Darwin*"
	then echo netstat -an >> $reportoutput
fi
echo ifconfig -a >> $reportoutput
echo netstat -rn >> $reportoutput
echo arp -a >> $reportoutput
echo " " >>$reportoutput
echo "Memory Information:"
if uname like "*debian*"
	then echo free >> $reportoutput
fi
echo " " >>$reportoutput
echo "Drive information"
echo df -h >> $reportoutput
echo mount >> $reportoutput
if uname like "*debian*"
	then echo stat -f / >>$reportout
	echo file -sL /dev/sd* >>$reportout
fi
echo " " >>$reportoutput
}

startupinfo ()
{
echo "**** Pulling Startup information ****" >> $reportoutput
echo date >> $reportoutput
echo " " >>$reportoutput
}

procinfo ()
{
echo "**** Pulling /Proc information" >> $reportoutput
echo date >> $reportoutput
echo " " >>$reportoutput
}

devinfo ()
{
echo "**** Pulling /Dev information" >> $reportoutput
echo date >> $reportoutput
echo ls -la /Dev >>$reportoutput
echo " " >>$reportoutput
}

processinfo ()
{
echo "**** Pulling Running Processes ****" >> $reportoutput
echo date >> $reportoutput
echo "Running Processes:" >> $reportoutput
if uname like "*Darwin*"
	then echo ps -ef >> $reportoutput
elif uname like "debian*"
	then echo ps -aux >> $reportoutput
fi
# ps env?
# ps tree?
echo " "
echo "Loaded Drivers:" >> $reportoutput
if uname like "*debian*"
	then echo lsmod >> $reportoutput
elif uname like "*bsd*"
	then echo kldstat >>$reportoutput
else echo "Unable to determine OS :("
fi
echo " "
echo "Open Handles and Files:" >> $reportoutput
echo lsof -V >> $reportoutput
echo " " >>$reportoutput
}

loginfo ()
{
echo "**** Pulling Logs ****" >> $reportoutput
echo date >> $reportoutput
find /var/log -type f -regextype posix-extended -regex '/var/log/[a-zA-Z\.]+(/[a-zA-Z\.]+)*' >>$reportoutputpath
echo " " >>$reportoutput
}

imagedrive ()
{
echo "**** Imaging Drive ****" >> $reportoutput
echo date >> $reportoutput
mount
echo "What drive would you like to image?"
read drive
	dcfldd if=/dev/$drive of=$drive.img bs=8k hash=sha256 hashwindow=10G hashlog=$drive.hashes conv=noerror,sync
	# Or if you have a linux host in Virtualbox you woud like imaged:
	# vboxmanage clonehd <virtual disk image file>.vmdk <output raw image file>.vmdk --format RAW 
echo " " >>$reportoutput
}

userinfo()
{
echo "**** Pulling User Profile information ****" >> $reportoutput
echo date >> $reportoutput
echo "What user's profile do you need? (full path)"
read targetuser
	cat $targetuser/.bash_history >>$reportoutput
	cat $targetuser/.bash_profile >>$reportoutput
	cat $targetuser/.bash_logout >>$reportoutput
	cat $targetuser/.bashrc >>$reportoutput
	cat $targetuser/.ssh/known_hosts >>$reportoutput
	cat $targetuser/.putty/sshhostkeys >>$reportoutput
	find / -user $targetuser -xdev -type f -exec sha1sum -b {} >>$reportoutput
echo " " >>$reportoutput
}

fileinfo ()
{
echo "**** Pulling Interesting File Information ****" >> $reportoutput
echo date >> $reportoutput
find / -name *.gz -xdev -type f -exec sha1sum -b {} >>$reportoutput
find / -name *.c -xdev -type f -exec sha1sum -b {} >>$reportoutput
# get executable files
# get non-exec files with no extension
# files over X size
# any .something files
# check out various IOCs for more places to look
# Encrypted files?
echo " " >>$reportoutput
}

filebydate()
{
echo "**** Pulling all files for certain date ****" >> $reportoutput
echo date >> $reportoutput
echo "What starting date range to you need?"
read startdate
echo "What ending date range to you need?"
read enddate
	find / -date $enddate >>$reportoutputpath 
echo " " >>$reportoutput
}

hashdir()
{
echo "**** Pulling Hash for all files in a directory ****" >> $reportoutput
echo date >> $reportoutput
echo "What directory do you need hashes for?"
read hashdir
	find $hashdir -xdev -type f -exec sha1sum -b {} >>$reportoutput
	# Also sort by inode to see if any gaps (mostly for system dirs /bin or /sbin)
	echo ls -aliR $hashdir bin | sort -n >>$reportoutput
echo " " >>$reportoutput
}

memoryinfo ()
{
echo "**** Pulling Memory Dump ****" >> $reportoutput
echo date >> $reportoutput
# use this to build correct version of LiME for target - NOT on target machine (check uname)!!!!
# git clone https://github.com/504ensicsLabs/LiME
# cd /LiME
# cd src
# make -C /lib/modules/3.16.0-34-generic/build M=$PWD
# mv lime.ko lime-3.16.0-34-generic.ko
sudo insmod lime-3.16.0-34-generic.ko "path=$reportoutputpath\memdump format=lime"
echo " " >>$reportoutput
}

networkinfo ()
{
echo "**** Pulling Network Dump ****" >> $reportoutput
echo date >> $reportoutput
echo "How many minutes of traffic do you need?"
read dumptime
	tcpdump $dumptime >>$reportoutputpath\tcpdump_$now.dump
echo " " >>$reportoutput
}

finish ()
{
echo "Finished Acquisition" >> $reportoutput
echo date >> $reportoutput
}

menu
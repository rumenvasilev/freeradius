#!/usr/bin/perl
### DESCRIPTION
#
#  This script is used to change the password of wireless SSID mydomain-Guest
#  in Sofia office. It will require a change in $oid if the controller access point
#  is replaced with a dedicated wireless controller.
#  It is set to change the password via SNMP v3 and send an email to the office assistant.
#  In case of error, additional admin email is set so it can be notified on time.
#  Credits go to ice4o@hotmail.com
#  If you have any suggestions, complains ping me via email.
#
#  Version is 1.2
#

#use strict;
#use warnings;
#use diagnostics;
use POSIX qw/strftime/;;
use Net::SNMP;

# program logic
#	create new random string
#	set the password via snmp
#	verify the password
#	email the password
#

### CONFIGURATION PARAMTERS
# Turn email notification on or off
my $prg_notify = "yes";	# yes/no
my $email = "reception\@mydomain.com";
my $cc = "email1\@mydomain.com, email2\@mydomain.com";
my $sysemail = "sysemail\@mydomain.com";
my $adminemail = "admin\@mydomain.com";
my $sendmail = "/usr/sbin/sendmail";
# Program email
my $err_log_file = "/var/log/wifi-guest.log";
my $password_length = 10;	# password symbol length
my $oid = "1.3.6.1.4.1.1916.2.131.50.1.3.4.1.1.24.5.71.117.101.115.116";	# oid of guest ssid pwd
## end configuration

use constant {
	SNMPhost			=>	'1.1.1.1',
	SNMPuser			=>	"snmpmanager",
	SNMPauthpwd		=>	"wif1gUes1",
	SNMPauthproto	=>	"md5",
	SNMPauthencryption	=>	'DES'
};


&connectSNMP();
sub connectSNMP
{
	# connection
	my ($session, $error) = Net::SNMP->session(
		-hostname => SNMPhost,
		-version => 3,
		-retries => 2,
		-username => SNMPuser,
		-authpassword => SNMPauthpwd,
		-authprotocol => SNMPauthproto,
		-privpassword => SNMPauthpwd,
		-privprotocol => SNMPauthencryption
	);
	
	if (!defined($session)) {
		my $err = $session->error();
		#send notification to admin-email
		&_err_mail($newpwd, $err);
		&_err_log("ERR: Password re-set FAILED! Code: 0x01");
		$session->close();
		exit 1;
   }
	
	# set new password
	my $newpwd = &generate_random_string($password_length);	
	sub _new_pwd
	{
		my $submit = $session->set_request(-varbindlist => [ $oid, OCTET_STRING, $newpwd]); 
		if (!defined($submit)) {
			my $err = $session->error();
			$session->close();
			#send notification to admin-email
			&_err_log("ERR: Password re-set FAILED! Code: 0x02");
			&_err_mail($newpwd, $err);
			exit 1;
   	}
   }
	
	# check new password
	sub _chk_pwd
	{	
		my $check = $session->get_request(-varbindlist => [ $oid ]);
		if (!defined($check)) {
			printf "ERROR: %s.\n", $session->error();
			$session->close();
			exit 1;
   	}
   	return $check->{$oid};
   }
	
	_new_pwd();
	my $resp = _chk_pwd();
	
	# verify the new password is set
   my $retry = 0;
   while ($retry <= 1) {
		if ($newpwd eq $resp) {
			&_err_log("MSG: The password for guest SSID has been changed.");
			&_err_mail($newpwd, "no");
			#print "MSG: New password has been set.\n";
			$session->close();
			exit;
		} else {
			&_err_log("ERR: Password re-set has failed. Trying to re-set again! Code: 0x03");
			#print "ERR: Password re-set has failed. Trying to re-set it again!\n";
			$retry = $retry+1;
			sleep(5);
			_new_pwd();
   		_chk_pwd();
		}
	}
   
	$session->close();

}

# This function generates random strings of a given length
# Usage: generate_random_string($length) -> $length = characters count used
sub generate_random_string
{
	my $length_of_randomstring=shift;# the length of 
			 # the random string to generate

	my @chars=('a'..'z','A'..'Z','0'..'9','_','@','$','%','-','#','!',';','+');
	my $random_string;
	foreach (1..$length_of_randomstring) 
	{
		# rand @chars will generate a random 
		# number between 0 and scalar @chars
		$random_string.=$chars[rand @chars];
	}
	return $random_string;
}

# Email the new data
# Usage: _err_mail($newpassword, 1) -> 1 error
sub _err_mail
{
	my ($pwd, $error) = @_;
	my $time = strftime('%d-%m-%Y %H:%M:%S',localtime);
	my $mail = '';
	if ($error eq "no") {
	
		$cc = "CC: ".$cc;
		$email = $email."\n".$cc;
		$mail = "Dear user, \n\n";
		$mail .= "Password for wireless connection mydomain-guest has been changed at $time.\n\n";
		$mail .= "The new password is \"$pwd\".\n\n";
		$mail .= "Thank you for your attention!\n";
		$mail .= "Have a nice day!";

	} else {

		$email = $adminemail;
		$mail = "Dear administrator, \n\n";
		$mail .= "I was unable to re-set the password for SSID mydomain-guest at $time.\n";
		$mail .= "Error message, returned by SNMP host was:\n\n\t$error\n\n";
		$mail .= "Thank you for your attention!\n";
		$mail .= "Have a nice day!";
			
	}
	
	# add timestamp in the beginning of the message
	my $message = qq(From: "System - WiFi Guest"\nTo: $email\nSubject: New WIFI credentials\n) . $mail;
	if ($prg_notify eq "yes") {
		open(MAIL, "| $sendmail -t") or &_err_log("ERR: Cannot send email due to the following error: $_");
		print MAIL $message;
		if ($error eq "no") {
			&_err_log("MSG: The new credentials were sent to $email.");
		} else {
			&_err_log("ERR: Error notification has been sent to admin email at $email.");
		}

		close(MAIL);
	} else {
		print "$message\n";
		exit;
	}
}

## Program logger
# Usage: _err_log($msg) -> $msg = "message I would like to log"
sub _err_log
{
	my $msg = shift;
	# add timestamp to the message
	$msg = strftime('%d-%b-%Y %H:%M:%S',localtime) . " " . $msg . "\n";
	
	if (-e $err_log_file) {
		if (-w $err_log_file) {
			# File exist so we just append
			open(LOG, ">>$err_log_file");
			printf LOG "$msg";
			close(LOG);
		} else {
			# Log file not writable by the current user
			print "Error, cannot append to file: $err_log_file\n";
			exit;
		}
	} else {
		# File does not exist so we create it for the first time
		open(LOG, ">$err_log_file") or die("Error, cannot create $err_log_file\n");
		printf LOG "$msg";
		close(LOG);
	}
}

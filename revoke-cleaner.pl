#!/usr/bin/perl
# Author @nu11secur1ty
use strict;
use warnings;
use diagnostics;
use Term::ANSIColor;

print color('GREEN');
print "You should remove all lines which you see on this print with the path";
print color('RESET');

print color('BLUE');
print " (/etc/openvpn/easy-rsa/pki/index.txt)\n";
print color('RESET');

print color('GREEN');
print "because these users are already"; 
print color('RESET'); 

print color('RED'); 
print " revoked!\n";
print color('RESET');

print color('GREEN');
print "If you do not see lines with (R) in the beginning, you will have nothing to clean!\n\n\n"; 
print color('RESET');

my $ENV = `cat /etc/openvpn/easy-rsa/pki/index.txt | grep R`;
	print "$ENV";

print color('Yellow'); 
print "This is your issued crt's\n";
print color('RESET');

my $issued = `ls -all /etc/openvpn/easy-rsa/pki/issued/`;
	print "$issued";

## Cleaning
my $ENVPKI = "/etc/openvpn/easy-rsa/pki/index.txt";
	print "Preparing for cleaning...\n";

print color('RED'); 
print "Please, choose the username, or if you are not really sure, just press Enter to exit the cleaner...\n";
print color('RESET');

chomp (my $username = <STDIN>);
	my $cleaner = `sed -i '/$username/d' $ENVPKI`;

print color('YELLOW');
print"You clint configurations are...\n";
print color('RESET');
my $configs = `ls -all /etc/openvpn/client/`;
	print"$configs";
	exit 0;

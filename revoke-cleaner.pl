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
print " revoked!\n\n\n";
print color('RESET');

my $ENV = `cat /etc/openvpn/easy-rsa/pki/index.txt | grep R`;
print "$ENV";

print color('Yellow'); 
print "This is your issued crt's\n";
print color('RESET');

my $issued = `cat /etc/openvpn/easy-rsa/pki/issued/`;
print "$issued";

## Cleaning
my $ENVPKI = "/etc/openvpn/easy-rsa/pki/index.txt";
print "Preparing for cleaning...\n";
print "Please, choose the username...\n";

chomp (my $username = <STDIN>);
my $cleaner = `sed -i '/$username/d' $ENVPKI`;

	exit 0;

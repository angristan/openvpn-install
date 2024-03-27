#!/usr/bin/perl
use strict;
use warnings;
use diagnostics;

my $clients = `cp -avr /etc/openvpn/client/* /var/www/html/`;
print "$clients"
my $open_aapache = `systemctl start apache2.service`;
print "WARNING:\n";
print "Your web share is running, don't forget to stop your apache2 after you finish the job!"

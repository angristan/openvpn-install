#!/usr/bin/perl
use strict;
use warnings;
use diagnostics;

my $clients = `cp -avr /etc/openvpn/client/* /var/www/html/`;
print "$clients"

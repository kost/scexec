#!/usr/bin/perl

binmode STDIN;
binmode STDOUT;
$/ = undef;

use strict;
use MIME::Base64;
my $enc=encode_base64(<>);
$enc=~ s/\R//g; 
print $enc;

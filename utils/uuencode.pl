#!/usr/bin/perl

binmode STDIN;
binmode STDOUT;
$/ = undef;

my $uue = pack u, <>; 
$uue=~ s/\R//g; 
print "${uue}"

#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Net::IP::Range' )
        or BAIL_OUT;
}

diag( "Testing Net::IP::Range $Net::IP::Range::VERSION, Perl $], $^X" );

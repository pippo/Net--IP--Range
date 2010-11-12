#!perl -T

use Test::More tests => 9;
use Test::Exception;

use Net::IP::Range;


my $range;

lives_ok {
        $range = Net::IP::Range->new( cidr => '1:2:3:4::/64' );
    } 'new(): cidr v6, range parses okay';

ok( $range, 'new(): cidr v6, instantiates' );
is(
    $range && $range->min_addr->unpacked,
    "00010002000300040000000000000000",
    'new(): cidr v6, min_addr is ok'
);
is(
    $range && $range->max_addr->unpacked,
    "0001000200030004ffffffffffffffff",
    'new(): cidr v6, max_addr is ok '
);


# CIDR, v4

lives_ok {
        $range = Net::IP::Range->new( cidr => '192.168.10.0/24' );
    } 'new(): cidr v4, range parses okay';

ok( $range, 'new(): cidr v4, instantiates' );
is(
    $range && $range->min_addr->unpacked,
    "c0a80a00",
    'new(): cidr v4, min_addr is ok'
);
is(
    $range && $range->max_addr->unpacked,
    "c0a80aff",
    'new(): cidr v4, max_addr is ok '
);

throws_ok {
    $range = Net::IP::Range->new( cidr => '192.168.10.1/24' )
    } qr/bad range/, 'new(): cidr v4, bad cidr fails';

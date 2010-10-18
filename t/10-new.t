#!perl -T

use Test::More tests => 9;
use Test::Exception;

BEGIN {
    use_ok( 'Net::IP::Range' ) or die;
}


my $range;

lives_ok {
        $range = Net::IP::Range->new( cidr => '1:2:3:4::/64' );
    } 'new(): cidr v6, range parses okay';

ok( $range, 'new(): cidr v6, instantiates' );
is(
    $range && unpack('H*', $range->first),
    "00010002000300040000000000000000",
    'new(): cidr v6, first is ok'
);
is(
    $range && unpack('H*', $range->last),
    "0001000200030004ffffffffffffffff",
    'new(): cidr v6, last is ok '
);


# CIDR, v4

lives_ok {
        $range = Net::IP::Range->new( cidr => '192.168.10.0/24' );
    } 'new(): cidr v4, range parses okay';

ok( $range, 'new(): cidr v4, instantiates' );
is(
    $range && unpack('H*', $range->first),
    "c0a80a00",
    'new(): cidr v4, first is ok'
);
is(
    $range && unpack('H*', $range->last),
    "c0a80aff",
    'new(): cidr v4, last is ok '
);

throws_ok {
    $range = Net::IP::Range->new( cidr => '192.168.10.1/24' )
    } 'new(): cidr v4, bad cidr fails';


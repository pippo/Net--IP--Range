#!perl -T

use Test::More tests => 30;

use Net::IP::Range;


my $test_ip1    = '1:2:3:4::1';
my $test_ip2    = '1:2:3:4::ff';
my $test_ip_fst = '1:2:3:4::';
my $test_ip_lst = '1:2:3:4:ffff:ffff:ffff:ffff';
my $test_bad_ip = '1:2:4:4::1f';

my $test_v4_ip1    = '192.168.1.10';
my $test_v4_ip2    = '192.168.1.80';
my $test_v4_ip_fst = '192.168.1.0';
my $test_v4_ip_lst = '192.168.1.255';
my $test_v4_bad_ip = '192.168.2.1';

my $range = Net::IP::Range->new( cidr => '1:2:3:4::/64' );

SKIP: {
    skip 'No instance to test with.', 15
        unless $range;

    my $rc = $range->occupy($test_ip1, 'host1');
    is( $rc, 1, 'occupy succeeds' );
    is( $range->lookup($test_ip1), 'host1', 'address is really occupied');

    $rc = $range->occupy($test_ip2, 'host2');
    is( $rc, 1, 'occupy succeeds' );
    is( $range->lookup($test_ip2), 'host2', 'address is really occupied');

    $rc = $range->occupy($test_ip2, 'host3');
    is( $rc, undef, 'occupying busy ip fails' );
    is( $range->lookup($test_ip2), 'host2', 'occupying busy ip doesnt overwrite');

    $rc = $range->occupy($test_ip_fst, 'first-host');
    is( $rc, 1, 'occupying first ip succeeds' );
    is( $range->lookup($test_ip_fst), 'first-host', 'first ip is really occupied');

    $rc = $range->occupy($test_ip_lst, 'last-host');
    is( $rc, 1, 'occupying last ip succeeds' );
    is( $range->lookup($test_ip_lst), 'last-host', 'last ip is really occupied');

    $rc = $range->occupy($test_bad_ip, 'some-host');
    is( $rc, undef, 'occupy (not in range) fails' );

    $rc = $range->free($test_ip1);
    is( $rc, 1, 'free succeeds' );
    is( $range->lookup($test_ip1), undef, 'address is really free');

    $rc = $range->free($test_ip1);
    is( $rc, undef, 'freeing free addr fails' );

    $rc = $range->free($test_bad_ip);
    is( $rc, undef, 'freeing bad (not in range) addr fails' );
}


##
## V4
##

$range = Net::IP::Range->new( cidr => '192.168.1.0/24' );

SKIP: {
    skip 'No instance to test with.', 15
        unless $range;

    my $rc = $range->occupy($test_v4_ip1, 'host1');
    is( $rc, 1, 'occupy v4 succeeds' );
    is( $range->lookup($test_v4_ip1), 'host1', 'v4 address is really occupied');

    $rc = $range->occupy($test_v4_ip2, 'host2');
    is( $rc, 1, 'occupy v4 succeeds' );
    is( $range->lookup($test_v4_ip2), 'host2', 'v4 address is really occupied');

    $rc = $range->occupy($test_v4_ip2, 'host3');
    is( $rc, undef, 'occupying busy v4 ip fails' );
    is( $range->lookup($test_v4_ip2), 'host2', 'occupying busy v4 ip doesnt overwrite');

    $rc = $range->occupy($test_v4_ip_fst, 'first-host');
    is( $rc, 1, 'occupying first v4 ip succeeds' );
    is( $range->lookup($test_v4_ip_fst), 'first-host', 'first v4 ip is really occupied');

    $rc = $range->occupy($test_v4_ip_lst, 'last-host');
    is( $rc, 1, 'occupying last v4 ip succeeds' );
    is( $range->lookup($test_v4_ip_lst), 'last-host', 'last v4 ip is really occupied');

    $rc = $range->occupy($test_v4_bad_ip, 'some-host');
    is( $rc, undef, 'occupy v4 (not in range) fails' );

    $rc = $range->free($test_v4_ip1);
    is( $rc, 1, 'free v4 succeeds' );
    is( $range->lookup($test_v4_ip1), undef, 'v4 address is really free');

    $rc = $range->free($test_v4_ip1);
    is( $rc, undef, 'freeing free v4 addr fails' );

    $rc = $range->free($test_v4_bad_ip);
    is( $rc, undef, 'freeing bad (not in range) v4 addr fails' );
}

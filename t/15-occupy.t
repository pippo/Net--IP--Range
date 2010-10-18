#!perl -T

use Test::More tests => 8;

BEGIN {
    use_ok( 'Net::IP::Range' ) or die;
}


my $test_ip1    = '1:2:3:4::10';
my $test_ip2    = '1:2:3:4::ff';
my $test_bad_ip = '1:2:4:4::1f';

my $range = Net::IP::Range->new( cidr => '1:2:3:4::/64' );

SKIP: {
    skip 'No instance to test with.' 7
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

    $rc = $range->occupy($test_bad_ip, 'some-host');
    is( $rc, undef, 'occupy (not in range) fails' );
}


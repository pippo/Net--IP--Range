#!perl -T

use Test::More tests => 32;

use Net::IP::Range;

my $test_ip1 = '1:2:3:4::10';
my $test_ip2 = '1:2:3:4::ff';
my $test_ip3 = '1:2:3:4::';
my $test_ip4 = '1:2:3:4:ffff:ffff:ffff:ffff';

my $range = Net::IP::Range->new( cidr => '1:2:3:4::/64' );

SKIP: {
    skip 'No instance to test with.', 18
        unless $range;

    $range->occupy($test_ip1, 'host1');
    $range->occupy($test_ip2, 'host2');
    $range->occupy($test_ip3, 'host3');
    $range->occupy($test_ip4, 'host4');

    ## occupied

    my $it = $range->iterator_occupied;
    ok( $it, 'got occupied iterator' );
    is( ref $it, 'Net::IP::Range::Iterator', 'iterator package ok' );

    my ( $ip, $host ) = $it->next;
    ok( $ip, 'got first ip' );
    is( ref $ip, 'Net::IP::Range::Item', 'first ip package ok' );
    is( $ip->unpacked, '00010002000300040000000000000000', 'first ip is sane' );
    is( $host, 'host3', 'first host is sane' );

    ( $ip, $host ) = $it->next;
    ok( $ip, 'got second ip' );
    is( ref $ip, 'Net::IP::Range::Item', 'second ip package ok' );
    is( $ip->unpacked, '00010002000300040000000000000010', 'second ip is sane' );
    is( $host, 'host1', 'second host is sane' );

    ( $ip, $host ) = $it->next;
    ok( $ip, 'got third ip' );
    is( ref $ip, 'Net::IP::Range::Item', 'third ip package ok' );
    is( $ip->unpacked, '000100020003000400000000000000ff', 'third ip is sane' );
    is( $host, 'host2', 'third host is sane' );

    ( $ip, $host ) = $it->next;
    ok( $ip, 'got forth ip' );
    is( ref $ip, 'Net::IP::Range::Item', 'forth ip package ok' );
    is( $ip->unpacked, '0001000200030004ffffffffffffffff', 'forth ip is sane' );
    is( $host, 'host4', 'forth host is sane' );

    ## free

    $it = $range->iterator_free;
    ok( $it, 'got free iterator' );
    is( ref $it, 'Net::IP::Range::Iterator', 'iterator package ok' );

    my $subrange = $it->next;
    ok( $subrange, 'got first subrange' );
    is( ref $subrange, 'Net::IP::Range', 'first subrange package ok' );
    is( $subrange->min_addr->unpacked, '00010002000300040000000000000001', 'first subrange min_addr is sane' );
    is( $subrange->max_addr->unpacked, '0001000200030004000000000000000f', 'first subrange max_addr is sane' );

    $subrange = $it->next;
    ok( $subrange, 'got second subrange' );
    is( ref $subrange, 'Net::IP::Range', 'second subrange package ok' );
    is( $subrange->min_addr->unpacked, '00010002000300040000000000000011', 'second subrange min_addr is sane' );
    is( $subrange->max_addr->unpacked, '000100020003000400000000000000fe', 'second subrange max_addr is sane' );

    $subrange = $it->next;
    ok( $subrange, 'got third subrange' );
    is( ref $subrange, 'Net::IP::Range', 'third subrange package ok' );
    is( $subrange->min_addr->unpacked, '00010002000300040000000000000100', 'third subrange min_addr is sane' );
    is( $subrange->max_addr->unpacked, '0001000200030004fffffffffffffffe', 'third subrange max_addr is sane' );
}

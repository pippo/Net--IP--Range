package Net::IP::Range;

use warnings;
use strict;


our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Net::IP::Range', $VERSION);



__END__

=head1 NAME

Net::IP::Range - IP network/range routines

=head1 SYNOPSIS

    use Net::IP::Range;

    my $range = Net::IP::Range->new( cidr => '192.168.10.0/24' );
    # or ...
    $range = Net::IP::Range->new( cidr => 'dead:beaf:aa:bb::/64' );

    # and then something like ...

    $range->occupy( $ip1, 'host1' );
    $range->occupy( $ip2 => 'host2', $ip3 => 'host3' );

    # and perhaps later ...

    $range->free($ip2);

    print "Max addr: ", $range->max_addr;
    print "Min addr: ", $range->min_addr;
    print "Range size: ", $range->size;


    my $it = $range->iterator(ITER_FREE);
    print "Free addresses:\n";
    while ( my $subrange = $it->next ) {
        print
            "\t", $subrange->[0],
            ($subrange->[1] ? "-" . $subrange->[1] : ''), "\n";
    }

    $it = $range->iterator(ITER_OCCUPIED);
    print "Occupied addresses:\n";
    while ( my $addr = $it->next ) {
        print "\t $addr->[0]  - $addr->[1]\n";
    }

=head1 DESCRIPTION

TBD

=head1 AUTHOR

Evgeniy Kosov, C<< <evgeniy at kosov.su> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-ip-range at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-IP-Range>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::IP::Range


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-IP-Range>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-IP-Range>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-IP-Range>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-IP-Range/>

=back

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

Copyright 2010 Evgeniy Kosov.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Net::IP::Range

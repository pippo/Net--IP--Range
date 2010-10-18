use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Net::IP::Range',
    license             => 'perl',
    dist_author         => q{Evgeniy Kosov <evgeniy@kosov.su>},
    dist_version_from   => 'lib/Net/IP/Range.pm',
    build_requires => {
        'Test::More'      => 0,
        'Test::Exception' => 0,
    },
    c_source            => './src',
    xs_files            => { 'Range.xs' => './Range.xs' },
    add_to_cleanup      => [ 'Net-IP-Range-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();

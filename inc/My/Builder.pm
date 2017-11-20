package My::Builder;

use 5.004;
use strict;
use warnings;
use base 'Module::Build';

use PkgConfig;

sub new {
    my ($class, %args) = @_;

    my $pkg_name = 'krb5';

    my $pc = PkgConfig->find($pkg_name);
    if ($pc->errmsg) {
        die "Failed to get pkg-config info for krb5!\n";
    }

    my $vendor = $pc->get_var('vendor');
    printf "Found %s kerberos 5 version %s\n", $vendor, $pc->pkg_version;

    if ($vendor ne 'MIT') {
        die 'This module currently only supports MIT kerberos';
    }

    if ($pc->get_cflags) {
        $args{extra_compiler_flags} = $pc->get_cflags;
        print "CFLAGS: $args{extra_compiler_flags}\n";
    }

    $args{extra_linker_flags} = $pc->get_ldflags;
    print "LDFLAGS: $args{extra_linker_flags}\n";

    my $builder = Module::Build->new(%args);

    return $builder;
}

1;

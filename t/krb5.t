
use 5.008_008;
use Test2::V0;

# use Test::TempDir::Tiny;
use Path::Tiny;

use Authen::Krb5;

# my $temp_dir = tempdir;
# my $cc_file = $temp_dir->child($CACHE);

ok Authen::Krb5::init_context, 'initialised library conext';

# just check a few symbols to make sure importing has worked
imported_ok(qw/KRB5_TGS_NAME KDC_OPT_FORWARDED AP_OPTS_MUTUAL_REQUIRED/);

subtest keytabs => sub {

    ok my $kt = Authen::Krb5::kt_resolve('t/data/host-01.keytab'), 'got kt';

    is $kt->get_name, 'FILE:t/data/host-01.keytab', 'kt has expected name';

    ok my $kt_cursor = $kt->start_seq_get, 'got kt cursor';
    isa_ok $kt_cursor, 'krb5_kt_cursorPtr';

    ok my $kt_entry = $kt->next_entry($kt_cursor), 'got kt entry';
    isa_ok $kt_entry, 'Authen::Krb5::KeytabEntry';

    is $kt_entry->kvno, 2, 'got expected kvno';

    ok my $kt_entry_principal = $kt_entry->principal, 'got kt entry principal';
    is $kt_entry_principal->realm, 'EXAMPLE.COM', 'has expected realm';
    is $kt_entry_principal->type,  1,             'kt entry type is 1';
    is $kt_entry_principal->data,  'host-01',     'data is host';

};

subtest default_credential_cache => sub {

    ok my $cc = Authen::Krb5::cc_default, 'got default cc';

    # is $cc->get_name, '', 'cc has expected name';

    # ok my $cc_cursor = $cc->start_seq_get, 'got cc cursor';
    # isa_ok $cc_cursor, 'krb5_cc_cursorPtr';
    #
    # ok my $cc_cred = $cc->next_cred($cc_cursor), 'got cred from cc';
    # isa_ok $cc_cred, 'Authen::Krb5::Creds';

    # $self->{'starttime'}     = $cache_object->starttime();          # start time of credential
    # $self->{'authtime'}      = $cache_object->authtime();
    # $self->{'endtime'}       = $cache_object->endtime();
    # $self->{'principal'}     = $cache_object->client();             # prints principal name
    # $cc->end_seq_get( $cache_pointer );                             # destroy pointer
};

ok lives {Authen::Krb5::free_context}, 'freed context';

done_testing;

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Krb5',
    'VERSION_FROM' => 'Krb5.pm',
    'LIBS'	=> ['-L/usr/local/krb5/lib -lkrb5 -lcrypto -lcom_err'],
    'DEFINE'	=> '',
    'INC'	=> '-I/usr/local/krb5/include',
);

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::OpenSSL::Configuration',
    'VERSION_FROM' => 'Configuration.pm', # finds $VERSION
);

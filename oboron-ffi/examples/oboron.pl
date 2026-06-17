#!/usr/bin/env perl
# Reference Perl binding for the oboron C ABI via FFI::Platypus — a
# sketch to bind against, not yet a packaged module. It loads the
# prebuilt shared library at runtime (no XS compilation), so all the
# crypto is the same audited Rust core every other binding uses.
#
# Prereqs:
#   cargo build --release -p oboron-ffi     # builds liboboron_ffi.so
#   cpanm FFI::Platypus
# Run:
#   perl examples/oboron.pl

use strict;
use warnings;
use FFI::Platypus 2.00;

my $ffi = FFI::Platypus->new( api => 2 );
$ffi->lib('./target/release/liboboron_ffi.so');

# Attach the C functions. `string` in/out copies bytes to/from Perl;
# `opaque*` is the char** out-parameter; `opaque` is the raw char*
# we hand back to oboron_string_free.
$ffi->attach( oboron_last_error  => []                                  => 'string' );
$ffi->attach( oboron_string_free => ['opaque']                          => 'void'   );
$ffi->attach( oboron_generate_key=> ['opaque*']                         => 'int'    );
$ffi->attach( oboron_enc         => ['string','string','string','opaque*'] => 'int' );
$ffi->attach( oboron_autodec     => ['string','string','opaque*']       => 'int'    );

# Marshal the (status, out-pointer) convention into a Perl string:
# check the status, copy the C string into Perl, then free the
# Rust-allocated buffer — exactly the ownership dance the C ABI requires.
sub _take {
    my ( $code, $ptr ) = @_;
    die "oboron error ($code): " . ( oboron_last_error() // 'unknown' ) . "\n"
        if $code != 0;
    my $str = $ffi->cast( 'opaque' => 'string', $ptr );   # copies the bytes
    oboron_string_free($ptr);                              # release Rust memory
    return $str;
}

# Perl arguments evaluate left to right, so the call (which sets $o as a
# side effect) runs before $o is read as the second argument to _take.
sub generate_key { my $o; _take( oboron_generate_key( \$o ), $o ) }
sub enc { my ( $pt, $fmt, $key ) = @_; my $o; _take( oboron_enc( $pt, $fmt, $key, \$o ), $o ) }
sub autodec { my ( $ct, $key ) = @_; my $o; _take( oboron_autodec( $ct, $key, \$o ), $o ) }

my $key    = generate_key();
my $obtext = enc( 'hello obsigil', 'apsv.b64', $key );
my $plain  = autodec( $obtext, $key );

print "key     : $key\n";
print "obtext  : $obtext\n";
print "decoded : $plain\n";
die "round-trip mismatch\n" unless $plain eq 'hello obsigil';
print "ok\n";

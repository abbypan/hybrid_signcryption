#!/usr/bin/perl

use File::Slurp qw/write_file/;

my ( $log_file ) = @ARGV;

my @files = qw/plain.10KB.txt plain.100KB.txt plain.1MB.txt plain.10MB.txt plain.50MB.txt/;

my @nums  = qw/10 50 100 200 500/;
#my @nums = qw/1 2 10/;

my $repeat = 1000;
#my $repeat = 2;

my $head = qq[type,n,msg_len,pmsg_enc_len,pmsg_enc_time,pmsg_dec_len,pmsg_dec_time,n_enc_len,n_enc_time,n_dec_len,n_dec_time\n];
write_file( $log_file, $head );

for my $i ( 1 .. $repeat ) {
  for my $n ( @nums ) {
    for my $f ( @files ) {
      print "\r$i: $n: $f";
      system( qq[./hybrid_sc_multi $f $log_file $n] );
    }
  }
}

#!/usr/bin/perl

use File::Slurp qw/write_file/;

my @files = qw/plain.10KB.txt plain.100KB.txt plain.1MB.txt plain.10MB.txt plain.100MB.txt plain.500MB.txt/;
my $n = 1000;
my $log_file = 'main.csv';
unlink($log_file);

my$head=qq[type,msg_len,enc_elapsed_time_sd,dec_elapsed_time_sd,all_len,iv_len,ciphertext_len,tag_len,sig_len,c2_len,e_len\n];
write_file($log_file, $head);

            for my $i ( 1 .. $n ){
for my $f (@files){
            print "\r$i: $f";
            system(qq[./hybrid_sc $f $log_file]);
    }
}

#!/usr/bin/perl

my @files = qw/plain.10KB.txt plain.10MB.txt plain.100MB.txt plain.300MB.txt/;
my $n = 1000;

system(qq[rm -rf data/ff/*]);

my @ff_types = qw/SDSS1 SDSS2/;
my @ff_groups = qw/ffdhe3072 ffdhe4096/;
for my $f (@files){
    for my $t (@ff_types){
        for my $g (@ff_groups){
            for my $i ( 1 .. $n ){
            print "$i: $f, $t, $g\n";
            my $d = "data/ff/$f.$g.$t.$i";
            mkdir($d);
            system(qq[perl signcryption_ff.pl $f $t $g |tee $d/$f.$t.$g.log]);
            system(qq[mv nytprof* $d/]);
            system(qq[rm $f.*]);
            }
        }
    }
}

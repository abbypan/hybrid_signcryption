#!/usr/bin/perl


my @files = qw/plain.10KB-exp.csv plain.100KB-exp.csv plain.1MB-exp.csv plain.10MB-exp.csv plain.50MB-exp.csv/;

for my $f ( @files ) {
    system( qq[Rscript avg.single.R $f $f.stat.csv]);
}

my $mf = 'multi.csv';
system( qq[Rscript avg.multi.payload.R $mf $mf.payload.csv]);
system( qq[Rscript avg.multi.sym.R $mf $mf.sym.csv]);
system( qq[Rscript avg.multi.k.R $mf $mf.k.csv]);

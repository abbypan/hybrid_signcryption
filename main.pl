#!/usr/bin/perl


my ($f) = @ARGV;

my $n = 1010;

for my $i (1 .. $n){
	print "\r$i";
	system(qq[./sigma $f >> $f.sigma.csv]);
	system(qq[./hybrid_signcryption $f >> $f.hybrid_signcryption.csv]);

	if($f=~/100KB/){
		my $mf = "resources/plain.10KB.txt";
		system(qq[./dtls_udp_echo -n 10 -f $mf 127.0.0.1 >> $f.dtls.csv]);
	}else{
		system(qq[./dtls_udp_echo -n 1 -f $f 127.0.0.1 >> $f.dtls.csv]);
	}
}

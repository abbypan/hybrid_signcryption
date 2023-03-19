#!/usr/bin/perl
use File::Slurp qw/slurp/;
use Data::Dumper;
use utf8;

main_ff_time();

sub main_ff_time {
my @head = qw/file group type i calls P F exclusive_time inclusive_time(ms) subroutine/;
open my $all_fh, '>', 'data/signcryption_time_ff_all.csv';
print $all_fh join(",", @head),"\n";

open my $signcryption_fh, '>', 'data/signcryption_time_ff.csv';
print $signcryption_fh join(",", @head),"\n";

my @dirs = glob("data/ff/*");
for my $d (@dirs){
    print "$d\n";
    system(qq[cd $d; nytprofhtml; cd ..]);
    my ($all_r, $signcryption_r) = read_ff_time("$d/nytprof/index-subs-excl.html");

    for my $all_i (@$all_r){
        print $all_fh join(",", @$all_i),"\n";
    }

    for  (@$signcryption_r){
        print $signcryption_fh join(",", @$_),"\n";
    }
    system(qq[rm -rf "$d/nytprof"]);
}

close $all_fh;
close $signcryption_fh;
}

sub read_ff_time {
my ($f) = @_;

print $f, "\n";
my ($src_f, $group, $type, $i) = $f=~m#^data/ff/(.+?\.txt)\.(.+?)\.(.+?)\.(.+?)\/nytprof.+?$#;
print "($src_f, $group, $type, $i)\n";

my @all;
my @signcryption;
my $c = slurp($f, { binmode => ':raw' } );
$c=~s/^.*<div class="body_content">(.+?)<\/div>.*/$1/s;
my @tr = $c=~/<tr>(.+?)<\/tr>/sg;
for my $t (@tr){
    my @td = $t=~/<td.+?>(.+?)<\/td>/sg;
    $_=~s/<span.+?>(.+?)<\/span>.*/$1/s for @td;
    unshift @td, ($src_f, $group, $type, $i);
    push @all, \@td;
    if($td[9]=~/main::::(un)?signcryption/s){
        if($td[8]=~/(.+?)µs/){
            $td[8]=$1/1000;    
        }elsif($td[8]=~/(.+?)ms/){
            $td[8]=$1;    
        }else{
            next;
        }    

        push @signcryption, \@td;
    };
}

return (\@all, \@signcryption);
}



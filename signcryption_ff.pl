#!/usr/bin/perl
use bigint;
use bignum;
use Capture::Tiny ':all';
use Crypt::KeyDerivation ':all';
use Crypt::OpenSSL::Bignum::CTX;
use Crypt::OpenSSL::Bignum;
use Data::Dumper;
use Devel::NYTProf;
use Digest::SHA qw/sha512_hex sha256_hex/;
use Fcntl       qw(SEEK_END);
use Math::BigInt;
use Math::Prime::Util ':all';
use ntheory ':all';
use File::Slurp qw/slurp/;

our $ctx    = Crypt::OpenSSL::Bignum::CTX->new();
our $bn_one = Crypt::OpenSSL::Bignum->new_from_decimal( "1" );
our $bn_16bytes = Crypt::OpenSSL::Bignum->new_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

our %Group = (
    'ffdhe2048' => {
        p => 'FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF',
        g => '2', 
        q => '7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49ACC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD4435A11C30942E4BFFFFFFFFFFFFFFFF', 
    }, 
    'ffdhe3072' => {
p => 'FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B66C62E37FFFFFFFFFFFFFFFF',
        g => '2', 
        q => '7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49ACC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF79E0D90771FEACEBE12F20E95B363171BFFFFFFFFFFFFFFFF',
    }, 
    'ffdhe4096' => {
p => 'FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B4238611FCFDCDE355B3B6519035BBC34F4DEF99C023861B46FC9D6E6C9077AD91D2691F7F7EE598CB0FAC186D91CAEFE130985139270B4130C93BC437944F4FD4452E2D74DD364F2E21E71F54BFF5CAE82AB9C9DF69EE86D2BC522363A0DABC521979B0DEADA1DBF9A42D5C4484E0ABCD06BFA53DDEF3C1B20EE3FD59D7C25E41D2B669E1EF16E6F52C3164DF4FB7930E9E4E58857B6AC7D5F42D69F6D187763CF1D5503400487F55BA57E31CC7A7135C886EFB4318AED6A1E012D9E6832A907600A918130C46DC778F971AD0038092999A333CB8B7A1A1DB93D7140003C2A4ECEA9F98D0ACC0A8291CDCEC97DCF8EC9B55A7F88A46B4DB5A851F44182E1C68A007E5E655F6AFFFFFFFFFFFFFFFF',
        g => '2', 
        q => '7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49ACC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD4435A11C308FE7EE6F1AAD9DB28C81ADDE1A7A6F7CCE011C30DA37E4EB736483BD6C8E9348FBFBF72CC6587D60C36C8E577F0984C289C9385A098649DE21BCA27A7EA229716BA6E9B279710F38FAA5FFAE574155CE4EFB4F743695E2911B1D06D5E290CBCD86F56D0EDFCD216AE22427055E6835FD29EEF79E0D90771FEACEBE12F20E95B34F0F78B737A9618B26FA7DBC9874F272C42BDB563EAFA16B4FB68C3BB1E78EAA81A00243FAADD2BF18E63D389AE44377DA18C576B50F0096CF34195483B00548C0986236E3BC7CB8D6801C0494CCD199E5C5BD0D0EDC9EB8A0001E15276754FCC68566054148E6E764BEE7C764DAAD3FC45235A6DAD428FA20C170E345003F2F32AFB57FFFFFFFFFFFFFFF',
    }, 
);

our ( $m_fname, $type, $group_name ) = @ARGV;
$m_fname //= 'plain.10KB.txt';
$type    //= 'SDSS1';
$group_name //= 'ffdhe2048';

print "test: $m_fname, $type, $group_name\n";

my ( $p, $g, $q ) = dh_p_g_q( @{$Group{$group_name}}{qw/p g q/} );
print "p=", $p->to_hex(), "\ng=", $g->to_hex(), "\nq=", $q->to_hex(), "\n\n";

my ( $bn_ax, $bn_ay ) = gen_keypair( $p, $g, $q );
print "keypair ax=", $bn_ax->to_hex(), "\n ay=g^ax=", $bn_ay->to_hex(), "\n\n";

my ( $bn_bx, $bn_by ) = gen_keypair( $p, $g, $q );
print "keypair bx=", $bn_bx->to_hex(), "\n by=g^bx=", $bn_by->to_hex(), "\n\n";

print "signcryption:\n";
my ( $c_fname, $iv, $r, $s ) = signcryption( $type, $p, $g, $q, $bn_ax, $bn_by, $m_fname );
print "iv=$iv\nr=$r\ns=$s\n\n";

print "unsigncryption:\n";
my $verify_result = unsigncryption( $type, $p, $g, $q, $bn_bx, $bn_ay, $c_fname, $iv, $r, $s );
print "verify_result: $verify_result\n\n";

print "signcryption aead:\n";
my ( $c_fname2, $iv2, $tag, $s2 ) = signcryption_aead( $type, $p, $g, $q, $bn_ax, $bn_ay, $bn_by, $m_fname );
print "iv=$iv2\ntag=$tag\ns=$s2\n\n";

print "unsigncryption aead:\n";
my $verify_result2 = unsigncryption_aead( $type, $p, $g, $q, $bn_bx, $bn_by, $bn_ay, $c_fname2, $iv2, $tag, $s2 );
print "verify_result: $verify_result2\n\n";

sub unsigncryption_aead {
  my ( $type, $p, $g, $q, $bn_bx, $bn_by, $bn_ay, $c_fname, $iv, $tag_fname, $s ) = @_;

  my $tag = unpack("H*", slurp($tag_fname));
  my $bn_r = Crypt::OpenSSL::Bignum->new_from_hex( $tag );
  my $bn_s = Crypt::OpenSSL::Bignum->new_from_hex( $s );

  my $tt;
  if ( $type eq 'SDSS1' ) {
    $tt = $g->mod_exp( $bn_r, $p, $ctx )->mod_mul( $bn_ay, $p, $ctx )->mod_exp(
      $bn_s->mod_mul( $bn_bx, $q, $ctx ),
      $p, $ctx
    );
  } elsif ( $type eq 'SDSS2' ) {
    $tt = $bn_ay->mod_exp( $bn_r, $p, $ctx )->mod_mul( $g, $p, $ctx )->mod_exp(
      $bn_s->mod_mul( $bn_bx, $q, $ctx ),
      $p, $ctx
    );
  } else {
    return;
  }

  my $tt_sha256 = sha256_hex( $tt->to_bin() );
  print "tt_sha256: $tt_sha256\n";
  my $bind_info = $bn_ay->to_bin() . $bn_by->to_bin();

  my $salt  = undef;
  my $k_bin = hkdf( pack( "H*", $tt_sha256 ), $salt, 'SHA256', 32, $bind_info );
  my $k     = unpack( "H*", $k_bin );
  print "k=$k, iv=$iv\n";
  my $dec_fname = "$c_fname.dec";

  my $cmd = qq[./aes256gcm $k $iv '' $c_fname $dec_fname $tag_fname 0];
  print "decrypt: $cmd\n";
  my ( $res, $stderr, $exit ) = capture {
      system($cmd);
  };
  return 0 if ( $stderr =~ /error/si );

  return 1;
} ## end sub unsigncryption_aead

#sub read_file_tail_16 {
#my ($filename) = @_;

#my $data;
#open (FILE, "<$filename") or die $!;
#binmode FILE;
#seek FILE, -16, SEEK_END;
#read FILE, $data, 16;
#close (FILE);
#return $data;
#}

sub signcryption_aead {
  my ( $type, $p, $g, $q, $bn_ax, $bn_ay, $bn_by, $m_fname ) = @_;

  my $bn_ex        = Crypt::OpenSSL::Bignum->rand_range( $q );
  my $bn_yb_ex     = $bn_by->mod_exp( $bn_ex, $p, $ctx );
  my $bn_yb_sha256 = sha256_hex( $bn_yb_ex->to_bin() );
  print "tt_sha256: $bn_yb_sha256\n";
  my $bind_info = $bn_ay->to_bin() . $bn_by->to_bin();

  my $salt  = undef;
  my $k_bin = hkdf( pack( "H*", $bn_yb_sha256 ), $salt, 'SHA256', 32, $bind_info );
  my $k     = unpack( "H*", $k_bin );

  chomp(my $iv = `openssl rand -hex 12`);
  #my $bn_iv    = Crypt::OpenSSL::Bignum->rand_range( $bn_16bytes );
  #my $iv = $bn_iv->to_hex();
  print "k=$k, iv=$iv\n";

    	my $c_fname = "$m_fname.$group_name.$type.gcm.enc";
    	my $tag_fname = "$m_fname.$group_name.$type.gcm.tag";
    	my $cmd 	= qq[./aes256gcm $k $iv '' $m_fname $c_fname $tag_fname 1];
    	print "encrypt: $cmd\n";
    	my ( $res, $stderr, $exit ) = capture {
        	system($cmd );
    	};
        return 0 if ( $stderr =~ /error/si );

#gcm authtag is used as r
  my $tag = unpack("H*", slurp($tag_fname));
  my $bn_r = Crypt::OpenSSL::Bignum->new_from_hex( $tag );

#s = x/(r + xa) mod q  if SDSS1 is used, or s=x/(1 + xa*r) mod q if SDSS2 is used.
  my $bn_s;
  if ( $type eq 'SDSS1' ) {
    $bn_s = $bn_r->add( $bn_ax )->mod_inverse( $q, $ctx )->mod_mul( $bn_ex, $q, $ctx );
  } elsif ( $type eq 'SDSS2' ) {
    $bn_s = $bn_r->mod_mul( $bn_ax, $q, $ctx )->add( $bn_one )->mod_inverse( $q, $ctx )->mod_mul( $bn_ex, $q, $ctx );
  } else {
    return;
  }

  my $s = $bn_s->to_hex();

  return ( $c_fname, $iv, $tag_fname, $s );

} ## end sub signcryption_aead

sub unsigncryption {
  my ( $type, $p, $g, $q, $bn_bx, $bn_ay, $c_fname, $iv, $r, $s ) = @_;
  my $bn_r = Crypt::OpenSSL::Bignum->new_from_hex( $r );
  my $bn_s = Crypt::OpenSSL::Bignum->new_from_hex( $s );

  my $t;
  if ( $type eq 'SDSS1' ) {
    $t = $g->mod_exp( $bn_r, $p, $ctx )->mod_mul( $bn_ay, $p, $ctx )->mod_exp(
      $bn_s->mod_mul( $bn_bx, $q, $ctx ),
      $p, $ctx
    );
  } elsif ( $type eq 'SDSS2' ) {
    $t = $bn_ay->mod_exp( $bn_r, $p, $ctx )->mod_mul( $g, $p, $ctx )->mod_exp(
      $bn_s->mod_mul( $bn_bx, $q, $ctx ),
      $p, $ctx
    );
  } else {
    return;
  }

  my $t_hex = sha512_hex( $t->to_bin() );
  my ( $k1, $k2 ) = $t_hex =~ /^(.{64})(.{64})$/;
  print "k1=$k1\nk2=$k2\n";

  my $dec_fname = "$c_fname.dec";

#`openssl enc -d -aes-256-ctr -in $c_fname -out $c_fname.dec -K $k1 -iv $iv`;

	my $cmd=qq[./aes256ctr $k1 $iv $c_fname $dec_fname 0];
    print "decrypt: $cmd\n";
	my ( $res, $stderr, $exit ) = capture {
    	system($cmd);
	};
	return 0 if ( $stderr =~ /error/si );

  my ( $r2, $stderr2, $exit2 ) = capture {
    system( qq[openssl mac -macopt digest:SHA256 -macopt hexkey:$k2 -in $dec_fname HMAC] );
  };

  $r2 =~ s/\s+//sg;
  return 1 if ( $r eq $r2 );

  return;
} ## end sub unsigncryption

sub signcryption {
  my ( $type, $p, $g, $q, $bn_ax, $bn_by, $m_fname ) = @_;

  my $bn_ex    = Crypt::OpenSSL::Bignum->rand_range( $q );
  my $bn_yb_ex = $bn_by->mod_exp( $bn_ex, $p, $ctx );

  my $bn_yb_sha512 = sha512_hex( $bn_yb_ex->to_bin() );

  my ( $k1, $k2 ) = $bn_yb_sha512 =~ /^(.{64})(.{64})$/;
  print "k1=$k1\nk2=$k2\n";

        chomp(my $iv = `openssl rand -hex 16`);

  my $c_fname = "$m_fname.$group_name.$type.ctr.enc";

    	my $cmd 	= qq[./aes256ctr $k1 $iv $m_fname $c_fname 1];
    	print "encrypt: $cmd\n";
    	my ( $res, $stderr, $exit ) = capture {
        	system($cmd );
    	};
        return 0 if ( $stderr =~ /error/si );

#`openssl enc -aes-256-ctr -in $m_fname -out $c_fname -K $k1 -iv $iv`;

  my ( $r, $stderr2, $exit2 ) = capture {
    system( qq[openssl mac -macopt digest:SHA256 -macopt hexkey:$k2 -in $m_fname HMAC] );
  };
  $r =~ s/\s+//sg;
  my $bn_r = Crypt::OpenSSL::Bignum->new_from_hex( $r );

#s = x/(r + xa) mod q  if SDSS1 is used, or s=x/(1 + xa*r) mod q if SDSS2 is used.
  my $bn_s;
  if ( $type eq 'SDSS1' ) {
    $bn_s = $bn_r->add( $bn_ax )->mod_inverse( $q, $ctx )->mod_mul( $bn_ex, $q, $ctx );
  } elsif ( $type eq 'SDSS2' ) {
    $bn_s = $bn_r->mod_mul( $bn_ax, $q, $ctx )->add( $bn_one )->mod_inverse( $q, $ctx )->mod_mul( $bn_ex, $q, $ctx );
  } else {
    return;
  }

  my $s = $bn_s->to_hex();

  return ( $c_fname, $iv, $r, $s );

} ## end sub signcryption

sub gen_keypair {
  my ( $p, $g, $q ) = @_;
  my $bn_x = Crypt::OpenSSL::Bignum->rand_range( $q );
  my $bn_y = $g->mod_exp( $bn_x, $p, $ctx );
  return ( $bn_x, $bn_y );
}

sub dh_p_g_q {
  my ( $p, $g, $q ) = @_;
  my $bn_p = Crypt::OpenSSL::Bignum->new_from_hex( $p );
  my $bn_g = Crypt::OpenSSL::Bignum->new_from_hex( $g );
  my $bn_q = Crypt::OpenSSL::Bignum->new_from_hex( $q );
  return ( $bn_p, $bn_g, $bn_q );
}


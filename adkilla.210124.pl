#!/usr/bin/env perl
use strict;
use warnings;
use utf8;
use open ':encoding(utf8)';
binmode(STDOUT, ":utf8");
use feature 'unicode_strings';
use Getopt::Long;

# History
# 
# 200606	Version 0.0.1

my $progn = 'adkilla';
my $version = '0.0.1';
my $stripfext = '.stripped';
# files for combined lists
my $blackmergefilename = 'blackmergefile.txt';
my $whitemergefilename = 'whitemergefile.txt';
my $finalmergefilename = 'finalmergefile.txt';
my $unboundfilename = 'unbound_include.txt';

# my $mylogfn = '/home/www/serv_root/log/adloglistprep.log';
# my $mylogfn = './adloglistprep.log';
my $mylogfn = '';

# used to store domains when merge
my %blacktreehash = ();
my %whitetreehash = ();
# domain tree node terminator
my $lastpartstr = '|||';

my $opt_show_help = '';
my $opt_show_version = '';
my $opt_cwd = '.';
my $opt_blacklistsfile = $progn . "_blacklist.conf";
my $opt_whitelistsfile = $progn . "_whitelist.conf";
my $blacklistprefix = 'black';
my $whitelistprefix = 'white';
my $opt_redirectip = '127.0.0.1';
my $opt_targetpath = "/var/unbound/$unboundfilename";
my $opt_configpath = '/usr/local/etc';
my $opt_download = '';
my $opt_strip = '';
my $opt_merge = '';
my $opt_downloadstripmerge = '';
my $opt_unbound = '';
my $opt_pfprep = '';
my $opt_verbosity = 0;
my $opt_blocksubdir = 0;

my $bf;
my $wf;

sub opt_show_help {
    print "Usage: $progn [OPTIONS]\n";
    print "Options:\n";
    print "    --help|h|?      show this help and exit\n";
    print "    --version       show program version and exit\n";
    print "    --{download|D}  download hostsfiles\n";
    print "    --{strip|S}     create stripped files with only hostnames\n";
    print "    --{merge|M}     merge the downloaded and processed lists\n";
    print "    --{downloadstripmerge}	download, strip and merge hostsfiles\n";
    print "    --{unbound|U}   prepare unbound include file from mergefile\n";
#     print "    [planned: --{bind|B}   prepare BIND zone file]\n";
    print "    -d=<path>       set base path where to work (default: current working directory).\n";
    print "                    Recommended setting: /var/adkilla\n";
    print "    -c=<path>       config directory path, where the blacklist and whitelist files are (default: /usr/local/etc)\n";
    print "    -v              increase output verbosity\n";
    print "    The following options are meaningful only in conjunction with unbound option:\n";
    print "    -s              if set, unbound also blocks subdomains of blacklisted domains\n";
    print "    -r=<IP>         the IP to redirect to (default 127.0.0.1, in conjunction with unbound option\n";
    print "    -t=<dir>        target directory for copying the resulting unbound_include.txt into\n";
    print "                     (usually /var/unbound)\n";
    exit 0;
}

sub opt_show_version {
    print "$progn $version\n";
    exit 0;
}

sub opt_wrong_usage {
    print STDERR "Error. Try '$progn --help' for more information.\n";
    exit -1;
}

GetOptions(
    "help|h|?"		=> \&opt_show_help,
    "version"		=> \&opt_show_version,
    "d=s"		=> \$opt_cwd,
    "r=s"		=> \$opt_redirectip,
    "c=s"		=> \$opt_configpath,
    "t=s"		=> \$opt_targetpath,
    "download"		=> \$opt_download,
    "strip"		=> \$opt_strip,
    "merge"		=> \$opt_merge,
    "downloadstripmerge"		=> \$opt_downloadstripmerge,
    "unbound"	=> \$opt_unbound,
    "s+"		=> \$opt_blocksubdir,
    "v+"		=> \$opt_verbosity,
) || wrong_usage();
wrong_usage() if @ARGV;

sub plog
{
	my $lvl = shift;
	my $txt = shift;
	my $logf;

	if ($lvl > $opt_verbosity) {
        if ($mylogfn ne '') {
            open($logf, ">>:utf8", $mylogfn)
                || die "$0: can't open $mylogfn for appending: $!";
            print $logf "($lvl) $txt";
            close $logf;
        }
        print "($lvl) $txt\n";
	}
}

sub striphostfbuf {
	my $fbuf = shift;
	# in case there is some formatting, remove it
	$$fbuf =~ s/^\s+$|<script>.+?<\/script>|<style>.+?<\/style>|<head>.+?<\/head>|<div>.+?<\/div>|<title>.+?<\/<title>|<table.+?<\/table>|<!--.+?-->|\[.+?\]//gsi;
	while ($$fbuf =~ s/<\S[^<>]*(?:>|$)//gs) {};
	# remove comment-only lines
	$$fbuf =~ s/^\s?+\#.*$//gm;
	# remove comment part of lines
	$$fbuf =~ s/\s?+\#.*$//gm;
	# remove IP addresses if present
	$$fbuf =~ s/^\s?+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+//gm;
	# remove IP6 lines
	# (some blocklist has everything twice, each for IP4 and IP6
	# others define some localhost, broadcast etc IP6 stuff
#  	$$fbuf =~ s/^[!:]*?\:\:+?[!:]*?$//gm;
  	$$fbuf =~ s/^.*?\:\:.*?$//gm;
#  	$$fbuf =~ s/^\:\:.*$//gm;
	# remove bad "domains" formed as malformed IP addresses
	# (Prigent)
	# TODO extract valid IPs and move them to IP blocklist
	$$fbuf =~ s/^\s?+\d+\.\d+\.\d+\.\d+.*$//gm;
# 	# remove bad "domains" formed as dotless strings (HorusTeknoloji lists)
# 	$$fbuf =~ s/^[^.]+$//gm;
# 	# correct bad "domain" without extension, (HorusTeknoloji phish list)
# 	$$fbuf =~ s/^suprizhediyeleratolyesi\.$//g;
	# remove trailing blank of lines
	$$fbuf =~ s/\s+$//gm;
	# remove all lines that refer to localhost etc
	$$fbuf =~ s/^.*?localhost$//gm;
	$$fbuf =~ s/^.*?localhost.localdomain$//gm;
	$$fbuf =~ s/^.*?local$//gm;
	$$fbuf =~ s/^.*?broadcasthost$//gm;
	# first line of Disconnect list is not tagged as comment
	$$fbuf =~ s/^Malvertising list by Disconnect$//gm;
	# error in OISD list (fixed)
# 	$$fbuf =~ s/justice\.ad\.gov\.ng\.//gm;
	# in the energized list there are plenty of domains that are 
	# easily recognizable as invalid due to their length.
	# as the energized list has way too many false positives, ditch it
	
	# remove entries that end with dot
	$$fbuf =~ s/^.*\.\s*$//g;
	
	# remove empty lines
	$$fbuf =~ s/(^|\n)[\n\s]*/$1/g;
	# some lists even have domain names written with separate spaces 
	# inmidst them, for example: 
	# raw.githubusercontent.com_RooneyMcNibNug_pihole-stuff_master_SNAFU.txt
	# so remove all remaining whitespace
	$$fbuf =~ s/[ \t]//gm;
}

sub readhostsfile
{
	my $fn = shift;
 	my $fh;
 	my $fbuf;
 	my $fmaxsiz = 100000000;
	open( $fh, '<:utf8', $fn)
		or die "readhostsfile: couldn't open $fn";
	my $fsize = read( $fh, $fbuf, $fmaxsiz);
	# die if read error or template too large
	return undef if (not defined $fsize or $fsize == $fmaxsiz);
	return striphostfbuf( \$fbuf);
}

sub downloadurl
{
	my $url = shift;
	my $ofn = shift;
	# get the file
# 	plog (2, "downloadurl: get url <$url> to save into file <$ofn>");
	my $sys = "wget --quiet --output-document='$ofn' '$url'";
	plog (2, "downloadurl: system <$sys>");
	my $res = system( $sys);
	return $res;
}

sub readhostsurl
{
	my $fn = shift;
	# get the file
	plog (2, "readhostsurl: get url: <$fn>");
	my $fbuf = qx{wget --quiet --output-document=- $fn};
	return undef if $?;
	return \$fbuf;
}

sub readutffile {
	my $fname = shift;
	my $fbuf = shift;
	my $fh;
	my $fmaxsiz = 100000000;

	open( $fh, '<:encoding(UTF-8)', $fname) or die( "readutffile: failed to open '$fname'");   
	# TODO we cannot assume no file will be smaller than 100 MB. This is no good way
	# better check filesize before
	my $fchars = read( $fh, $$fbuf, $fmaxsiz );
	if (not defined $fchars) {
		die( "readutffile: could not read from '$fname'");
	}
	close $fh;
	return $fchars;
}

sub readutfdir {
	my $dname = shift;
	opendir DIR, $dname or die; # "cannot open dir $dname: $!";
	my @dir = readdir DIR;
	closedir DIR;
	# remove . and ..
	my @odir = ();
	foreach (sort @dir) {
		push ( @odir, $_) if ($_ ne '.' and $_ ne '..');
	}
	return @odir;
}

# TODO error checking etc!!! XXX
sub writeutffile {
	my $fn = shift;
	my $tref = shift;
	open( my $fh, ">:encoding(UTF-8)", $fn)
		or die "cannot open > $fn: $!";
	print $fh $$tref;
	close $fh;
}

sub anyindex {
  my $aref = shift;
  my $str = shift;
  my $indexref = shift;
  my $isin = 0;
  $$indexref = 0;
  foreach (@$aref) {
    if ($_ eq $str) {
	    $isin = 1;
	    last;
    }
    $$indexref += 1;
  }
  return $isin;
}

sub getdirdatetag
{
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
	my $now = sprintf("%04d-%02d-%02d-%02d:%02d:%02d", $year+1900, $mon+1, $mday, $hour, $min, $sec);
	return $now;
}

sub do_read_listfile
{
	my $hosturlfilename = shift;
	my $hosturls = shift;
	my $hosts1urls0 = shift;
	my $fbuf = ();
	my $fchars = readutffile( $hosturlfilename, \$fbuf);
	if (not defined $fchars) {
		plog( 0, "Failed to read urlfile $hosturlfilename");
		die;
	}
	# first strip the file from comments and empty lines
		# remove comment-only lines
	$fbuf =~ s/^\s?+\#.*$//gm;
	# remove comment part of lines
	$fbuf =~ s/\s?+\#.*$//gm;
	
	# remove any lines that do not start with 'http[s]://'
	# to get only the URLs to be downloaded, or the hosts
	if ($hosts1urls0) {
		$fbuf =~ s/^(\s?+http[s]?\:\/\/.*)$//gm;
	
	} else {
		$fbuf =~ s/^(?:(?!(\s?+http[s]?\:\/\/.*)).)*$//gm;
# # see https://stackoverflow.com/questions/23403494/perl-matching-string-not-containing-pattern
# 		$fbuf =~ s/^
# 		(?:
# 			(?!
# 				(\s?+http[s]?\:\/\/.*)
# 			).
# 		)*
# 		$//gmx;
	}
	# remove trailing blank of lines
	$fbuf =~ s/\s?+$//gm;
	# remove empty lines
	$fbuf =~ s/(^|\n)[\n\s]*/$1/g;
	# now read in the lines and add each host to our list
	@{$hosturls} = split( "\n", $fbuf);
}

sub do_download_list
{
	my $hosturlfilename = shift;
	my $hosturls = shift;
	my $fnprefix = shift;
	my %listfile = ();
	my $snapdir = shift;
	
	plog( 1,"Reading URL file '$hosturlfilename'");
	do_read_listfile( $hosturlfilename, $hosturls, 0);
	plog( 1,'Getting Lists from web');
	foreach (sort @{$hosturls}) {
# 		my $f = readhostsurl($_);
		# mod URL to a suitable filename
		my $ofn = $_;
		$ofn =~ s/^\S+:\/\///;
		$ofn =~ s/[&;:\/\?
]/_/g;
		my $fpath = $snapdir . '/' . $fnprefix . $ofn;
		my $f = downloadurl($_, $fpath);
		
		if ($f) {
			plog( 2, "URL '$_' read fail, skipping");
# 		} else {
# 			plog( 3, "URL '$_' read success, stored: '$fpath'");
		}
		# now check: is the file a .tar.gz (->Prigent)
		# this is super annoying: 
		# you have to unpack a directory structure,
		# which is not even consistent
		#  'malware' list extracts to directory 'phishing'
		#  'ads' list extracts to directory 'publicite'
		#      furthermore 'ads' list is redundant copy of 'publicite'
		# and then move the interesting contents to a blockfile
		if ($fpath =~ /.*?\.tar\.gz$/) {
			my $ret = system( "gunzip -d '$fpath'");
			if ($ret) {
				plog( 2, "Unzip failure: \"gunzip -d '$fpath'\" returned $ret");
			} else {
				plog( 3, "Unzip $fpath successful");
				chop $fpath;
				chop $fpath;
				chop $fpath;
				$ret = system( "tar -x -f '$fpath'");
				if ($ret) {
					plog( 2, "Untar failure: \"tar -x  '$fpath'\" returned $ret");
				} else {
					plog( 3, "Untar $fpath successful");
					# finally clean up the mess
					# extract the directory name
					my $dname = $fpath;
					$dname =~ s/(.*?blackdsi\.ut-capitole\.fr_blacklists_download_)(\S+)(\.tar)/$2/;
					my $drealname = $dname;
# 					if ($dname eq 'ads') {
# 						$drealname = 'publicite';
# 					}
					if ($dname eq 'malware') {
						$drealname = 'phishing';
					}
					# remove and move
					my $rm = "rm $fpath";
					chop $fpath;
					chop $fpath;
					chop $fpath;
					chop $fpath;
					my $mv = "mv $drealname/domains $fpath";
					my $rmdc = "rm $drealname/*";
					my $rmd = "rmdir $drealname";
					system( $mv);
					system( $rm);
					system( $rmdc);
					system( $rmd);
				}
			}
		}
	}
	plog( 1,'Finished getting lists');
	return 0;
}

sub do_download
{
	my @blackhostsurls;
	my @whitehostsurls;
	my $snapdir = '';

    $snapdir = $opt_cwd . '/' .getdirdatetag();
    
    if ( !mkdir( $snapdir)) {
        plog (0, "mkdir '$snapdir' failed!");
        return $!;
    }
	# get lists URLs
	do_download_list( $bf, \@blackhostsurls, $blacklistprefix, $snapdir);
	do_download_list( $wf, \@whitehostsurls, $whitelistprefix, $snapdir);
}

sub do_strip
{
	my $snapdir = getsnapdir();
# 	
# 
	plog (2, "Using work directory '$snapdir'");
# 	
#     # get latest snapshot directory
#     my @sdirs = readutfdir( $snapdir);
#     my $latest = '';
#     foreach (@sdirs) {
#         if (-d and $_ gt $latest) {
#             $latest = $_;
#         }
#     }
#     $snapdir .= "/$latest";
# #     chop $snapdir;    # remove / at end
	plog (2, "Using work directory '$snapdir'");

	# now read the files, strip them from comments 
	# and merge their hostname lists
	my @hfiles = readutfdir( $snapdir);
	foreach (@hfiles) {
		# do not read stripped files!
		next if (-d or /$stripfext$/);
		# do not touch mergefiles etc
		next if ($_ eq $unboundfilename or
            $_ eq $blackmergefilename or
			$_ eq $whitemergefilename or
			$_ eq $finalmergefilename);
		my $fbuf = ();
		my $fchars = readutffile( "$snapdir/$_", \$fbuf);
		if (not defined $fchars) {
			plog( 0, "Failed to read hostsfile $snapdir/$_");
			die;
		}
		# strip all except host names from the hostfiles
		striphostfbuf( \$fbuf);
		writeutffile( "$snapdir/$_$stripfext", \$fbuf);
		plog (2, "File '$_' strip success");
	}
	plog( 1,'Finished stripping lists');
}

# printlist( $outtextref, $domainshashref, $rootstr)
sub printlist
{
	my $oref = shift;
	my $dhref = shift;
	my $rootstr = shift;
	
	if (scalar %{$dhref}) {
		# generate output sorted from tld downwards
		if (exists $dhref->{$lastpartstr}) {
			my $rs = $rootstr;
			chop( $rs);
			$$oref .= "$rs\n";
		}
		foreach (sort keys %{$dhref}) {
			next if ($_ eq $lastpartstr);
			printlist( $oref, $dhref->{$_}, "$_.$rootstr");
		}
	}
}

sub addDomain
{
	my $ds = shift;
	my $dthr = shift;
	
	# work down the domain string, beginning with tld, 
	# then putting subdomains into hash keys (subhashes)
	my $top = '';
	my $lastpart = 0;
	do {
		(my $remainder, $top) = $ds =~ 
			/
		    ^                     # Anchor to start of string.
		    (
		    (?:                   # One or more sub-domains.
		        [a-z0-9-_]{0,63}   # Middle part may have dashes.
		      \.                  # Required dot separates subdomains.
		    )+                    # End one or more sub-domains.
		    )
		    (                  # Top level domain (length from 1 to 63).
		      [a-z0-9-_]{1,63}         # Either traditional-tld-label = 1*63(ALPHA).
		    )                     # End top level domain.
		    $                     # Anchor to end of string.
		    /xi;

		if (not defined $remainder and not defined $top) {
			# we got the last part
			$top = $ds;
			$ds = '';
			$lastpart = 1;
		} else {
			chop $remainder;
			$ds = $remainder;
		}
		# is that top level domain part already in the current tree level?
		if (not exists $dthr->{$top}) {
			# not yet there, set it up
			$$dthr{$top} = {};
		}
		my $dthrn = %{$dthr}{$top};
		$dthr = $dthrn;
		if ($lastpart) {
			$$dthr{$lastpartstr} = {};
		}
	} while ($ds ne '');
}

sub getsnapdir
{
	my $snapdir = $opt_cwd;
    # get latest snapshot directory
    my @sdirs = readutfdir( $snapdir);
    my $latest = '';
    foreach (@sdirs) {
        if (-d "$snapdir/$_" and $_ gt $latest) {
            $latest = $_;
        }
    }
    $snapdir .= "/$latest";
	return $snapdir;
}

sub do_merge_list
{
	my $treehashref = shift;
	my $fileprefix = shift;
	my $mergefn = shift;
	my $hosturlfilename = shift;
	my $outtext = shift;
	
	my $snapdir = getsnapdir();
	my %domains = ();
	
	# now read the files, strip them from comments 
	# and merge their hostname lists
	my @hfiles = readutfdir( $snapdir);
	foreach (@hfiles) {
		# only read stripped files!
		next if (-d or not /$stripfext$/);
		next if (not /^$fileprefix.*?$/);
		my $fbuf = ();
		my $fchars = readutffile( "$snapdir/$_", \$fbuf);
		if (not defined $fchars) {
			plog( 0, "Failed to read hostsfile $snapdir/$_");
			die;
		}
		# now read in the lines and add each host to our list
		my @hostlist = split( "\n", lc $fbuf);
		# now process every entry
		foreach (@hostlist) {
			# do some checks:
			# is it domain or IP?
			# if IP, add to IP blocklist (if valid IP) TODO
			# if domain, check whether it is valid
			# useful link: https://www.oreilly.com/library/view/regular-expressions-cookbook/9781449327453/ch08s15.html
			if ( /\b((?=[a-z0-9-]{1,63}\.)[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b/ ) {
# 				if ( /^\s?+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+/) {
				if ( /^\s?+\d+\.\d+\.\d+\.\d+\s*/) {
					# it looks like an IP.
					# Check if it is a valid IP
					# if so, add to IP list
plog( 3, "Looks like IP address found, skipped for now: <$_>");
				} else {
					# seems to be a valid domain
					
					# domain is ok-formed, add it
					addDomain( $_, $treehashref);
				}
			} else {
plog( 3, "Badly-formed domain name found, skipped: <$_>");
			}
		}
	}
	# finally read the black/whitelist URL file,
	# and this time scan it for any manually added domains
	# (i.e. those that do not begin with a http[s]:// )
	my @hosts = ();
	plog( 1,"Reading hosts/URL file '$hosturlfilename'");
	do_read_listfile( $hosturlfilename, \@hosts, 1);
	foreach (@hosts) {
		addDomain( $_, $treehashref);
	}
	# write out the merged list in nicely domain-sorted manner
	printlist( $outtext, $treehashref, '');
	plog( 1, 'Finished merging lists');
	# generate output sorted from tld downwards
	writeutffile( "$snapdir/$mergefn", $outtext);
}

sub do_merge
{
	my $blacklisttext;
	my $whitelisttext;
	

	do_merge_list( \%blacktreehash, $blacklistprefix, $blackmergefilename, $bf, \$blacklisttext);
	do_merge_list( \%whitetreehash, $whitelistprefix, $whitemergefilename, $wf, \$whitelisttext);
	
	# now walk both lists
	my @finallist = my @blacklist = split( "\n", $blacklisttext);
	my @whitelist = split( "\n", $whitelisttext);
	my $indexref;
	my $offs = 0;
	foreach( @whitelist) {
		if ( anyindex( \@blacklist, $_, \$indexref)) {
			# remove whitelisted item from array
			splice( @finallist, $indexref - $offs++, 1);
		} 
	}
	# convert array to final blocklist text
	my $finallisttext = join( "\n", @finallist);
	my $snapdir = getsnapdir();
	my $fpath = $snapdir . '/' . $finalmergefilename;
	my $r = writeutffile( $fpath, \$finallisttext);
}

sub do_unbound
{
	my $snapdir = getsnapdir();
	my $fbuf = ();
	my $fchars = readutffile( "$snapdir/$finalmergefilename", \$fbuf);
	if (not defined $fchars) {
		plog( 0, "Failed to read mergefile $snapdir/$finalmergefilename");
		die;
	}
	my @hostlist = split( "\n", $fbuf);
	my $outtext;
	foreach (@hostlist) {
		# do *not* use redirect, as it will block possibly legit subdomains, too.
		# Or, use it if you want just this :)
		if ($opt_blocksubdir) {
            $outtext .= "local-zone: \"$_\" redirect\n";
            $outtext .= "local-data: \"$_ A $opt_redirectip\"\n";
        } else {
            $outtext .= "local-data: \"$_. IN A $opt_redirectip\"\n";
        }
	}
	my $unboundfn = "$snapdir/$unboundfilename";
	writeutffile( $unboundfn, \$outtext);
	plog( 1, "Finished preparing unbound include file '$unboundfn'");
	if ($opt_targetpath ne '') {
        writeutffile( "$opt_targetpath/$unboundfilename", \$outtext);
        plog( 1, "Copied unbound include file '$unboundfilename' to '$opt_targetpath'");
	}
}


sub main
{
	if ($opt_configpath ne '') {
       	$bf = "$opt_configpath/$opt_blacklistsfile";
       	$wf = "$opt_configpath/$opt_whitelistsfile";
    } else {
       	$bf = "$opt_cwd/$opt_blacklistsfile";
       	$wf = "$opt_cwd/$opt_whitelistsfile";
    }
                
	if ($opt_download) {
        do_download();
    } elsif ($opt_strip) {
        do_strip();
    } elsif ($opt_merge) {
        do_merge();
    } elsif ($opt_downloadstripmerge) {
        do_download();
        do_strip();
        do_merge();
        if ($opt_unbound) {
            do_unbound();
        }
    } elsif ($opt_unbound) {
        do_unbound();
    } else {
        opt_show_help();
    }
}

main( );
exit 0;

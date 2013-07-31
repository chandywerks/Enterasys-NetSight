package Enterasys::NetSight;
use strict;
use warnings;

use SOAP::Lite;
use Socket;

# On some systems Crypt::SSLeay uses IO::Socket::SSL and breaks,
# This forces it to use Net::SSL just in case.
$ENV{PERL_NET_HTTPS_SSL_SOCKET_CLASS} = "Net::SSL";
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

sub new
{
	my ($class, $args) = @_;
	my $self = 
	{
		host 	=> $args->{host} || undef,
		port	=> $args->{port} || 8443,
		user	=> $args->{user} || undef,
		pass	=> $args->{pass} || undef,
	};
	$self->{proxy} = "https://".$self->{user}.":".$self->{pass}."@".$self->{host}.":".$self->{port}."/axis/services/NetSightDeviceWebService";

	$self->{soap} = SOAP::Lite->new(
			uri		=> "http://ws.web.server.netsight.enterasys.com",
			proxy	=> $self->{proxy},
		);

	return bless($self, $class);
}
sub snmp
{
	# Returns a hash reference with SNMP credentails
	# The format of this hash can be used to create a 
	# new SNMP::Session with the Net-SNMP module

	my ($self,$ip) = @_;
	my (%snmp,%temp) = ();

	$ip=inet_ntoa(inet_aton($ip));	# Resolve hostname

	my $ret = $self->{soap}->getSnmpCredentialAsNgf($ip);
	if($ret->fault)
	{
		warn $ret->faultcode." : ".$ret->faultstring."\n";
		return undef;
	}

	# Parse NGF SNMP string into hash table
	foreach my $attribute(split(" ",$ret->result() || return undef))
	{
		if((my @keyval=split("=",$attribute))==2)
			{ $temp{$keyval[0]}=$keyval[1] }
	}

	# Format hash for Net-SNMP
	my $auth = "";	# Use to build Net-SNMP SecLevel param

	$snmp{DestHost}=$ip;
	$snmp{Version}=substr($temp{snmp},1,1);

	if($snmp{Version} == 3)
	{
		$snmp{SecName}=$temp{user};
		if($temp{authtype} ne "None")
		{
			$temp{authtype} =~ s/SHA\d+/SHA/;
			$snmp{AuthProto}=$temp{authtype};
			$snmp{AuthPass}=$temp{authpwd};
			$auth="auth";
		}
		else
		{
			$auth="noAuth";
		}

		if($temp{privtype} ne "None")
		{
			$snmp{PrivProto}=$temp{privtype};
			$snmp{PrivPass}=$temp{privpwd};	
			$auth .= "Priv";
		}
		else
		{
			$auth .= "NoPriv";
		}
		$snmp{SecLevel} = $auth;
	}
	else
	{
		# Attempts to get highest privilage community string
		# TODO Allow user to specify argument for privilage level?
		if($temp{su})
		{
			$snmp{Community}=$temp{su};
		}
		elsif($temp{rw})
		{
			$snmp{Community}=$temp{rw};
		}
		elsif($temp{ro})
		{
			$snmp{Community}=$temp{ro};
		}
		else
		{
			return undef;
		}
	}
	return %snmp;
}
1;

=head1 NAME

Enterasys::NetSight - Provides an abstraction layer between SOAP::Lite and the Netsight Device WebService.

=head1 SYNOPSIS

	use Enterasys::NetSight
	my $netsight = Enterasys::NetSight->new({
				host	=> $ip_addr,
				port	=> $port,
				user	=> $username,
				pass	=> $password,
			});

	# You can make any API call available with $netsight->{soap}...
	# For example the following would print a NetSight Generated Format string
	# containing SNMP credentials for a specified IP address,
	print $netsight->{soap}->getSnmpCredentialAsNgf($ip)->result(),"\n";

	# However there are methods available to put the data in a more usable hash table,
	print Dumper({$netsight->snmp($ip)});

	# Used with the perl SNMP module you can use the return of that method to create a
	# new SNMP session object,
	my $session = new SNMP::Session($netsight->snmp($ip));

	# Which you could then use to query a mib,
	print $session->get('sysDescr.0');

=head2 Methods

=over 12

=item C<new>

Requires a 'host', 'user', and 'pass' parameter. 'port' is optional and will default to port 8443.
Returns a new Enterasys::Netsight object or undef if invalid parameters were specified.

=item C<snmp>

Requires an IP address or hostname as an argument. Returns a hash table which can be passed
as an argument to make a new SNMP::Session with the perl SNMP module. Returns undef if no
SNMP creds found.

=back

=head1 AUTHOR

Chris Handwerker - <chandwer@enterasys.com>

=cut

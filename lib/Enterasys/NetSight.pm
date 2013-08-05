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

	return defined(eval{$self->{soap}->isIpV6Enabled()})?bless($self, $class):undef;
}
sub getAllDevices
{
	# Returns a hash table with IP Addresses for keys
	# and a hash reference value containing device information
	# associated with the IP address

	my ($self) = @_;
	my %devices = ();

	my $ret = $self->{soap}->getAllDevices;

	if($ret->fault)
	{
		warn "Error: ".$ret->faultstring."\n";
		return undef;
	}

	# Grab IP out of each WsDeviceListResult
	while(my($key,$value)=each($ret->result->{data}))
	{
		print "$key => $value\n";
		$devices{$value->{ip}}=$value;
	}
	return \%devices;
}
sub getDevice
{
	# Returns a WsDevice table for a given IP address
	my ($self,$ip) = @_;
	my $ret=$self->{soap}->getDeviceByIpAddressEx($ip);

	if($ret->fault)
	{
		warn "Error: ".$ret->faultstring."\n";
		return undef;
	}

	return $ret->result->{data};
}
sub getSnmp
{
	# Returns a hash reference with SNMP credentails
	# The format of this hash can be used to create a 
	# new SNMP::Session with the Net-SNMP module

	my ($self,$ip) = @_;
	my (%snmp,%temp) = ();

	$ip=inet_ntoa(inet_aton($ip));	# Resolve hostname

	my $ret=$self->{soap}->getSnmpCredentialAsNgf($ip);

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
sub exportDevices
{
	# Gets credentails for all devices in NetSight as an NGF string and
	# parses it into a hash table

	my ($self) = @_;
	my %table = ();

	my $ret=$self->{soap}->exportDevicesAsNgf;

	if($ret->fault)
	{
		warn "Error: ".$ret->faultstring."\n";
		return undef;
	}

	foreach my $line(split("\n",$ret->result))
	{
		my %temp = ();
		foreach my $attribute(split(" ",$line))
		{
			if((my @keyval=split("=",$attribute))==2)
				{ $temp{$keyval[0]}=$keyval[1] }
			else
				{ $temp{$keyval[0]}=undef }
		}
		$table{$temp{dev}}=\%temp;
	}
	return \%table;
}
1;

# ABSTRACT: Provides an abstraction layer between SOAP::Lite and the Netsight Device WebService.

=head1 SYNOPSIS

	use Enterasys::NetSight;
	use Data::Dumper;

	my $netsight = Enterasys::NetSight->new({
				host	=> $ip_addr,
				port	=> $port,
				user	=> $username,
				pass	=> $password,
			}) or die $!;

	# You can make any API call available with $netsight->{soap}...
	# For example the following would print a NetSight Generated Format string
	# containing SNMP credentials for a specified IP address,

	print $netsight->{soap}->getSnmpCredentialAsNgf($ip)->result(),"\n";

	# However this module provides shortcut methods returning useful data formats,
	# for example using the 'getSnmp' method,

	print Dumper({$netsight->getSnmp($ip)});

	# Used with the perl SNMP module you can use the return of that method to create a
	# new SNMP session object,

	my $session = new SNMP::Session($netsight->getSnmp($ip));

	# Which you could then use to query a mib,

	print $session->get('sysDescr.0');

	# See OF-Connect-WebServices.pdf for details about API calls and complex data types referenced in this doc.

=head2 Methods

=over 12

=item C<new>

Requires a 'host', 'user', and 'pass' parameter. 'port' is optional and will default to port 8443.
Returns a new Enterasys::Netsight object or undef if invalid parameters were specified.

=item C<getSnmp>

Requires an IP address or hostname as an argument. Returns a hash table which can be passed
as an argument to make a new SNMP::Session with the perl SNMP module. Returns undef if no
SNMP creds found.

=item C<getDevice>

Requires an IP address or hostname as an argument. Returns a WsDevice hash table containing device information.
Shortcut for $netsight->{soap}->getDeviceByIpAddressEx($ip)->result()->{data}. This method will
check the return status for errors. Returns undef if no device details found.

=item C<getAllDevices>

Returns a hash table with device IP address keys and hash reference values pointing to
a WsDevice table. The WsDevice table contains details about each device.

=item C<exportDevices>

Returns a hash table with device IP address keys and a hash reference to a table containing both
SNMP and/or CLI credentails. This method parses the NetSight Generated Format (NGF) strings returned
from the 'exportDevicesAsNgf' API call.

=back

=cut

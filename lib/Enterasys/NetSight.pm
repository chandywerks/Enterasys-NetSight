package Enterasys::NetSight;
use strict;
use warnings;

use SOAP::Lite;
use Socket;
use Carp;

# On some systems Crypt::SSLeay uses IO::Socket::SSL and breaks,
# This forces it to use Net::SSL just in case.
$ENV{PERL_NET_HTTPS_SSL_SOCKET_CLASS}="Net::SSL";
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME}=0;

sub new
{
	my ($class, $args)=@_;
	my $self= 
	{
		host 	=> _resolv($args->{host}) || undef,
		port	=> $args->{port} || 8443,
		user	=> $args->{user} || undef,
		pass	=> $args->{pass} || undef,
	};

	if(!$self->{host})
		{ carp("You must specify a host for new method") && return undef }
	elsif(!$self->{user})
		{ carp("You must specify a user for new method") && return undef }
	elsif(!$self->{pass})
		{ carp("You must specify a password for new method") && return undef }

	$self->{proxy} = "https://".$self->{user}.":".$self->{pass}."@".$self->{host}.":".$self->{port}."/axis/services/NetSightDeviceWebService";

	$self->{soap} = SOAP::Lite->new(
			uri		=> "http://ws.web.server.netsight.enterasys.com",
			proxy	=> $self->{proxy},
		);
	# Make sure we can make an API call or return undef
	return defined(eval{$self->{soap}->isIpV6Enabled()})?bless($self, $class):undef;
}

# Get methods
sub getAllDevices
{
	# Returns a hash table with IP Addresses for keys
	# and a hash reference value containing device information
	# associated with the IP address

	my ($self)=@_;
	my %devices=();

	my $call=$self->{soap}->getAllDevices;

	if($call->fault) 
		{ carp($call->faultstring) && return undef }

	# Grab IP out of each WsDeviceListResult
	while(my($key,$value)=each($call->result->{data}))
		{ $devices{$value->{ip}}=$value }

	return %devices;
}
sub getDevice
{
	# Returns a WsDevice table for a given IP address
	my ($self,$args)=@_;

	if(!defined $args->{host})
		{ carp("You must specify a host for getDevice method") && return undef }

	$args->{host}=_resolv($args->{host});

	my $call=$self->{soap}->getDeviceByIpAddressEx($args->{host});

	if($call->fault) 
		{ carp($call->faultstring) && return undef }

	return $call->result->{data};
}
sub getSnmp
{
	# Returns a hash reference with SNMP credentials
	# The format of this hash can be used to create a 
	# new SNMP::Session with the Net-SNMP module

	my ($self,$args)=@_;
	my (%snmp,%temp)=();

	if(!defined $args->{host})
		{ carp("You must specify a host for getSnmp method") && return undef }
	if(defined $args->{level} && $args->{level} ne "su" && $args->{level} ne "rw" && $args->{level} ne "ro")
		{ carp("Invalid privilege level specified. Valid options are su, rw, or ro") && return undef }

	$args->{host}=_resolv($args->{host});

	my $call=$self->{soap}->getSnmpCredentialAsNgf($args->{host});

	if($call->fault) 
		{ carp($call->faultstring) && return undef }

	# Parse NGF SNMP string into hash table
	foreach my $attribute(split(" ",$call->result() || return undef))
	{
		if((my @keyval=split("=",$attribute))==2)
			{ $temp{$keyval[0]}=$keyval[1] }
	}

	# Format hash for Net-SNMP
	my $auth="";	# Use to build Net-SNMP SecLevel param

	$snmp{DestHost}=$args->{host};
	$snmp{Version}=substr($temp{snmp},1,1);

	if($snmp{Version}==3)
	{
		$snmp{SecName}=$temp{user};
		if($temp{authtype} ne "None")
		{
			$temp{authtype}=~s/SHA\d+/SHA/;
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
			$auth.="Priv";
		}
		else
		{
			$auth.="NoPriv";
		}
		$snmp{SecLevel}=$auth;
	}
	else
	{
		# Attempts to get highest privilage community string if no level specified
		if(defined $args->{level})
			{ $snmp{Community}=$temp{$args->{level}} or return undef }
		elsif($temp{su})
			{ $snmp{Community}=$temp{su} }
		elsif($temp{rw}) 
			{ $snmp{Community}=$temp{rw} }
		elsif($temp{ro})
			{ $snmp{Community}=$temp{ro} }
		else
			{ return undef }
	}

	return %snmp;
}
sub getAuth
{
	# Runs the 'exportDevices' method if $self->{devices} hash ref is undefined
	# and uses that to parse Cli credentials for all other calls.
	my ($self,$args)=@_;

	if(!defined $args->{host})
		{ carp("You must specify a host for getCli method") && return undef }
	if($args->{refresh})
		{ $self->{devices}=undef }
	if(!defined $self->{devices})
		{ $self->{devices}=exportDevices($self) or return undef }

	$args->{host}=_resolv($args->{host});

	my %creds=();
	my $device=$self->{devices}->{$args->{host}};

	$creds{host}=$device->{dev};
	$creds{user}=$device->{cliUsername};
	$creds{pass}=$device->{cliLogin};
	
	return %creds;
}
sub exportDevices
{
	# Gets credentials for all devices in NetSight as an NGF string and
	# parses it into a hash table
	my ($self)=@_;
	my %table=();

	my $call=$self->{soap}->exportDevicesAsNgf;

	if($call->fault) 
		{ carp($call->faultstring) && return undef }

	foreach my $line(split("\n",$call->result))
	{
		my %temp=();
		foreach my $attribute(split(" ",$line))
		{
			if((my @keyval=split("=",$attribute))==2)
				{ $temp{$keyval[0]}=$keyval[1] }
			else
				{ $temp{$keyval[0]}=undef }
		}
		$table{$temp{dev}}=\%temp;
	}

	return %table;
}
sub ipV6Enabled
{
	my ($self)=@_;
	my $call=$self->{soap}->isIpV6Enabled;

	if($call->fault) 
		{ carp($call->faultstring) && return undef }

	return $call->result();
}
sub netSnmpEnabled
{
	my ($self)=@_;
	my $call=$self->{soap}->isNetSnmpEnabled;

	if($call->fault) 
		{ carp($call->faultstring) && return undef }

	return $call->result();
}

# Add Methods
sub addAuth
{

}
sub addSnmp
{

}
sub addDevice
{

}
sub addProfile
{

}

# Update Methods
sub updateAuth
{

}
sub updateSnmp
{

}
sub updateDevice
{

}
sub updateProfile
{

}

# Delete Methods
sub deleteDevice
{

}

# Private
sub _resolv
{
	# Resolve IP for a hostname
	my ($host)=@_;
	return inet_ntoa(inet_aton($host));
}
1;

# ABSTRACT: Provides an abstraction layer between SOAP::Lite and the Netsight Device WebService.

=head1 SYNOPSIS

	use Enterasys::NetSight;
	use Data::Dumper;

	my $netsight = Enterasys::NetSight->new({
				host	=> $ip,
				port	=> $port,
				user	=> $username,
				pass	=> $password,
			}) or die $!;

You can make any API call available with the SOAP::Lite object accessable with $netsight->{soap}.

For example the following would print a NetSight Generated Format string containing SNMP credentials for a specified IP address,

	print $netsight->{soap}->getSnmpCredentialAsNgf($ip)->result(),"\n";

However this module provides shortcut methods returning useful data formats to work with. 

For example we can parse the NGF formatted string into a hash table with the getSnmp method,

	print Dumper {$netsight->getSnmp({host=>$ip})};

Used with the perl SNMP module you can use the return of that method to create a new SNMP session object,

	my $session = new SNMP::Session($netsight->getSnmp({host=>$ip}));

Which you could then use to query a mib,

	print $session->get('sysDescr.0');

More examples

	print Dumper $netsight->getAuth({host=>$ip, refresh=>1});
	print Dumper $netsight->getDevice({host=>$ip});

	print Dumper $netsight->getAllDevices();
	print Dumper $netsight->exportDevices();

	print $netsight->ipV6Enabled?"true":"false";
	print $netsight->netSnmpEnabled?"true":"false";

=head1 METHODS

See OF-Connect-WebServices.pdf for details about API calls and complex data types referenced in this doc.

=over

=item new()

Returns a new Enterasys::Netsight object or undef if invalid parameters were specified.

=over

=item host

IP address or hostname of the NetSight server.

=item user

Username with API access.

=item pass

Password for the user.

=item port

Optional port, defaults to NetSight's default port 8443.

=back


=item getSnmp()

Returns a hash table which can be passed as an argument to make a new SNMP::Session with the perl SNMP module. Returns undef if no SNMP creds found.

=over

=item host

IP address or hostname of a target device.

=item level

Optional, defaults to highest privilage level available. Options are su, rw, ro (super user, read/write, read only). If specified privilage does not exist method returns undef. This parameter is ignored if the device has SNMP v3 credentials.

=back

=item getAuth()

Returns a hash table containing CLI credentials: host, user, and pass. Because there is no API call to get a single CLI cred, similar to getSnmpCredentialAsNgf, this method runs the "exportDevices" method once and keeps the device information in memory.

=over

=item host

IP address or hostname of a target device.

=item refresh

Exports devices from the NetSight server and stores an updated copy in memory when set true.

=back

=item getDevice()

Returns a WsDevice hash table containing device information. Shortcut for $netsight->{soap}->getDeviceByIpAddressEx($ip)->result()->{data}. This method will check the return status for errors. Returns undef if no device details found.

=over

=item host

IP address or hostname of a target device.

=back


=item getAllDevices()

Returns a hash table with device IP address keys and hash reference values pointing to
a WsDevice table containing device information. Returns undef on error.


=item exportDevices()

Returns a hash table with device IP address keys and a hash reference to a table containing both
SNMP and/or CLI credentials. This method parses the NetSight Generated Format (NGF) strings returned
from the 'exportDevicesAsNgf' API call. Returns undef on error.


=item ipV6Enabled()

Returns 1 if NetSight is configured for IPv6, 0 if not, undef on error. Shortcut for $netsight->{soap}->isNetSnmpEnabled.


=item netSnmpEnabled()

Returns 1 if NetSight is using the Net-SNMP stack, 0 if not, undef on error. Shortcut for $netsight->{soap}->netSnmpEnabled.

=back

=cut

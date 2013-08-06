Enterasys::NetSight
=========

This module provides an abstraction layer between SOAP::Lite and the NetSight Device WebService and provides methods that parse return data into useful data structures.

For example the 'snmp' method in Enterasys::NetSight returns snmp creds for a given IP as a hash table which can be used with the perl SNMP module to create a new SNMP::Session object.

See perldoc for usage details.

### INSTALLATION

If you just want to use the module [download a package from here](https://metacpan.org/) or through a cpan client. NOTE: net yet on cpan

If you wish the build a package from the git repository you need the Dist::Zilla application and git.

To build a package from git:

	git init
	git pull https://github.com/chandwer/Enterasys-NetSight.git
	dzil build

To install the built package:

	cd Enterasys-NetSight-#.##
    perl Makefile.PL
    make test
    sudo make install

### DEPENDENCIES

* SOAP::Lite
* Net::SSL
* Socket

### AUTHOR

Chris Handwerker 2013 <<chandwer@enterasys.com>>

### LICENSE

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

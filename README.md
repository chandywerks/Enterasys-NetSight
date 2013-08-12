Enterasys::NetSight
=========

This module provides an abstraction layer between SOAP::Lite and the NetSight Device WebService and provides methods that parse return data into useful data structures.

For example the 'snmp' method in Enterasys::NetSight returns snmp creds for a given IP as a hash table which can be used with the perl SNMP module to create a new SNMP::Session object.

See perldoc for usage details.

### INSTALLATION

You can use the cpan or cpanm CLI utility to install the package. This will attempt to satisfy all the dependencies for you.
You may need to download the OpenSSL header files in order to install the Crypt::SSLeay dependancy. 
In debian based systems you can install the headers with aptitude like so,

	sudo apt-get install libssl-dev

If you wish to install manually you will have to make sure you have the SOAP::Lite module installed.
Download the [tar.gz package](https://metacpan.org/module/Enterasys::NetSight) and run the following,

	tar -xvf Enterasys-NetSight-#.##.tar.gz
	cd Enterasys-NetSight-#.##
	perl Makefile.PL
	make test
	sudo make install

If make test fails you are probably missing SOAP::Lite or some other dependency.

### BUILDING PACKAGE FROM GIT

If you wish the build a package from the git repository you will need git and the Dist::Zilla application along with
the PodWeaver plugin.

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
* Socket
* Carp

### AUTHOR

Chris Handwerker 2013 <<chandwer@enterasys.com>>

### LICENSE

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

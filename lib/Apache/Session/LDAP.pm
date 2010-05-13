package Apache::Session::LDAP;

use strict;
use vars qw(@ISA $VERSION);

$VERSION = '0.02';
@ISA = qw(Apache::Session);

use Apache::Session;
use Apache::Session::Lock::Null;
use Apache::Session::Store::LDAP;
use Apache::Session::Generate::MD5;
use Apache::Session::Serialize::Storable;

sub populate {
    my $self = shift;

    $self->{object_store} = new Apache::Session::Store::LDAP $self;
    $self->{lock_manager} = new Apache::Session::Lock::Null $self;
    $self->{generate}     = \&Apache::Session::Generate::MD5::generate;
    $self->{validate}     = \&Apache::Session::Generate::MD5::validate;
    $self->{serialize}    = \&Apache::Session::Serialize::Storable::serialize;
    $self->{unserialize}  = \&Apache::Session::Serialize::Storable::unserialize;

    return $self;
}

1;

=pod

=head1 NAME

Apache::Session::LDAP - An implementation of Apache::Session

=head1 SYNOPSIS

  use Apache::Session::LDAP;
  tie %hash, 'Apache::Session::DB_File', $id, {
    ldapServer       => 'ldap://localhost:389',
    ldapConfBase     => 'dmdName=applications,dc=example,dc=com',
    ldapBindDN       => 'cn=admin,dc=example,dc=com',
    ldapBindPassword => 'pass',
  };

=head1 DESCRIPTION

This module is an implementation of Apache::Session.  It uses an LDAP directory
to store datas.

=head1 AUTHOR

Xavier Guimard, E<lt>guimard@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Xavier Guimard

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=head1 SEE ALSO

L<Apache::Session>

=cut

## OpenCA::OpenSSL::Configuration
##
## Copyright (C) 2001 Michael Bell (loon@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## Copyright remains Michael Bell's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Michael Bell should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
##    "This product includes OpenCA software written by Michael Bell
##     (loon@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]
##
## Porpouse:
## =========
##
## Get easily configuration parameters passed into an openssl config file
##
## Status:
## =======
##
##          Started: 2001-Feb-02
##    Last Modified: 2001-Mar-02
##

## if you edit the CA_FILE please do the following
## @ca = getSection (MODE => CA, FILE => CA_FILE);
## foreach $role ('ls ..../OpenSSL/') {
##   ca -> %hca
##   @help = getSection (MODE => ROLE, FILE => $role);
##   overwrite %hca with the values of @help
##   setSection (MODE => CA. FILE => ROLE, HASH => @hca);
## }

use strict;

package OpenCA::OpenSSL::Configuration;

use OpenCA::TRIStateCGI;

$OpenCA::OpenSSL::Configuration::VERSION = '0.1.0';

##
## Before I start programing something to this part of OpenCA
##
## We don't have to use the full flexibility of OpenSSL. We only
## use the parts which we need
##
## So we use OpenSSL from a little bit different view
##
## first we know the default-section at the beginning of the config-file
##
## But know comes our idea of roles
##
## we have normal roles and a special role called "CA" ;-)
##
##                ##########
##                ## ROLE ##
##                ##########
##                    ##
##  ####################################################################################
##  # REQ # DN # ATTRIBUTES # REQ_EXT # X509_EXT # CA # POLICY # CRL_EXT # OID_SECTION #
##  ####################################################################################
##
## our naming rules are the followings
##
## The CA itself: 
##   - req       (not with role)
##   - ca
##   - dn        (not with role)
##   - policy
##   - attribute (not with role)
##   - req_ext   (not with role)
##   - crl_ext
##   - x509_ext
##   - oid_section
##
## The role with the name xyz has the same sections but with "_xyz".
##
## Parsing:
##   - localize the sections
##   - build the roles
##   - finish
##
## Menus:
##   - I know nine different menus per each role
##   - MENU => name of section
##   - ROLE => role which is affected
##   - MENU => "DEFAULT" is the leading default section
##   - ROLE => "" is the CA itself
##   - MENU => "ROLE"    is list of all roles (incl. default)

$OpenCA::OpenSSL::Configuration::MENU = {
  CA =>
  {
   DEFAULT => [
               "oid_section",
               "HOME",
               "RANDFILE",
               "dir"
              ],
   REQ => [
           "dir",
           "default_bits",
           "default_keyfile",
           "input_password",
           "output_password",
           "oid_file",
           "RANDFILE",
           "encrypt_key",
           "default_md",
           "string_mask",
          ],
   CA => [
          "dir",
          "certs",
          "crl_dir",
          "database",
          "new_certs_dir",
          "certificate",
          "serial",
          "crl",
          "private_key",
          "RANDFILE",
          "HOME",
          "default_days",
          "default_startdate",
          "default_enddate",
          "default_crl_days",
          "default_md",
          "database",
          "msie_hack",
          "preserve",
          "oid_file",
         ],
   DN => [
          "countryName",
          "stateOrProvinceName",
          "localityName",
          "0.organizationName",
          "1.organizationName",
          ## if you need it activate it ;-)
          ## "2.organizationName",
          ## "3.organizationName",
          ## "4.organizationName",
          ## "5.organizationName",
          ## "6.organizationName",
          ## "7.organizationName",
          ## "8.organizationName",
          ## "9.organizationName",
          "0.organizationalUnitName",
          "1.organizationalUnitName",
          "2.organizationalUnitName",
          "commonName",
          "emailAddress"
         ],
   POLICY => [
              "countryName",
              "stateOrProvinceName",
              "localityName",
              "organizationName",
              "organizationalUnitName",
              "commonName",
              "emailAddress"
             ],
   ATTRIBUTE => [
                 "unstructuredName",
                 "challengePassword"
                ],
   REQ_EXT => [
               "challengePassword",
               "unstructuredName"
              ],
   CRL_EXT => [
               "issuerAltName",
               "authorityKeyIdentifier"
              ],
   X509_EXT => [
                "authorityInfoAccess",
                "basicConstraints",
                "crlDistributionPoints",
                "keyUsage",
                "extendedKeyUsage",
                "subjectKeyIdentifier",
                "authorityKeyIdentifier",
                "subjectAltName",
                "issuerAltName",
                "nsCertType",
                "nsComment",
                "nsCaRevocationUrl",
                "nsBaseUrl",
                "nsRevocationUrl",
                "nsRenewalUrl",
                "nsCaPolicyUrl",
                "nsSslServerName"
               ]
  },

  ROLE =>
  {
   REQ => [
           "default_bits",
           "default_keyfile",
           "input_password",
           "output_password",
           "encrypt_key",
           "default_md",
           "string_mask",
          ],
   CA => [
          "default_days",
          "default_startdate",
          "default_enddate",
          "default_md",
          "msie_hack",
          "preserve",
         ],
   DN => [
          "countryName",
          "stateOrProvinceName",
          "localityName",
          "0.organizationName",
          "1.organizationName",
          ## if you need it activate it ;-)
          ## "2.organizationName",
          ## "3.organizationName",
          ## "4.organizationName",
          ## "5.organizationName",
          ## "6.organizationName",
          ## "7.organizationName",
          ## "8.organizationName",
          ## "9.organizationName",
          "0.organizationalUnitName",
          "1.organizationalUnitName",
          "2.organizationalUnitName",
          "commonName",
          "emailAddress"
         ],
   POLICY => [
              "countryName",
              "stateOrProvinceName",
              "localityName",
              "organizationName",
              "organizationalUnitName",
              "commonName",
              "emailAddress"
             ],
   ATTRIBUTE => [
                 "unstructuredName",
                 "challengePassword"
                ],
   REQ_EXT => [
               "challengePassword",
               "unstructuredName"
              ],
   CRL_EXT => [
               "issuerAltName",
               "authorityKeyIdentifier"
              ],
   X509_EXT => [
                "authorityInfoAccess",
                "basicConstraints",
                "crlDistributionPoints",
                "keyUsage",
                "extendedKeyUsage",
                "subjectKeyIdentifier",
                "authorityKeyIdentifier",
                "subjectAltName",
                "issuerAltName",
                "nsCertType",
                "nsComment",
                "nsCaRevocationUrl",
                "nsBaseUrl",
                "nsRevocationUrl",
                "nsRenewalUrl",
                "nsCaPolicyUrl",
                "nsSslServerName"
               ]
  },
};

$OpenCA::OpenSSL::Configuration::SECTION =
  {
   X509_EXT  => "ext",
   CRL_EXT   => "crl",
   REQ_EXT   => "req_ext",
   POLICY    => "policy",
   DN        => "dn",
   ATTRIBUTE => "attribute",
   CA        => "default_ca",
   REQ       => "req",
   OID       => "oid",
   DEFAULT   => ""
  };
# Preloaded methods go here.

######################
## public functions ##
######################
## getMenu          ##
## getSection       ##
## setSection       ##
######################

################
## getMenu
################
## Arguments
##   * MODE
##   * SECTION
################
## return value is a sorted array 
## with all possible menuentries
##
## if section is empty then the names of the 
## possible menues will be displayed
################
sub getMenu {
  my $self = shift;
  my $keys = { @_ };

  my @return;

  ## check the mode
  my $mode  = uc $keys->{MODE};
  return undef if ($mode !~ /^(CA|ROLE)$/ );

  ## check the section
  my $section = uc $keys->{SECTION};
  return undef
    if ($section !~ 
        /^(CA|X509_EXT|CRL_EXT|REQ_EXT|ATTRIBUTE|REQ|POLICY|OID|DEFAULT|DN|)$/ 
       );

  if (not $keys->{SECTION}) {
    ## show the available section
    my $help;

    foreach $help (keys %{$OpenCA::OpenSSL::Configuration::MENU->{$mode}}) {
      push (@return, $help);
    }
  } else {
    ## normal menu
    @{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}} =
      sort @{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}};
    my $i;
    for ($i = 0; 
         $i < scalar (@{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}}); 
         $i++) {
      push (@return,
            $OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]
           );
      if ($section =~ /^DN$/i ) {
        push (@return,
              $OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]."_default"
             );
        push (@return,
              $OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]."_min"
             );
        push (@return,
              $OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]."_max"
             );
      }
    } 
    @return = reverse @return;
  }

  return @return;
}


################
## getSection
################
## Arguments
##   * MODE
##   * SECTION
##   * FILE
##   * FILETYPE
################
## return value is a sorted array 
## with all possible menuentries and evtl. values)
##
## if section is empty then the default-section is taken
################
sub getSection {

  my $class = shift; 
  my $keys = { @_ };
  my $self = { DEBUG => 0 };
  bless $self, $class;

  my @return;

  ## check the mode
  my $mode  = uc $keys->{MODE};
  return undef if ($mode !~ /^(CA|ROLE)$/i );

  ## check the section
  my $section = uc $keys->{SECTION};
  return undef
    if ($section !~ 
        /^(CA|X509_EXT|CRL_EXT|REQ_EXT|ATTRIBUTE|REQ|POLICY|OID|DEFAULT|DN|)$/ 
       );
     

  ## loadfile
  $self->loadFile ($keys->{FILE});

  ## load section
  if ( $keys->{FILETYPE} =~ /^EXT$/i ) {
    $self->parseCfg;
  } elsif ( not $keys->{FILETYPE} ) {
    $self->parseCfg ($OpenCA::OpenSSL::Configuration::SECTION->{$section});
  } else {
    return undef;
  }

  ## build menu
  @{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}} =
    sort @{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}};
  my $i;
  for ($i = 0; 
       $i < scalar (@{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}}); 
       $i++) {
    $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]} =~
      s/\\\n/\n/g;
    push (@return,
          [
           $OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i],
           $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]}
          ]
         );
    if ($section =~ /^DN$/i ) {
      push (@return,
            [
             $OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]."_default",
             $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]."_default"}
            ]
           );
      push (@return,
            [
             $OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]."_min",
             $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]."_min"}
            ]
           );
      push (@return,
            [
             $OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]."_max",
             $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]."_max"}
            ]
           );
    }
  } 

  return reverse @return;
}

################
## setSection
################
## Arguments
##   * MODE
##   * SECTION
##   * FILE
##   * FILETYPE
################
## return is 0|1 
################
sub setSection {

  my $class = shift; 
  my $self = { DEBUG => 0 };
  bless $self, $class;
  my $keys = { @_ };

  ## check the mode
  my $mode  = uc $keys->{MODE};
  return 0 if ($mode !~ /^(CA|ROLE)$/ );

  ## check the section
  my $section = uc $keys->{SECTION};
  return 0
    if ($section !~ 
        /^(CA|X509_EXT|CRL_EXT|REQ_EXT|ATTRIBUTE|REQ|POLICY|OID|DEFAULT|DN|)$/ 
       );
     
  ## load file
  print "setSection: loadFile<br>\n" if ($self->{DEBUG});
  $self->loadFile ($keys->{FILE});

  ## remove section from confLines
  print "setSection: parseCfg<br>\n" if ($self->{DEBUG});
  if ( $keys->{FILETYPE} !~ /^EXT$/i ) {
    $self->parseCfg ($OpenCA::OpenSSL::Configuration::SECTION->{$section});
  } else {
    $self->parseCfg ($OpenCA::OpenSSL::Configuration::SECTION->{DEFAULT});
  }

  ## load the edited section
  print "setSection: edit the section<br>\n" if ($self->{DEBUG});
  my $cgi  = new OpenCA::TRIStateCGI;
  my $i;
  if ( $keys->{OPTION} ) {
    $self->{cnfDB}->{$keys->{OPTION}} = $keys->{VALUE};
    if ( $self->{cnfDB}->{$keys->{OPTION}} =~ /^$/ ) {
      delete $self->{cnfDB}->{$keys->{OPTION}};
    } else {
      $self->{cnfDB}->{$keys->{OPTION}} =~ s/(\r|)\n/\\\n/g;
    }
  } else {
    for ($i = 0; 
         $i < scalar (@{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}}); 
         $i++) {
      if ($keys->{HASH}) {
        $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]} =
          $keys->{HASH}{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]};
      } else {
        $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]} =
          $cgi->param ($OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]);
      }
  
      if ( $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]}
           =~ /^$/ ) {
        delete
          $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]};
      } else {
        $self->{cnfDB}->{$OpenCA::OpenSSL::Configuration::MENU->{$mode}->{$section}[$i]} =~
          s/(\r|)\n/\\\n/g;
      }
    }
  }

  ## add the edited section
  print "setSection: add the edited the section<br>\n" if ($self->{DEBUG});
  if ( $keys->{FILETYPE} !~ /^EXT$/i ) {
    push @{$self->{cnfLines}}, "\n [ ".
                              $OpenCA::OpenSSL::Configuration::SECTION->{$section}.
                              " ] \n";
  }
  ## protect dir, nsSslServerName, nsBaseUrl etc.
  if ( $self->{cnfDB}->{dir} ) {
    push @{$self->{cnfLines}}, "dir = ".$self->{cnfDB}->{dir}."\n";
    delete $self->{cnfDB}->{dir};
  }
  if ( $self->{cnfDB}->{nsSslServerName} ) {
    push @{$self->{cnfLines}}, "nsSslServerName = ".$self->{cnfDB}->{nsSslServerName}."\n";
    delete $self->{cnfDB}->{nsSslServerName};
  }
  if ( $self->{cnfDB}->{nsBaseUrl} ) {
    push @{$self->{cnfLines}}, "nsBaseUrl = ".$self->{cnfDB}->{nsBaseUrl}."\n";
    delete $self->{cnfDB}->{nsBaseUrl};
  }
  foreach $i (keys %{$self->{cnfDB}}) {
    push @{$self->{cnfLines}}, $i." = ".$self->{cnfDB}->{$i}."\n";
  }

  ## write confLines to file
  my $emptyLine = 0;
  print "setSection: write the file<br>\n" if ($self->{DEBUG});
  open( FD, ">$keys->{FILE}" ) || return 0;
  foreach $i (@{$self->{cnfLines}}) {
    if ($i =~ /^ *\n$/ ) {
      if (not $emptyLine) {
        print FD $i;
        $emptyLine = 1;
      }
    } else {
      $emptyLine = 0;
      print FD $i;
    }
  }
  close(FD);

  return 1;
}

################
## newRole
################
## Arguments
##   * CA_FILE
##   * ROLE_FILE
##   * EXT_FILE
################
## return is 0|1 
################
sub newRole {

  my $class = shift; 
  my $self = { DEBUG => 0 };
  bless $self, $class;
  my $keys = { @_ };

  ## show arguments
  print "newRole: CA_FILE - $keys->{CA_FILE}<br>\n"     if ($self->{DEBUG});
  print "newRole: ROLE_FILE - $keys->{ROLE_FILE}<br>\n" if ($self->{DEBUG});
  print "newRole: EXT_FILE - $keys->{EXT_FILE}<br>\n"   if ($self->{DEBUG});
  print "newRole: start initialization<br>\n" if ($self->{DEBUG});

  my $h2 = $keys->{ROLE_FILE};
  $h2 =~ s/ /\\ /g;
 
  ## copy CA_FILE to ROLE_FILE
  my $command = "cp $keys->{CA_FILE} $h2";
  print "newRole: try to copy CA_FILE ($command)<br>\n" if ($self->{DEBUG});
  my $ret = `$command`;
  return 0 if( $? != 0 );
  print "newRole: copy CA_FILE to ROLE_FILE was successful<br>\n" if ($self->{DEBUG});

  ## for every section
  my $section;
  foreach $section (keys %{$OpenCA::OpenSSL::Configuration::MENU->{ROLE}}) {
    print "newRole: section - $section<br>\n" if ($self->{DEBUG});
    ## setSection to erase all CA-specific parameters
    OpenCA::OpenSSL::Configuration->setSection (MODE     => "ROLE", 
                                                SECTION  => $section,
                                                FILE     => $keys->{ROLE_FILE},
                                                FILETYPE => "");
  }
  
  ## touch EXT_FILE
  $h2 = $keys->{EXT_FILE};
  $h2 =~ s/ /\\ /g;
  my $ret = `touch $h2`;
  return 0 if( $? != 0 );
  print "newRole: EXT_FILE created successfully<br>\n" if ($self->{DEBUG});
  
  return 1; 
}

#######################
## private functions ##
#######################

## loadFile
####################
## $file
####################
## load the specified file
####################
sub loadFile {
  my $self = shift;
  my @keys = @_ ; 
  
  my $temp;
  my @configLines;
  
  my $fileName = $keys[0];
 
  ## protect the logic against empty extfiles
  @{$self->{cnfLines}} = ();
 
  ## load all lines
  open( FD, "$fileName" ) || return undef;
  while( $temp = <FD> ) {
    push ( @{$self->{cnfLines}}, $temp);
    print $temp if ($self->{DEBUG});
  }
  close(FD);
  
}

#####################################
## begin of parseCfg specific code ##
#####################################

## parseCfg
####################
## $section
####################
## parse the configuration
####################
sub parseCfg {
  my $self = shift;

  my $line;

  my $hline;
  my $hposition;

  my $h_item_line_begin;
  my $h_item_position_begin;
  my $h_item_line_end;
  my $h_item_position_end;

  my $h_value_line_begin;
  my $h_value_position_begin;
  my $h_value_line_end;
  my $h_value_position_end;

  my $h_section_begin = 0;
  my $h_section_end   = 0;

  my $ignore = 1;
  my $section = "";

  $ignore = 0 if ( (not $_[0]) or ($_[0] =~ /^DEFAULT$/i) );
  print "ignore: $ignore<br>\n" if ($self->{DEBUG});

  for ($line = 0; $line < scalar (@{$self->{cnfLines}}); $line++) {

    $h_section_end = $line-1;

    my $position = 0;

    ## spacer
    ($line, $position) = $self->getSpacerEnd (LINE => $line, POSITION => $position);

    ## end ? (empty line)
    $position++;
    next if ( $position >= length $self->{cnfLines}[$line] );

    ## content ?
    if ( (substr ($self->{cnfLines}[$line],$position, 1) ne "#") and
         (substr ($self->{cnfLines}[$line],$position, 1) ne "\n") ) {

      print "content\n" if ($self->{DEBUG});

      ## label ?
      if ( substr ($self->{cnfLines}[$line], $position, 1) eq "[") {

        if (not $ignore) { ## needed section complete
          ## remove the section from cnfLines
          splice @{$self->{cnfLines}}, 
                 $h_section_begin, 
                 $h_section_end - $h_section_begin;
          return 1;
        }

        print "label\n" if ($self->{DEBUG});

        $h_section_begin = $line;

        $position++;

        ## spacer
        ($line, $position) = $self->getSpacerEnd (LINE => $line, POSITION => $position);
        $position++;

        ## identifier
        ($hline, $hposition) = $self->getIdentifierEnd (LINE => $line, POSITION => $position);
        $section = $self->getItem ( BEGINLINE     => $line,
                                    BEGINPOSITION => $position,
                                    ENDLINE       => $hline,
                                    ENDPOSITION   => $hposition);
        print "section ".$section."\n" if ($self->{DEBUG});
        $position = $hposition + 1;

        ## spacer
        ($line, $position) = $self->getSpacerEnd  (LINE     => $line,
                                                   POSITION => $position);
        ## ]
        $position++; # last from blank
        $position++; # ]

        ## section which is needed
        if ($ignore and ($section =~ /^$_[0]$/i) ) {
            $ignore = 0;
        }
      
      } else {
        ## rule

        print "rule\n" if ($self->{DEBUG});

        ## identifier
        ($hline, $hposition) = $self->getIdentifierEnd (LINE => $line, 
                                                        POSITION => $position);
        $h_item_line_begin     = $line;
        $h_item_position_begin = $position;
        $h_item_line_end       = $hline;
        $h_item_position_end   = $hposition;

        $position = $hposition + 1;

        ($line, $position) = $self->getSpacerEnd  (LINE     => $line,
                                                   POSITION => $position);

        ## =
        $position++; # letzes from space
        $position++; # =

        ## spacer
        ($line, $position) = $self->getSpacerEnd  (LINE     => $line,
                                                   POSITION => $position);
        $position++;

        ## value
        ($hline, $hposition) = $self->getItemEnd (LINE => $line, 
                                                  POSITION => $position);
        $h_value_line_begin     = $line;
        $h_value_position_begin = $position;
        $h_value_line_end       = $hline;
        $h_value_position_end   = $hposition;

        $position = $hposition + 1;

        if ($line != $hline) {
          $line = $hline;
          $position = 0;
        }

        if (not $ignore) {

          my $identifier = $self->getItem ( 
            BEGINLINE     => $h_item_line_begin,
            BEGINPOSITION => $h_item_position_begin,
            ENDLINE       => $h_item_line_end,
            ENDPOSITION   => $h_item_position_end);

          print "identifier ".$identifier."\n" if ($self->{DEBUG});
        
          my $value = $self->getItem (
            BEGINLINE     => $h_value_line_begin,
            BEGINPOSITION => $h_value_position_begin,
            ENDLINE       => $h_value_line_end,
            ENDPOSITION   => $h_value_position_end);

          $value =~ s/\r\\//;
          print "value ".$value."\n" if ($self->{DEBUG});
        
          ## add the variable with value to cnfDB
          $self->{cnfDB}->{$identifier} = $value;
        }
      }
    }

    ## remove spacer

    ## rest is end or comment - I don't track anything of them
    
  }

  ## remove the section from cnfLines if section exists
  if ($section =~ /^$_[0]$/) {
    splice @{$self->{cnfLines}}, 
           $h_section_begin, 
           scalar (@{$self->{cnfLines}}) - $h_section_begin;
  }
  return 1;
}

## getSpacerEnd
####################
## LINE
## POSITION
####################
## find the end of a spacer
####################
sub getSpacerEnd {
  my $self = shift;
  my $keys = { @_ };

  my $line     = $keys->{LINE};
  my $position = $keys->{POSITION};
  
  my $spacer = 1;
  
  while ($spacer) {
    ## readline until no blank
    while ( (length $self->{cnfLines}[$line] > $position) and
            ( (substr ($self->{cnfLines}[$line],$position,1) eq " " ) or
              (substr ($self->{cnfLines}[$line],$position,1) eq "\t" ) 
            ) ) {
      $position++;
    }
    ## spacer end ?
    $spacer = 0;
    ## \\\n ?
    if ( ( substr ($self->{cnfLines}[$line], $position, 1) eq '\\') and
         ( length $self->{cnfLines}[$line] == ($position+1) ) ) {
      ## ($self->{cnfLines}[$line][$position+1] eq '\n') ) {
      $line++;
      $position = 0;
      $spacer = 1;
    }
  }
  $position--;
  return ($line, $position);
}

## getIdentifierEnd
####################
## LINE
## POSITION
####################
## find the end of an identifier
####################
sub getIdentifierEnd {
  my $self = shift;
  my $keys = { @_ };

  my $line     = $keys->{LINE};
  my $position = $keys->{POSITION};

  ## readline until # or end of line
  while ( (length $self->{cnfLines}[$line] > $position) and
          (substr ($self->{cnfLines}[$line], $position, 1) ne " ") and
          (substr ($self->{cnfLines}[$line], $position, 1) ne "\t") and
          (substr ($self->{cnfLines}[$line], $position, 1) ne "=") and
          (substr ($self->{cnfLines}[$line], $position, 1) ne "]")
        ) {
    $position++;
  }
  $position--;
  return ($line, $position);
}
        
## getItemEnd
####################
## LINE
## POSITION
####################
## find the end of a value/item
####################
sub getItemEnd {
  my $self = shift;
  my $keys = { @_ };

  my $line = $keys->{LINE};
  my $position = $keys->{POSITION};

  ## readline until # or end of line
  while ( not ( ( (substr ($self->{cnfLines}[$line], $position-1, 1) eq " ") or
                  (substr ($self->{cnfLines}[$line], $position-1, 1) eq "\t")
                ) and
                (substr ($self->{cnfLines}[$line], $position, 1) eq "#")
              ) and
          (length $self->{cnfLines}[$line] > ($position+1)) ) {
    $position++;
    if ( ( (substr ($self->{cnfLines}[$line], $position-1, 1) eq " ") or
           (substr ($self->{cnfLines}[$line], $position-1, 1) eq "\t") or
           (substr ($self->{cnfLines}[$line], $position-1, 1) eq "\r")
         ) and
         (substr ($self->{cnfLines}[$line], $position, 1) eq "\\")
       ) {
      $line++;
      $position = 0;
    }
  }
  $position--;

  ## erase following spaces
  while ( (substr ($self->{cnfLines}[$line], $position, 1) eq " ") or
          (substr ($self->{cnfLines}[$line], $position, 1) eq "\t")
        ) {
    $position--;
  }

  return ($line, $position);
}

## getItem
####################
## BEGINLINE
## BEGINPOSITION
## ENDLINE
## ENDPOSITION
####################
## get the content between the parameters
####################
sub getItem {
  my $self = shift;
  my $keys = { @_ };

  my $line     = $keys->{BEGINLINE};
  my $beginpos = $keys->{BEGINPOSITION};
  my $endpos   = $keys->{ENDPOSITION};

  my $item = "";

  while ($line <= $keys->{ENDLINE}) {

    $beginpos = 0;
    $endpos = length ($self->{cnfLines}[$line]) -1;

    $beginpos = $keys->{BEGINPOSITION} if ($line == $keys->{BEGINLINE});
    $endpos   = $keys->{ENDPOSITION}   if ($line == $keys->{ENDLINE});

    $item .= substr ($self->{cnfLines}[$line], $beginpos, $endpos-$beginpos+1);

    $line++;

  }
   
  return $item; 
}

###################################
## end of parseCfg specific code ##
###################################

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OpenCA::OpenSSL::Configuration - Perl extension to deal with openssl config files.

=head1 SYNOPSIS

use OpenCA::OpenSSL::Configuration;

=head1 DESCRIPTION

Sorry, no documentation available yet.

=head1 AUTHOR

Michael Bell <loon@openca.org>

=head1 SEE ALSO

perl(1).

=cut


#
# DNShijack
#
# This mod_perl2 script for Apache2 is the guts of informing a user that a
# particular DNS request has been blocked.  If the user wants to pretend
# that they really know what they are doing they can click on a button on
# the website to set a session cookie in their browser so that further
# requests to the site instead get passed off to a mod_proxy session.
#
# TODO:
#  * simply return 1x1 transparent pixels for images and nothing but
#    an HTTP error for other files.  So we only hijack pages where the
#    browser is expecting text/(plain|html)
#
# Alexander Clouter <alex@digriz.org.uk> - Copyright 2008
#  - released under the GNU General Public License (GPL) version 2
# 
# Sponsored by The School of Oriental and African Studies, UK
#
package DNShijack;

use strict;
use warnings;

use Apache2::RequestRec;
use Apache2::RequestUtil;
use Apache2::Connection;
use Apache2::Request;

use Apache2::Log;
use Apache2::Const -compile => qw(:common :log :http :methods :proxy);
use APR::Const     -compile => qw(SUCCESS);

use Net::DNS;
use Apache2::Cookie;
use Digest::HMAC;
use Digest::MD5;
use Template;
use I18N::AcceptLanguage;

sub trans_handler {
  my $r = shift;

  my $res = Net::DNS::Resolver->new(
  	nameservers	=> [ split(/s+/, $ENV{'dnshijackNS'}) ],
	recurse		=> 0,
  );

  my $domain = $r->hostname;
  return Apache2::Const::DECLINED
	unless (defined($domain) && $domain ne '');

  my $query = $res->query($domain, 'A');

  unless ( defined($query) ) {
    $r->log_rerror(Apache2::Log::LOG_MARK(),
      			Apache2::Const::LOG_WARNING, APR::Const::SUCCESS,
	"dnshijack: DNS lookup ('$domain') failed");
    return Apache2::Const::DECLINED;
  }

  unless ( scalar grep { $_->address eq $r->connection->local_ip } $query->answer ) {
     $r->log_rerror(Apache2::Log::LOG_MARK(),
      			Apache2::Const::LOG_WARNING, APR::Const::SUCCESS,
 	"dnshijack: DNS lookup ('$domain') does not point to us\n");
    return Apache2::Const::DECLINED;
  }

  # we set this note, to save some possible DNS lookups in a bad situation
  my $notes = $r->notes;
  $notes->add('dnshijack-domain', $domain);
  $r->notes($notes);

  my $jar = Apache2::Cookie::Jar->new($r);
  my @c_cookies = $jar->cookies("dnshijack-$ENV{'dnshijackREALM'}-bypass");
  my $c_cookie;
  if ( scalar(@c_cookies) > 0 ) {
    $c_cookie = shift @c_cookies;
  }
  # we shifted the cookies so there should be none left however if there
  # are some left then something is afoot so we die horribly :)
  if ( scalar(@c_cookies) > 0 ) {
    $r->log_rerror(Apache2::Log::LOG_MARK(),
      			Apache2::Const::LOG_WARNING, APR::Const::SUCCESS,
	"dnshijack: more than one cookie!");
    return Apache2::Const::DECLINED;
  }

  # validate the cookie if it exists
  if ( defined($c_cookie) ) {
    my ( $c_domain, $c_salt, $c_hmac_method, $c_hmac, $guff )
  		= split /:/, $c_cookie->value, 5;

    unless ( defined($c_domain) && defined($c_salt)
		&& defined($c_hmac_method) && defined($c_hmac)
		&& !defined($guff) ) {
      $r->log_rerror(Apache2::Log::LOG_MARK(),
      			Apache2::Const::LOG_WARNING, APR::Const::SUCCESS,
      	"dnshijack: borked cookie format '${\$c_cookie->value}'");
      return Apache2::Const::DECLINED;
    }

    unless ( $domain =~ /(^|\.)$c_domain$/i ) {
      $r->log_rerror(Apache2::Log::LOG_MARK(),
      			Apache2::Const::LOG_WARNING, APR::Const::SUCCESS,
	"dnshijack: (sub)domain mis-match, is '$c_domain', should be '$domain'");
      return Apache2::Const::DECLINED;
    }

    unless ( length($c_salt) == 8 && $c_salt =~ /^[.\/0-9a-z]+$/i ) {
      $r->log_rerror(Apache2::Log::LOG_MARK(),
      			Apache2::Const::LOG_WARNING, APR::Const::SUCCESS,
	"dnshijack: valid salt format '$c_salt'");
      return Apache2::Const::DECLINED;
    }

    unless ( length($c_hmac) == 22 && $c_salt =~ /^[.\/0-9a-z=+]+$/i ) {
      $r->log_rerror(Apache2::Log::LOG_MARK(),
      			Apache2::Const::LOG_WARNING, APR::Const::SUCCESS,
	"dnshijack: HMAC is not a valid format '$c_hmac'");
      return Apache2::Const::DECLINED;
    }

    unless ( $c_hmac_method eq 'md5' ) {
      $r->log_rerror(Apache2::Log::LOG_MARK(),
      			Apache2::Const::LOG_WARNING, APR::Const::SUCCESS,
	"dnshijack: Unknown HMAC Method '$c_hmac_method'");
      return Apache2::Const::DECLINED;
    }

    my $hmac = Digest::HMAC->new($ENV{'dnshijackKEY'}, 'Digest::MD5');
    $hmac->add(join(':', ( $c_domain, $c_salt, $c_hmac_method )));

    my $hmac64 = $hmac->b64digest;
    unless ( $c_hmac eq $hmac64 ) {
      $r->log_rerror(Apache2::Log::LOG_MARK(),
      			Apache2::Const::LOG_WARNING, APR::Const::SUCCESS,
	"dnshijack: incorrect HMAC, got '$c_hmac', expected '$hmac64'");
      return Apache2::Const::DECLINED;
    }

    # if we get this far, it's validated so mod_proxy the request
    $r->proxyreq(Apache2::Const::PROXYREQ_PROXY);
    $r->filename('proxy:http://' . $r->hostname . $r->uri);
    $r->handler('proxy-server');

    # trim out cookie from the outgoing proxy request
    my @cookies = grep { $_ ne "dnshijack-$ENV{'dnshijackREALM'}-bypass" } $jar->cookies;
    if ( scalar(@cookies) ) {
      foreach my $num ( 0..(scalar(@cookies)-1) ) {
        $cookies[$num] .= '=' . $jar->cookies($cookies[$num])->value;
      }

      $r->headers_in->set('Cookie', join('; ', @cookies));
    }
    else {
      $r->headers_in->unset('Cookie');
    }

    return Apache2::Const::OK;
  }

  return Apache2::Const::DECLINED;
}

sub handler {
  my $r = shift;

  if ($r->method_number == Apache2::Const::M_OPTIONS) {
    $r->allowed($r->allowed | (1<<Apache2::Const::M_GET) | (1<<Apache2::Const::M_POST));
    return Apache2::Const::DECLINED;
  }

  my $domain = $r->notes->get('dnshijack-domain');
  unless ( defined($domain) ) {
    my $rc = &bakeTemplate($r, 'not-blocked');
    return Apache2::Const::OK;
  }

  my $res = Net::DNS::Resolver->new(
  	nameservers	=> [ split(/\s+/, $ENV{'dnshijackNS'}) ],
	recurse		=> 0,
  );

  my $reason;
  # we assume the DNS lookups will succeed as so far they have
  my $query = $res->query($domain, 'TXT');
  if (defined($query) && defined(($query->answer)[0])
	&& ref(($query->answer)[0]) eq 'Net::DNS::RR::TXT') {
    my $rr = ($query->answer)[0];
    if (($rr->char_str_list)[0] =~ /^v=dbl1 : ([\w\.\-]+) : (.*)$/) {
      $domain = $1;
      $reason = $2;
    }
  }

  if ( $r->method_number == Apache2::Const::M_GET ) {
    return &splash($r, $domain, $reason);
  }
  elsif ( $r->method_number == Apache2::Const::M_POST ) {
    my $req = Apache2::Request->new($r); 

    return &splash($r, $domain, $reason)
    	unless ( defined($req->param("dnshijack-$ENV{'dnshijackREALM'}-accept-risk")) );
    
    my $hmac = Digest::HMAC->new($ENV{'dnshijackKEY'}, 'Digest::MD5');
    return &cookie($r, $domain, $hmac, 'md5');
  }
  else {
    $r->allowed($r->allowed | (1<<Apache2::Const::M_GET) | (1<<Apache2::Const::M_POST));
    return Apache2::Const::HTTP_METHOD_NOT_ALLOWED;
  }

  return Apache2::Const::SERVER_ERROR;
}

sub splash {
  my $r = shift;
  
  my $domain = shift;
  my $reason = shift;

  my $vars = {
	domain	=> $domain,
	reason	=> $reason,
  };

  my $output;
  my $rc = &bakeTemplate($r, 'main', $vars);

  return Apache2::Const::OK;
};

sub cookie {
  my $r = shift;
  my $domain = shift;
  my $hmac = shift;
  my $hmac_method = shift;
  
  my $salt = '';
  my @chars = ( '.', '/', 0..9, 'A'..'Z', 'a'..'z' );
  $salt .= $chars[int rand @chars]
  	for ( 1..8 );

  $hmac->add(join(':', ( $domain, $salt, $hmac_method )));

  my $value = join ':', ( $domain, $salt, $hmac_method, $hmac->b64digest );

  my $cookie = Apache2::Cookie->new(
			$r,
			-name	=> "dnshijack-$ENV{'dnshijackREALM'}-bypass",
			-value	=> $value,
			-domain	=> $domain,
			-path	=> '/',
  );

  $r->no_cache(1);
  $r->err_headers_out->add('Set-Cookie', $cookie->as_string);
  $r->headers_out->set('Location', $r->unparsed_uri);

  $r->log_rerror(Apache2::Log::LOG_MARK(),
			Apache2::Const::LOG_INFO, APR::Const::SUCCESS,
	"dnshijack: host accepted risk");

  return Apache2::Const::REDIRECT;
};

sub bakeTemplate {
  my $r = shift;
  my $name = shift;
  my $vars = shift || { };

  local *DIR;
  opendir DIR, $r->document_root . '/templates';
  my @langs = grep { /^[a-z-]+$/i
  			&& -d $r->document_root . "/templates/$_" }
		readdir DIR;
  closedir DIR;

  my $i18n = I18N::AcceptLanguage->new(
  	defaultLanguage	=> $ENV{'dnshijackDEFAULT_LANGUAGE'},
	strict		=> 0,
  );
  my $lang = $i18n->accepts($r->headers_in->get('Accept-Language'), \@langs);

  $vars->{'date'}		= scalar gmtime;
  $vars->{'realm'}		= $ENV{'dnshijackREALM'};
  $vars->{'contact'}{'name'}	= $ENV{'dnshijackCONTACT_NAME'};
  $vars->{'contact'}{'email'}	= $ENV{'SERVER_ADMIN'};
  # FIXME: needs escaping?
  $vars->{'uri'}		= 'http://' . $r->hostname . $r->unparsed_uri;

  my $c = $r->connection;
  $vars->{'c'}{'rip'}	= $c->remote_ip;
  $vars->{'c'}{'lip'}	= $c->local_ip;

  my $output;
  my $template = Template->new({
	INCLUDE_PATH	=> $r->document_root . '/templates'
  });
  my $rc = $template->process("$lang/$name.tml", $vars, \$output);

  $r->no_cache(1);

  if ( $rc != 1 ) {
    $r->content_type('text/plain');
    print <<EOF;
Templating error: ${\$template->error}

Please contact $ENV{'dnshijackCONTACT_NAME'} <$ENV{'SERVER_ADMIN'}>
EOF

    return 1;
  }

  $r->content_type('text/html');
  $r->content_languages([ $lang ]);

  print $output;

  return 0;
}

1;
__END__


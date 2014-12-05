# AMI LW environment configuration file

import std;
import geoip;
import basicauth;

backend radar1 {
  .host = "172.31.43.45";
  #.host = "172.31.27.32";
  .port = "80";
}

backend radar2 {
  #.host = "172.31.43.45";
  .host = "172.31.27.32";
  .port = "80";
}

director radar_balancer round-robin {
  { .backend = radar1; }
  { .backend = radar2; }
}

acl purge {
  "localhost";
  "127.0.0.1";
  "10.32.0.0"/16;
  "172.0.0.0"/8;
  "54.0.0.0"/8;
}

# Default Varnish cache policy for AMI Hosting

# Cache hit: the object was found in cache
sub vcl_hit {
if (req.request == "PURGE") {
  purge;
  error 200 "Purged.";
}
}

# Cache miss: request is about to be sent to the backend
sub vcl_miss {
# Restore the original incoming Cookie
if (req.http.X-AMI-Cookie) {
    set bereq.http.Cookie = req.http.X-AMI-Cookie;
    unset bereq.http.X-AMI-Cookie;
}
# PURGE method support
if (req.request == "PURGE") {
    error 404 "Not in cache.";
}
}

sub vcl_hash {
  # [AMI]: populate req.http.X-AMI-Layout so it can be used later
  if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|js|css|xml)$"
    || req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|js|css|xml)\?"
    || req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|js|css|xml)\@"
    || req.url ~ "ajax"
    ) {//special logic only applies to HTML pages
    set req.http.X-AMI-Layout = "l";//static resource - always assume large layout
  } else {
       call devicedetect;
       if (req.http.X-UA-Device == "pc") {
           set req.http.X-AMI-Layout = "l";
       } else if (req.http.X-UA-Device ~ "tablet") {
           set req.http.X-AMI-Layout = "m";
       } else if (req.http.X-UA-Device ~ "mobile") {
           set req.http.X-AMI-Layout = "s";
       } else {
           set req.http.X-AMI-Layout = "l";//unknown layout
       }

  }
  hash_data(req.url);

  if (req.http.host) {
    hash_data(req.http.host+"|"+req.http.X-AMI-Layout);
  } else {
    hash_data(server.ip);
  }
  return (hash);
}

sub vcl_recv {

  if (req.http.host ~ "^(www|geo\.)?starmagazine\.com") {
    error 753 "Redirect to Radar";
  }
  set req.backend = radar_balancer;

  if (req.request == "PURGE") {
    if (!client.ip ~ purge) {
     error 405 "Not allowed.";
    }
    ban("obj.http.x-url ~ " + req.url);
    ban("req.http.url ~ " + req.url);
    return(lookup);
  }

  if (req.url !~ "wp-(login|admin)" && req.url !~ "preview=true") {
        unset req.http.cookie;
  } else {
   //no caching for admin area
   return(pass);
  }

}

# Drop any cookies Wordpress tries to send back to the client.
sub vcl_fetch {
    if (!(req.url ~ "wp-(login|admin)") && req.url !~ "preview=true") {
        unset beresp.http.set-cookie;
    }
}

# Backend down: Error page returned when all backend servers are down
sub vcl_error {

  if (obj.status == 753) {
        set obj.http.Location = "http://radaronline.com";
        set obj.status = 302;
        return(deliver);
  }

  if (obj.status == 401) {
  set obj.http.Content-Type = "text/html; charset=utf-8";
  set obj.http.WWW-Authenticate = "Basic realm=Secured";
  synthetic {"

 <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
 "http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd">

 <HTML>
 <HEAD>
 <TITLE>Error</TITLE>
 <META HTTP-EQUIV='Content-Type' CONTENT='text/html;'>
 </HEAD>
 <BODY><H1>401 Unauthorized (varnish)</H1></BODY>
 </HTML>
 "};
  return (deliver);
}

  # Default Varnish error (Nginx didn't reply)
  set obj.http.Content-Type = "text/html; charset=utf-8";

  synthetic {"<?xml version="1.0" encoding="utf-8"?>
  <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
   "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
  <html>
    <head>
      <title>"} + obj.status + " " + obj.response + {"</title>
    </head>
    <body>
    <h1>This server is experiencing technical problems. Please
try again in a few moments. Thanks for your continued patience, and
we're sorry for any inconvenience this may cause.</h1>
    <p>Error "} + obj.status + " " + obj.response + {"</p>
    <p>"} + obj.response + {"</p>
      <p>XID: "} + req.xid + {"</p>
    </body>
   </html>
   "};
  return(deliver);
}


sub devicedetect {
    unset req.http.X-UA-Device;
    set req.http.X-UA-Device = "pc";

    # Handle that a cookie may override the detection alltogether.
    if (req.http.Cookie ~ "(?i)X-UA-Device-force") {
        /* ;?? means zero or one ;, non-greedy to match the first. */
        set req.http.X-UA-Device = regsub(req.http.Cookie, "(?i).*X-UA-Device-force=([^;]+);??.*", "\1");
        /* Clean up our mess in the cookie header */
        set req.http.Cookie = regsuball(req.http.Cookie, "(^|; ) *X-UA-Device-force=[^;]+;? *", "\1");
        /* If the cookie header is now empty, or just whitespace, unset it. */
        if (req.http.Cookie ~ "^ *$") { unset req.http.Cookie; }
    } else {
        if (req.http.User-Agent ~ "(?i)googlebot\-mobile") { set req.http.X-UA-Device = "mobile-bot"; }
        elsif (req.http.User-Agent ~ "(?i)(ads|google|bing|msn|yandex|baidu|ro|career|)bot" ||
            req.http.User-Agent ~ "(?i)(baidu|jike|symantec)spider" ||
            req.http.User-Agent ~ "(?i)scanner" ||
            req.http.User-Agent ~ "(?i)(web)crawler") {
            set req.http.X-UA-Device = "bot"; }
        elsif (req.http.User-Agent ~ "(?i)ipad")        { set req.http.X-UA-Device = "tablet-ipad"; }
        elsif (req.http.User-Agent ~ "(?i)ip(hone|od)") { set req.http.X-UA-Device = "mobile-iphone"; }
        /* how do we differ between an android phone and an android tablet?
           http://stackoverflow.com/questions/5341637/how-do-detect-android-tablets-in-general-useragent */
        elsif (req.http.User-Agent ~ "(?i)android.*(mobile|mini)") { set req.http.X-UA-Device = "mobile-android"; }
        // android 3/honeycomb was just about tablet-only, and any phones will probably handle a bigger page layout.
        elsif (req.http.User-Agent ~ "(?i)android 3")              { set req.http.X-UA-Device = "tablet-android"; }
        // May very well give false positives towards android tablets. Suggestions welcome.
        elsif (req.http.User-Agent ~ "(?i)android")         { set req.http.X-UA-Device = "tablet-android"; }
        elsif (req.http.User-Agent ~ "Mobile.+Firefox")     { set req.http.X-UA-Device = "mobile-firefoxos"; }
        elsif (req.http.User-Agent ~ "^HTC" ||
            req.http.User-Agent ~ "Fennec" ||
            req.http.User-Agent ~ "IEMobile" ||
            req.http.User-Agent ~ "BlackBerry" ||
            req.http.User-Agent ~ "SymbianOS.*AppleWebKit" ||
            req.http.User-Agent ~ "Opera Mobi") {
            set req.http.X-UA-Device = "mobile-smartphone";
        }
        elsif (req.http.User-Agent ~ "(?i)symbian" ||
            req.http.User-Agent ~ "(?i)^sonyericsson" ||
            req.http.User-Agent ~ "(?i)^nokia" ||
            req.http.User-Agent ~ "(?i)^samsung" ||
            req.http.User-Agent ~ "(?i)^lg" ||
            req.http.User-Agent ~ "(?i)bada" ||
            req.http.User-Agent ~ "(?i)blazer" ||
            req.http.User-Agent ~ "(?i)cellphone" ||
            req.http.User-Agent ~ "(?i)iemobile" ||
            req.http.User-Agent ~ "(?i)midp-2.0" ||
            req.http.User-Agent ~ "(?i)u990" ||
            req.http.User-Agent ~ "(?i)netfront" ||
            req.http.User-Agent ~ "(?i)opera mini" ||
            req.http.User-Agent ~ "(?i)palm" ||
            req.http.User-Agent ~ "(?i)nintendo wii" ||
            req.http.User-Agent ~ "(?i)playstation portable" ||
            req.http.User-Agent ~ "(?i)portalmmm" ||
            req.http.User-Agent ~ "(?i)proxinet" ||
            req.http.User-Agent ~ "(?i)sonyericsson" ||
            req.http.User-Agent ~ "(?i)symbian" ||
            req.http.User-Agent ~ "(?i)windows\ ?ce" ||
            req.http.User-Agent ~ "(?i)winwap" ||
            req.http.User-Agent ~ "(?i)eudoraweb" ||
            req.http.User-Agent ~ "(?i)htc" ||
            req.http.User-Agent ~ "(?i)240x320" ||
            req.http.User-Agent ~ "(?i)avantgo") {
            set req.http.X-UA-Device = "mobile-generic";
        }
    }
}
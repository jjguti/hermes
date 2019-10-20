[![Build Status](https://travis-ci.org/jjguti/hermes.svg?branch=master)](https://travis-ci.org/jjguti/hermes)

hermes is a GPL anti-spam solution that will help you get rid of (most) UCE.

It's key features are:

* Multiplatform:
  hermes runs on Linux, Solaris and even on Windows.

* Transparent:
  Although clients will connect to hermes, hermes won't display any message of
  its own or alter in any way the communications with your real mail server,
  except at the moment of greylisting.

* Efficient:
  We have gone to great lengths to make hermes as efficient as possible, both
  for your computer and for the SMTP server that it proxies.

* Configurable:
  hermes is highly configurable, from greylisting time to logging method and
  everything in between.

* Extension friendly:
  We support most SMTP extensions such as SMTP-AUTH and STARTTLS.

* Compatible:
  You can use hermes in combination with other techniques such as nolisting or
  Bayesian Filtering either on the client side or on the server side (or both
  if you prefer). You can also use fakehermes to fake a secondary smtp server
  and further reduce your spam.

#!/usr/bin/perl -w

# this small script generates the Configfile class from the
# Configfile.cpp.in and Configfile.h.in. this way when we want
# to add a new option to the config file, we just have to put it
# on Configfile.tmpl and automagically it will appear on our code
# It will also generate an example hermesrc from the same info.
# 2007-04-17 Now it also generates an html document for our webpage

my $hvar="";
my $cppvar1="",$cppvar2="",$cppvar3="",$conf_example="",$htmlvar="";

open HTMLIN, "<../docs/hermes-options.html.in";
$htmltempl=join("",<HTMLIN>);
close HTMLIN;

while(<>)
{
  chomp;
  if(! /^#/ && ! /^\t*$/ && ! /^\*/)
  {
    s/^\s+//;s/\s+$//;
    @_=split ",";
    my $camelcased=&camel_case($_[1]);
    my $type=$_[0];
    $type="list<string>" if($type =~ /list/);
    $hvar1.="$type $_[1];\n";
    $hvar2.="$type& get$camelcased();\n";
    if($type =~ /list/)
    {
      $cppvar1.="$_[1]=Configfile::parseAsList($_[2]);\n";
    }
    else
    {
      $cppvar1.="$_[1]=$_[2];\n";
    }
    $cppvar2.="PARSE_".uc($_[0])."(\"$_[1]\",$_[1])\n";
    $cppvar3.="GET_VAR(get$camelcased,$_[1],$type&)\n";
    $conf_example.="$_[1] = $_[2]\n\n";
    my $htmltemp=$htmltempl;
    $htmltemp =~ s/%type%/$_[0]/;
    $htmltemp =~ s/%name%/$_[1]/g;
    $htmltemp =~ s/%default%/$_[2]/;
    $htmltemp =~ s/%explanation%/$htmlexpl/;
    $htmlexpl="";
    $htmlvar.=$htmltemp;
  }
  else
  {
    if(/^\*clean\*$/) # clean restarts our htmlexpl contents
    {
      $htmlexpl="";
    }
    else
    {
      if(/^\*/)
      {
        s/^\*$//;
        s/^\*/#/;
        $conf_example.="$_\n";
        chomp;
        s/^#//;
        s/>/&gt;/;
        $htmlexpl.="$_\n";
      }
    }
  }
}

chomp $cppvar1;
chomp $cppvar2;
chomp $cppvar3;
chomp $hvar1;
chomp $hvar2;
chomp $conf_example;

open CPPIN, "<../src/Configfile.cpp.in";
$cppstr=join("",<CPPIN>);
close CPPIN;
open CPPOUT, ">Configfile.cpp";
$cppstr =~ s/%templ_default_values%/$cppvar1/;
$cppstr =~ s/%templ_parsevars%/$cppvar2/;
$cppstr =~ s/%templ_getmethods%/$cppvar3/;
print CPPOUT $cppstr;
close CPPOUT;

open HIN, "<../src/Configfile.h.in";
$hstr=join("",<HIN>);
close HIN;
open HOUT, ">Configfile.h";
$hstr =~ s/%templ_privateattribs%/$hvar1/;
$hstr =~ s/%templ_publicmethods%/$hvar2/;
print HOUT $hstr;
close HOUT;

open RCEX, ">../dists/hermesrc.example";
print RCEX $conf_example;
close RCEX;

open HTML, ">../docs/hermes-options.html";
print HTML $htmlvar;
close HTML;

sub camel_case()
{
  my $str=shift;
  my $outstr="";

  for($i=0;$i<length($str);$i++)
  {
    my $letter=substr($str,$i,1);
    if($letter eq "_")
    {
      $i++;
      $outstr.=uc(substr($str,$i,1));
    }
    else
    {
      $outstr.=$letter;
    }
  }
  return ucfirst($outstr);
}

#!/usr/bin/perl

# Made by Tobias Riper, 2023

use strict;
no strict 'vars';
no strict 'subs';

use Getopt::Long;
use XML::LibXML;
use Term::ANSIColor;
use Pod::Usage;


## parse the XML file

@DEFINE_flags = ();
@GCC_flags = ();

GetOptions(
  'compile-gcc-flags=s'     => \$user_input_compile_flags,
  'compile-define-flags=s'  => \$user_input_define_flags,
  'static'                  => \$static_compilation_is_enabled,
);

GetOptions('help|?' => \$help, man => \$man) or pod2usage(2);

if( $user_input_compile_flags ){
        push(@GCC_flags, $user_input_compile_flags);
}
if( $user_input_define_flags ){
        push(@DEFINE_flags, $user_input_define_flags);
}


system("clear");
print(color("cyan"));
sleep(1);

printf("██████╗ ██╗      █████╗  ██████╗██╗  ██╗███████╗██╗    ██████╗ ██╗     ██╗   ██╗ ██████╗ ██╗███╗   ██╗    ██████╗ ██╗   ██╗██╗██╗     ██████╗ ███████╗██████╗ 
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔════╝██║    ██╔══██╗██║     ██║   ██║██╔════╝ ██║████╗  ██║    ██╔══██╗██║   ██║██║██║     ██╔══██╗██╔════╝██╔══██╗
██████╔╝██║     ███████║██║     █████╔╝ █████╗  ██║    ██████╔╝██║     ██║   ██║██║  ███╗██║██╔██╗ ██║    ██████╔╝██║   ██║██║██║     ██║  ██║█████╗  ██████╔╝
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══╝  ██║    ██╔═══╝ ██║     ██║   ██║██║   ██║██║██║╚██╗██║    ██╔══██╗██║   ██║██║██║     ██║  ██║██╔══╝  ██╔══██╗
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║     ██║    ██║     ███████╗╚██████╔╝╚██████╔╝██║██║ ╚████║    ██████╔╝╚██████╔╝██║███████╗██████╔╝███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝    ╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝");


printf("\n");

sleep(1);

@GCC_flags = (  " -Wno-int-conversion ",
                " -Wno-pointer-to-int-cast ",
                " -Wl,-z,relro ",
              );

# For Cross Compilation
if( ! ( $ARGV[0] ) ){
        print color('red');
        print "actually compiling with GCC\n";
        print color('reset');
        @CC = ("gcc");
}else{
        @CC = shift;
}


print color('reset');
print color('green');
print("========================================================================================\n");
print color('reset');

system("xxd -i rtl_nic/rtl8156b-2.fw ./8156.h");
system("xxd -i rtl_nic/rtl8153b-2.fw ./8153.h");

system("tail -n +2 8153.h     | head -n -2  | sponge 8153.h");
system("tail -n +2  8156.h    | head -n -2  | sponge 8156.h");

system("@CC -DCHOOSEN_PLATFORM=1 rtl_plugin.c -lusb-1.0 -o rtl81xx -Wno-incompatible-pointer-types -finstrument-functions");
system("rm ./8153.h");
system("rm ./8156.h");


print color('reset');
print color('green');
print("========================================================================================\n");
print color('reset');

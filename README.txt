simple fuzz
by: aaron conole <apconole@yahoo.com>

synopsis
  simple fuzz is exactly what it sounds like - a simple fuzzer. don't mistake 
simple with a lack of fuzz capability. this fuzzer has two network modes of 
operation, an output mode for developing command line fuzzing scripts, as well
as taking fuzzing strings from literals and building strings from sequences.
  simple fuzz is built to fill a need - the need for a quickly configurable
black box testing utility that doesn't require intimate knowledge of the inner
workings of C or require specialized software rigs. the aim is to just provide
a simple interface, clear inputs/outputs, and reusability.

features
  simple script language for creating test cases
  support for repeating strings as well as fixed strings ('sequences' vs. 
         'literals')
  variables within test cases (ex: strings to be replaced with different 
                                   strings)
  tcp and udp payload transport (icmp support tbd)
  binary substitution support (see basic.a11 for more information)
  plugin support (NEW!) see plugin.txt for more information.
  previous packet contents inclusion

intro - the problem
  why'd i write this? i was going to use spike for black box testing at work, 
but the problem with that is - how do i get the people in SQA to be able to 
really hammer away at my stuff? they're not software engineers and in many 
cases are barely competent programmers. giving them a bulky C program, based on
SPIKE that might require heavy modification seemed like i would be setting 
myself up for maintenance nightmares, and insufficient code coverage.
  but - SPIKE is very powerful, very flexible, and VERY well known. this is 
true but has one caveat: all the power and flexibility and large penis of SPIKE
comes at the cost of a steep learning curve. it requires time to learn, and 
if/when a bug might surface, would require time delving into internals which I
don't want to be 'the guy' for at work.

intro 2 - the solution
  write my own, more simple fuzzing software. I'm not gonna pretend I know a 
whole lot about which other fuzzers exist. I saw a webpage that rattled them
off like everyone had written them. maybe they have, and I'm late to the party.
what I took away from most of the reading was this: all those fuzzers are very 
specialized. seriously. there are fuzzers which contain their own IP stacks for
testing and mapping OS behavior. i certainly don't need that.

intro 3 - so what do i have
  a pretty simple fuzzer. it is reminiscent of easy-fuzz from 2004 written by 
priest of the priestmasters. his layout for building a fuzzy test was pretty 
nice. a "script" file, with a preamble - setting some basic state and
variables, followed by the "meat and potatoes" tests. since i really liked this
approach, i sto^H^H^Hborrowed it for my own. naturally, since i wrote my code
from scratch i was able to do things i wanted without being tied to his design
decisions.

chapter 1 - using rotting fruit to make a fuzzy engine
  so - how to use. the utility takes only a few commandline options, which i'll
list here for posterity:

output modes:
  -O
    this option sets the engine to run in output mode
  -T
    this option sets the engine to run in TCP mode
  -U
    this option sets the engine to run in UDP mode

logging:
  -L filename
    this option specifies a file to write instead of the standard output
  -n
    this option will start a new log file after each fuzz attempt
  -X
    this option specifies that the fuzz outputs to the log / screen should be
    printed as a hexadecimal dump.

config file:
  -f filename
    this option specifies the fuzzing "script" - covered later.

network host:
  -e
    this option stops testing when the host fails to respond.
  -S host
    this option sets the remote host to which we will connect
  -p port
    this sets the port for the host to which we will connect.
  -t timeout
    this sets an amount of time (minimum of 100) in MILLIseconds to wait
    for a response. your best bet would be to run a sniffer (crappy one 
    included) and watch the responses that way.

variables:
  -D variable=value
    sets a fuzzing test case variable to be replaced with value. every 
    occurance of the variable will be replaced.

    note: if you set a variable 'foo' equal to 'bar' then %foo would be equal to 
    strlen('bar'). See basic.nuke.crlf for the canonical example.

misc:
  -b number
    starts fuzzing at test case 'number'

  -q
    sets "quiet" mode - output will only contain fuzzed payload (if -O is 
    specified) and the potential response.
  -v
    sets "verbose" mode - output will contain extra information
  -l
    transmit literals only.
  -s
    transmit sequences only.
  -r
    do not send a trailing newline (generally used for binary fuzzing)

help:
  -V
    shows the version information
  -h
    shows the help


chapter 2 - scraping together caterpillars
  so, now that you know how to execute the fuzzer, we need to setup a script. 
the first thing when writing the script is to understand all the 'reserved'
parts. so here are the keywords, and what they do. note: only FUZZ is case
sensitive.

___________________________________________________________________________
| keyword         |   meaning
+-----------------+--------------------------------------------------------
|  #              | when used at the start of a line, denotes a comment
+-----------------+--------------------------------------------------------
|  //             | when used at the start of a line, denotes a comment
+-----------------+--------------------------------------------------------
|  ;              | when used at the start of a line, denotes a comment
+-----------------+--------------------------------------------------------
| literal         | used to assign a string that should be inserted to a 
++++++++++++++++++| fuzzing test case "literally". ex: literal=abcd
+++++++++++++++++++--------------------------------------------------------
| sequence        | used to assign a string that should be sequence filled
+++++++++++++++++++ into a fuzzing test case. ex: sequence=A
+++++++++++++++++++--------------------------------------------------------
| seqstep         | used to set a step increment for fuzz sequences. ex:
+++++++++++++++++++ seqstep=1 with a maxseqlen=30 would create fuzz strings
+++++++++++++++++++ of size 1 - 30 for each sequence.
+-----------------+--------------------------------------------------------
| lineterm        | replaces the end of line character with the text specified
+++++++++++++++++++ ex:
+++++++++++++++++++ # the following makes every test case terminate with \r\n
+++++++++++++++++++ !CRLF=0d 0a
+++++++++++++++++++ lineterm=CRLF
+++++++++++++++++++--------------------------------------------------------
| reppol          | used to indicate which policy to use when substituting data
+++++++++++++++++++ from previous packets. Valid values are always and once.
+++++++++++++++++++ always indicates that the substitution string should be
+++++++++++++++++++ refreshed with packet data after every packet.
+++++++++++++++++++ once indicates that the substitution string should only be
+++++++++++++++++++ refreshed after the first time it is recovered.
+++++++++++++++++++--------------------------------------------------------
| reqwait         | sets the time to wait between requests in milliseconds
+-----------------+--------------------------------------------------------
| maxseqlen       | sets the maximum size that a sequence can fill
+-----------------+--------------------------------------------------------
| include         | includes a secondary config file, which must be 
+++++++++++++++++++ terminated with an endcfg line. use absolute paths.
+++++++++++++++++++--------------------------------------------------------
| endcfg          | terminates the configuration block. all blocks following
+++++++++++++++++++ will be interpreted as parts of fuzzing requests. therefore
+++++++++++++++++++ no comments are allowed to go in the testing blocks. it is
+++++++++++++++++++ probably a good idea to fill up comments at the beginning
+++++++++++++++++++ which describe all of the tests that are to be executed.
+++++++++++++++++++--------------------------------------------------------
| --              | used to denote the "end" of a block of text representing
+++++++++++++++++++ a test.
+++++++++++++++++++--------------------------------------------------------
| c-              | used to denote the "end" of a block of text representing
+++++++++++++++++++ a test. indicates that the system should keep the existing
+++++++++++++++++++ connection alive.
+++++++++++++++++++--------------------------------------------------------
| FUZZ            | used in test blocks to insert a fuzzy string. the test
+++++++++++++++++++ will be executed for each possible fuzz string that could
+++++++++++++++++++ be inserted. this means for every literal and sequence, you
+++++++++++++++++++ will get a copy of the test with all instances of FUZZ
+++++++++++++++++++ replaced.
+++++++++++++++++++--------------------------------------------------------
| %FUZZ           | used in test blocks to insert the length of the fuzz string
+++++++++++++++++++ in ascii form. IE: if the fuzz length is 4, the system will
+++++++++++++++++++ insert the ascii character "4".
+++++++++++++++++++--------------------------------------------------------
| %%FUZZ          | as above, except inserts the binary length. currently, this
+++++++++++++++++++ is done as 4byte value (or sizeof(size_t) on your platform)
+++++++++++++++++++--------------------------------------------------------
| |X=[off:len:def]| Indicates a variable whose contents derive from the 
+++++++++++++++++++ preceding packets' data. off is the offset into the 
+++++++++++++++++++ previous packet, len is the length of data, and def is
+++++++++++++++++++ a default value (usually for the first packet).
+++++++++++++++++++--------------------------------------------------------
| $X=y            | used to create a symbol, with name X and value y. this will
+++++++++++++++++++ replace each occurance of X in the fuzzing payload with y.
+++++++++++++++++++ additionally, all instances of %X would become strlen(y)
+++++++++++++++++++ ex: FUZZ X would become FUZZ y, and FUZZ %X would become
+++++++++++++++++++     FUZZ 1 (since y is 1 character).
+++++++++++++++++++--------------------------------------------------------
| $X[N]=y         | used to create an array (or block) of symbols. N represents
+++++++++++++++++++ an index into the array. This replacement happens prior to
+++++++++++++++++++ the FUZZ replacement, and will cause replacement N times
+++++++++++++++++++ for each array. 
+++++++++++++++++++--------------------------------------------------------
| !X=deadbeef     | Used to create a binary subsitution symbol. The first
+++++++++++++++++++ occurance of X within the fuzz payload will become the
+++++++++++++++++++ binary bytes defined by deadbeef. Valid formats for 
+++++++++++++++++++ specifying binary data:
+++++++++++++++++++ !X=de ad 0xbe Efca \xfe BADCab
+++++++++++++++++++--------------------------------------------------------
| !X[N]=deadbeef  | Used to create an array (or block) of binary symbols. N
+++++++++++++++++++ represents an index into the array. NOTE: the symbol size
+++++++++++++++++++ could vary here - a length limiting option is in the works
+++++++++++++++++++--------------------------------------------------------
| ++X             | Special flag for binary symbols that will attempt to
+++++++++++++++++++ increment the start value after every fuzz case. NOTE:
+++++++++++++++++++ the engine tries to be "intelligent" about incrementing,
+++++++++++++++++++ but for symbol values larger than 4 bytes, or symbols on
+++++++++++++++++++ big endian machines, there may be errors resulting.
+++++++++++++++++++--------------------------------------------------------
|-"reserved words"| The following fuzz case keywords are considered special
+++++++++++++++++++ cases and may not be used as symbols (or undefined behavior
+++++++++++++++++++ will occur:
+++++++++++++++++++ __SEQUENCE_NUM_ASCII__ - This keyword only applies to 
+++++++++++++++++++            sequences and will increment after each sequence
+++++++++++++++++++            addition where it is replaced. (ex: if you have
+++++++++++++++++++            a sequence defined as AAA__SEQUENCE_NUM_ASCII__
+++++++++++++++++++            and a max sequence length of 100, you'll get
+++++++++++++++++++            AAA0001AAA0002AAA0003... etc).
+++++++++++++++++++--------------------------------------------------------

caveat: all config files MUST end with a newline.

chapter 3 - my little fuzzer, first time out
  so, lets take the above knowledge and build a simple little fuzzing test.

==========================================================================
# begin my first fuzzing test.

# some literals to fuzz around with
literal=abcdefg
literal=hijklmn
literal=opqrstu
literal=vwxyz01
literal=2345678
literal=9.,/-()

# some sequences - these get expanded
sequence=%n
sequence=%%n
sequence=a
sequence=A
sequence=abacabb
sequence=12345678987654321

#how big to expand sequences
maxseqlen=1024

#this is going to be a simple fuzz, so just put the word FUZZ as a test
#after endcfg, then follow that with -- and a newline
endcfg
FUZZ
--
========================================================================

save the above snippet to '/tmp/myfirst.cfg'

then run:

sfuzz -O -f /tmp/myfirst.cfg

and check your output.

now modify some more. the line where you have 'FUZZ' change to

[FUZZ} this crap

save and rerun. see the difference? play around with it. add second test by
putting the following after the --

this is not a fuzz. sad face.
--

remember, newline is important at the end of the file.

chapter 4 - fuzzy wuzzy gets around
   so, now to use on network host. lets say we have a webserver running on 
foo.com and it has some etc enumeration vulnerability. we can use fuzzer to
find this out. in the above, add the following to the config portion of the 
file:

# etc enumeration
literal=./../../../etc/

# wait 200ms between requests
reqwait=200

this will cause the system to pause when doing network outputs for 200ms 
between each request. (note : the system will already pause for 100ms to wait
for data which may be returned on the socket).

now, we add a test case to the bottom:

GET /FUZZ HTTP/1.1
Hostname: foo.com

--

it is important that in this test case, we make sure those lines become 
terminated with CRLF (i didn't do that in this example). since the webserver
won't read it right without them(although, maybe that's a good fuzz test). 
anyway, to run, simply change the cmd line now to:

sfuzz -T -f /tmp/myfirst.cfg -S foo.com -p 80

and fire it off. use a network monitor to watch the traffic. there is a 
rudimentary 'test for response' in there which dumps the response to the 
screen, but it's not terribly reliable.


!!!!!!!!            SUPER LARGE DISCLAIMER          !!!!!!!!!!!!
don't use this to exploit someone's network, or be a douche. this is for 
security research use and internal testing. using this to crash someones system
without permission or "pwn sum n00bz" is pretty lame.

thats all for now

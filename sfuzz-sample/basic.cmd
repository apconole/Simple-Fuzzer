#A really basic sfuzz config for fuzzing sfuzz

include /usr/local/share/sfuzz-db/basic-fuzz-strings.list
include /usr/local/share/sfuzz-db/std-cmdline-exploits.list

endcfg
./sfuzz -f FUZZ
--
FUZZ ./sfuzz
--
./sfuzz -L FUZZ
--
./sfuzz -S FUZZ
--

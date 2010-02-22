#A really basic sfuzz config for fuzzing sfuzz

include basic-fuzz-strings.list
include std-cmdline-exploits.list

endcfg
./sfuzz -f FUZZ
--
FUZZ ./sfuzz
--
./sfuzz -L FUZZ
--
./sfuzz -S FUZZ
--

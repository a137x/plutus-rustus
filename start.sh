
#!/bin/bash
# run plutus-rustus in background
#
# to run it: bash start.sh & disown
#
exec ./target/release/plutus-rustus
echo plutus-rustus started...
```bash

#### KEYGEN
DEGREE=8 LOOKUP_BITS=8 cargo run --release \
        --example pre_block \
        -- --name pre_block \
        -k 10 --input pre_block.in \
        keygen

#### PROOF
DEGREE=8 LOOKUP_BITS=8 cargo run --release \
	--example pre_block \
	-- --name pre_block \
	-k 10 \
	prove

#### VERIFY
DEGREE=8 LOOKUP_BITS=8 cargo run \
	--example pre_block \
	-- --name pre_block \
	-k 10 \
	verify

```

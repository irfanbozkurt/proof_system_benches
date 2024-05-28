```bash

#### KEYGEN
LOOKUP_BITS=8 cargo run --release \
        --example pre_block \
        -- --name pre_block \
        -k 10 --input pre_block.in \
        keygen

#### PROOF
LOOKUP_BITS=8 cargo run --release \
	--example pre_block \
	-- --name pre_block \
	-k 10 \
	prove

#### VERIFY
LOOKUP_BITS=8 cargo run \
	--example pre_block \
	-- --name pre_block \
	-k 10 \
	verify

```

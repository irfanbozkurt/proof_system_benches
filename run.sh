
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
echo "@@@@@@@@@@@@@@@@@@@@@  1 - Pre-block benchmarks  @@@@@@@@@@@@@@@@@@@@@";
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
echo "";
echo "";

# gnark_bench
cd gnark_bench;
go run pre_block.go 0;
echo "";
echo "";
cd ..;

# halo2_bn254_bench
cd halo2_bn254_bench;
echo "Setting up pkey and vkey for halo2";
LOOKUP_BITS=8 cargo run --release \
        --example pre_block \
        -- --name pre_block \
        -k 10 --input pre_block.in \
        keygen;

echo "Proving";
LOOKUP_BITS=8 cargo run --release \
	--example pre_block \
	-- --name pre_block \
	-k 10 \
	prove;
echo "Verifying";
LOOKUP_BITS=8 cargo run \
	--example pre_block \
	-- --name pre_block \
	-k 10 \
	verify
cd ..;
echo "";
echo "";

# plonky2 bench
cd plonky2_bench;
RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example pre_block;
cd ..;
echo "";
echo "";

# gnark_bench
cd gnark_bench;
go run . 2;
echo "";
echo "";
cd ..;

# # halo2_bn254_bench
# cd halo2_bn254_bench;
# echo "Setting up pkey and vkey for halo2";
# RAYON_NUM_THREADS=16 LOOKUP_BITS=16 cargo run --release \
# 		--example verify_block \
# 		-- --name verify_block \
# 		-k 17 --input verify_block.in \
# 		keygen;

# echo "Proving";
# RAYON_NUM_THREADS=16 LOOKUP_BITS=16 cargo run --release \
# 		--example verify_block \
# 		-- --name verify_block \
# 		-k 17 prove;

# echo "Verifying";
# RAYON_NUM_THREADS=16 LOOKUP_BITS=16 cargo run --release \
# 		--example verify_block \
# 		-- --name verify_block \
# 		-k 17 verify;
# cd ..;
# echo "";
# echo "";

# # plonky2 bench
# cd plonky2_bench;
# RUSTFLAGS=-Ctarget-cpu=native cargo run --release --example verify_block;
# cd ..;
# echo "";
# echo "";


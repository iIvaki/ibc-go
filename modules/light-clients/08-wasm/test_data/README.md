# How to regenerate grandpa test data

This is a general outline of the process and the actions to take are dependent on the changes that were implemented. The changes could be from any of the following: ibc-go, hyperspace, parachain, polkadot, grandpa light client contract, heighliner, or interchaintest.

1. Make your code changes
2. Build local docker images for the e2e test with all modifications
	1. ibc-go-simd (from local repo)
		1. heighliner build -c ibc-go-simd -g local --local
	2. hyperspace
		1. Repo: ComposableFi/centauri
		2. PR: gh pr checkout 388
		3. Build local Hyperspace docker from centauri repo:
		4. amd64: "docker build -f scripts/hyperspace.Dockerfile -t hyperspace:local ."
		5. arm64: "docker build -f scripts/hyperspace.aarch64.Dockerfile -t hyperspace:local --platform=linux/arm64/v8 .
	3. parachain
		1. Repo: ComposableFi/centauri
		2. PR: gh pr checkout 388
		3. Build local parachain docker from centauri repo:
		4. ./scripts/build-parachain-node-docker.sh (you can change the script to compile for ARM arch if needed)
	4. polkadot
		1. Repo: paritytech/polkadot
		2. Branch: release-v0.9.39
		3. Commit: dc25abc712e42b9b51d87ad1168e453a42b5f0bc
		4. Build local polkadot docker from  polkadot repo
		5. amd64: docker build -f scripts/ci/dockerfiles/polkadot/polkadot_builder.Dockerfile . -t polkadot-node:local
		6. arm64: docker build --platform linux/arm64 -f scripts/ci/dockerfiles/polkadot/polkadot_builder.aarch64.Dockerfile . -t polkadot-node:local
3. If needed, build new ics10_grandpa_cw.wasm and place in examples/polkadot of interchaintest
	1. RUSTFLAGS='-C link-arg=-s' cargo build -p ics10-grandpa-cw --target=wasm32-unknown-unknown --release --lib
4. Run hyperspace interchaintest (main branch)
  1.From the hyperspace_test.go file, make sure the version/tags of ibc-go-simd, hyperspace, parachain, and polkadot match what you used. They are currently set to the defaults.
  2.go test -v -timeout 20m -run ^TestHyperspace$ examples/hyperspace/hyperspace_test.go -count=1
5. Test should pass, if not, it needs to be fixed
6. The genesis.json test_data file will be generated on a successful run and needs to be replaced. The new file will be located at examples/hyperspace/exported_state.json. The exported state is not taken from the latest height, but from a height before the last few update clients. We will use those update clients that aren't included in data.json.
7. Open a SQLite brower with ~/.interchaintest/databases/block.db, execute: "SELECT test_case_name, chain_id, block_height, msg_n, type, raw FROM v_cosmos_messages WHERE test_case_id=(SELECT MAX(id) from test_case);". You will pull various base64 encoded strings from these messages along with other data like heights the message/states are associated with.
8. Populate data.json and update test cases, for example:
	1. TestVerifyMembershipGrandpa
		1. successful ClientState verification
			1. client_state_proof is pulled from MsgConnectionOpenAck message
			2. if necessary, update baseline test's delayTimePeriod, delayBlockPeriod, proofHeight, LatestHeight of ClientState
		2. successful Connection verification
			1. connection_proof_try is pulled from MsgConnectionOpenAck message
			2. if necessary, update test case's proof height and delay period
		3. successful Channel verification
			1. channel_proof_try is pulled from MsgChannelOpenAck message
			2. if necessary, update proof height
		4. successful PacketCommitment verification
			1. packet_commitment_date and packet_commitment_proof is pulled from the first MsgRecvPacket message
			2. if necessary, update proof height and sequence #
		5. successful Acknowledgement verification
			1. ack_data, ack_proof, and ack are 
			2. if necessary, update
	2. TestInitializeGrandpa
		1. client_state_data and consensus_state_data is pulled from MsgCreateClient message
	3. TestStatusGrandpa
		1. Delete consensus state 36 from genesis.json if it is there. Hopefully, no other tests require it either...
	4. TestVerifyHeaderGrandpa
		1. header is pulled from the MsgUpdateClient immediately after the exported state height
Then, run the grandpa-specific tests and debug from there!
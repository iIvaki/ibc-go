package types_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	transfertypes "github.com/cosmos/ibc-go/v9/modules/apps/transfer/types"
	"github.com/cosmos/ibc-go/v9/modules/core/04-channel/v2/types"
)

func TestCommitPacket(t *testing.T) {
	transferData, err := json.Marshal(transfertypes.FungibleTokenPacketData{
		Denom:    "uatom",
		Amount:   "1000000",
		Sender:   "sender",
		Receiver: "receiver",
		Memo:     "memo",
	})
	require.NoError(t, err)
	packet := types.Packet{
		Sequence:           1,
		SourceChannel:      "channel-0",
		DestinationChannel: "channel-1",
		TimeoutTimestamp:   100,
		Payloads: []types.Payload{
			{
				SourcePort:      transfertypes.PortID,
				DestinationPort: transfertypes.PortID,
				Version:         transfertypes.V1,
				Encoding:        "application/json",
				Value:           transferData,
			},
		},
	}

	payloadHash := types.HashPayload(packet.Payloads[0])
	require.Equal(t, "5a405608ab85eacdd3f6ad429a5d7cbcc0349055f57708311ece1983dd993307", hex.EncodeToString(payloadHash))

	commitment := types.CommitPacket(packet)
	require.Equal(t, "450194f2ce25b12487f65593e106d91367a1e5c90b2efc03ed78265a54cfcebe", hex.EncodeToString(commitment))

	require.Len(t, commitment, 32)
}

func TestCommitAcknowledgement(t *testing.T) {
	ack := types.Acknowledgement{
		AcknowledgementResults: []types.AcknowledgementResult{
			{
				AppName: "doesntmatter",
				RecvPacketResult: types.RecvPacketResult{
					Status:          0, // doesnt matter
					Acknowledgement: []byte("some bytes"),
				},
			},
		},
	}
	commitment := types.CommitAcknowledgement(ack)
	require.Equal(t, "f03b4667413e56aaf086663267913e525c442b56fa1af4fa3f3dab9f37044c5b", hex.EncodeToString(commitment))
}

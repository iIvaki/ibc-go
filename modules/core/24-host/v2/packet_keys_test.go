package v2_test

import (
	"encoding/hex"
	"testing"

	v2 "github.com/cosmos/ibc-go/v9/modules/core/24-host/v2"
	"github.com/stretchr/testify/require"
)

func TestPacketCommitmentKey(t *testing.T) {
	actual := hex.EncodeToString(v2.PacketCommitmentKey("channel-0", 1))
	require.Equal(t, "6368616e6e656c2d30010000000000000001", actual)
}

func TestPacketReceiptKey(t *testing.T) {
	actual := hex.EncodeToString(v2.PacketReceiptKey("channel-0", 1))
	require.Equal(t, "6368616e6e656c2d30020000000000000001", actual)
}

func TestPacketAcknowledgementKey(t *testing.T) {
	actual := hex.EncodeToString(v2.PacketAcknowledgementKey("channel-0", 1))
	require.Equal(t, "6368616e6e656c2d30030000000000000001", actual)
}

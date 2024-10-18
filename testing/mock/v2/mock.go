package mock

import (
	channeltypesv2 "github.com/cosmos/ibc-go/v9/modules/core/04-channel/v2/types"
	mockv1 "github.com/cosmos/ibc-go/v9/testing/mock"
)

const (
	ModuleName = "mockv2"
)

var (
	MockRecvPacketResult = channeltypesv2.RecvPacketResult{
		Status:          channeltypesv2.PacketStatus_Success,
		Acknowledgement: mockv1.MockAcknowledgement.Acknowledgement(),
	}
	MockFailRecvPacketResult = channeltypesv2.RecvPacketResult{
		Status:          channeltypesv2.PacketStatus_Success,
		Acknowledgement: mockv1.MockFailAcknowledgement.Acknowledgement(),
	}
)

func NewMockPacketData(sourcePort, destPort string) channeltypesv2.PacketData {
	return channeltypesv2.PacketData{
		SourcePort:      sourcePort,
		DestinationPort: destPort,
		Payload: channeltypesv2.Payload{
			Encoding: "json",
			Value:    mockv1.MockPacketData,
			Version:  mockv1.Version,
		},
	}
}
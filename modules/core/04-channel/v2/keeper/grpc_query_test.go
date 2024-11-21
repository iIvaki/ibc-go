package keeper_test

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cosmos/cosmos-sdk/types/query"

	"github.com/cosmos/ibc-go/v9/modules/core/04-channel/v2/keeper"
	"github.com/cosmos/ibc-go/v9/modules/core/04-channel/v2/types"
	commitmenttypes "github.com/cosmos/ibc-go/v9/modules/core/23-commitment/types"
	ibctesting "github.com/cosmos/ibc-go/v9/testing"
)

func (suite *KeeperTestSuite) TestQueryChannel() {
	var (
		req        *types.QueryChannelRequest
		expChannel types.Channel
	)

	testCases := []struct {
		msg      string
		malleate func()
		expError error
	}{
		{
			"success",
			func() {
				ctx := suite.chainA.GetContext()
				suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetChannel(ctx, ibctesting.FirstChannelID, expChannel)

				req = &types.QueryChannelRequest{
					ChannelId: ibctesting.FirstChannelID,
				}
			},
			nil,
		},
		{
			"req is nil",
			func() {
				req = nil
			},
			status.Error(codes.InvalidArgument, "empty request"),
		},
		{
			"invalid channelID",
			func() {
				req = &types.QueryChannelRequest{}
			},
			status.Error(codes.InvalidArgument, "identifier cannot be blank: invalid identifier"),
		},
		{
			"channel not found",
			func() {
				req = &types.QueryChannelRequest{
					ChannelId: ibctesting.FirstChannelID,
				}
			},
			status.Error(codes.NotFound, fmt.Sprintf("channel-id: %s: channel not found", ibctesting.FirstChannelID)),
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			merklePathPrefix := commitmenttypes.NewMerklePath([]byte("prefix"))
			expChannel = types.Channel{ClientId: ibctesting.SecondClientID, CounterpartyChannelId: ibctesting.SecondChannelID, MerklePathPrefix: merklePathPrefix}

			tc.malleate()

			queryServer := keeper.NewQueryServer(suite.chainA.GetSimApp().IBCKeeper.ChannelKeeperV2)
			res, err := queryServer.Channel(suite.chainA.GetContext(), req)

			expPass := tc.expError == nil
			if expPass {
				suite.Require().NoError(err)
				suite.Require().NotNil(res)
				suite.Require().Equal(expChannel, res.Channel)
			} else {
				suite.Require().ErrorIs(err, tc.expError)
				suite.Require().Nil(res)
			}
		})
	}
}

func (suite *KeeperTestSuite) TestQueryPacketCommitment() {
	var (
		expCommitment []byte
		path          *ibctesting.Path
		req           *types.QueryPacketCommitmentRequest
	)

	testCases := []struct {
		msg      string
		malleate func()
		expError error
	}{
		{
			"success",
			func() {
				path = ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				expCommitment = []byte("commitmentHash")
				suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetPacketCommitment(suite.chainA.GetContext(), path.EndpointA.ChannelID, 1, expCommitment)

				req = &types.QueryPacketCommitmentRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequence:  1,
				}
			},
			nil,
		},
		{
			"empty request",
			func() {
				req = nil
			},
			status.Error(codes.InvalidArgument, "empty request"),
		},
		{
			"invalid channel ID",
			func() {
				req = &types.QueryPacketCommitmentRequest{
					ChannelId: "",
					Sequence:  1,
				}
			},
			status.Error(codes.InvalidArgument, "identifier cannot be blank: invalid identifier"),
		},
		{
			"invalid sequence",
			func() {
				req = &types.QueryPacketCommitmentRequest{
					ChannelId: ibctesting.FirstChannelID,
					Sequence:  0,
				}
			},
			status.Error(codes.InvalidArgument, "packet sequence cannot be 0"),
		},
		{
			"channel not found",
			func() {
				req = &types.QueryPacketCommitmentRequest{
					ChannelId: "channel-141",
					Sequence:  1,
				}
			},
			status.Error(codes.NotFound, fmt.Sprintf("%s: channel not found", "channel-141")),
		},
		{
			"commitment not found",
			func() {
				path := ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				req = &types.QueryPacketCommitmentRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequence:  1,
				}
			},
			status.Error(codes.NotFound, "packet commitment hash not found"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			tc.malleate()

			queryServer := keeper.NewQueryServer(suite.chainA.GetSimApp().IBCKeeper.ChannelKeeperV2)
			res, err := queryServer.PacketCommitment(suite.chainA.GetContext(), req)

			expPass := tc.expError == nil
			if expPass {
				suite.Require().NoError(err)
				suite.Require().NotNil(res)
				suite.Require().Equal(expCommitment, res.Commitment)
			} else {
				suite.Require().ErrorIs(err, tc.expError)
				suite.Require().Nil(res)
			}
		})
	}
}

func (suite *KeeperTestSuite) TestQueryPacketCommitments() {
	var (
		req            *types.QueryPacketCommitmentsRequest
		expCommitments = []*types.PacketState{}
	)

	testCases := []struct {
		msg      string
		malleate func()
		expError error
	}{
		{
			"success",
			func() {
				path := ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				expCommitments = make([]*types.PacketState, 0, 10) // reset expected commitments
				for i := uint64(1); i <= 10; i++ {
					pktStateCommitment := types.NewPacketState(path.EndpointA.ChannelID, i, []byte(fmt.Sprintf("hash_%d", i)))
					suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetPacketCommitment(suite.chainA.GetContext(), pktStateCommitment.ChannelId, pktStateCommitment.Sequence, pktStateCommitment.Data)
					expCommitments = append(expCommitments, &pktStateCommitment)
				}

				req = &types.QueryPacketCommitmentsRequest{
					ChannelId: path.EndpointA.ChannelID,
					Pagination: &query.PageRequest{
						Key:        nil,
						Limit:      11,
						CountTotal: true,
					},
				}
			},
			nil,
		},
		{
			"success: with pagination",
			func() {
				path := ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				expCommitments = make([]*types.PacketState, 0, 10) // reset expected commitments
				for i := uint64(1); i <= 10; i++ {
					pktStateCommitment := types.NewPacketState(path.EndpointA.ChannelID, i, []byte(fmt.Sprintf("hash_%d", i)))
					suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetPacketCommitment(suite.chainA.GetContext(), pktStateCommitment.ChannelId, pktStateCommitment.Sequence, pktStateCommitment.Data)
					expCommitments = append(expCommitments, &pktStateCommitment)
				}

				limit := uint64(5)
				expCommitments = expCommitments[:limit]

				req = &types.QueryPacketCommitmentsRequest{
					ChannelId: path.EndpointA.ChannelID,
					Pagination: &query.PageRequest{
						Key:        nil,
						Limit:      limit,
						CountTotal: true,
					},
				}
			},
			nil,
		},
		{
			"empty request",
			func() {
				req = nil
			},
			status.Error(codes.InvalidArgument, "empty request"),
		},
		{
			"invalid channel ID",
			func() {
				req = &types.QueryPacketCommitmentsRequest{
					ChannelId: "",
				}
			},
			status.Error(codes.InvalidArgument, "identifier cannot be blank: invalid identifier"),
		},
		{
			"channel not found",
			func() {
				req = &types.QueryPacketCommitmentsRequest{
					ChannelId: "channel-141",
				}
			},
			status.Error(codes.NotFound, fmt.Sprintf("%s: channel not found", "channel-141")),
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			tc.malleate()
			ctx := suite.chainA.GetContext()

			queryServer := keeper.NewQueryServer(suite.chainA.GetSimApp().IBCKeeper.ChannelKeeperV2)
			res, err := queryServer.PacketCommitments(ctx, req)

			expPass := tc.expError == nil
			if expPass {
				suite.Require().NoError(err)
				suite.Require().NotNil(res)
				suite.Require().Equal(expCommitments, res.Commitments)
			} else {
				suite.Require().Error(err)
			}
		})
	}
}

func (suite *KeeperTestSuite) TestQueryPacketAcknowledgement() {
	var (
		expAcknowledgement []byte
		path               *ibctesting.Path
		req                *types.QueryPacketAcknowledgementRequest
	)

	testCases := []struct {
		msg      string
		malleate func()
		expError error
	}{
		{
			"success",
			func() {
				path = ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				expAcknowledgement = []byte("acknowledgementHash")
				suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetPacketAcknowledgement(suite.chainA.GetContext(), path.EndpointA.ChannelID, 1, expAcknowledgement)

				req = &types.QueryPacketAcknowledgementRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequence:  1,
				}
			},
			nil,
		},
		{
			"empty request",
			func() {
				req = nil
			},
			status.Error(codes.InvalidArgument, "empty request"),
		},
		{
			"invalid channel ID",
			func() {
				req = &types.QueryPacketAcknowledgementRequest{
					ChannelId: "",
					Sequence:  1,
				}
			},
			status.Error(codes.InvalidArgument, "identifier cannot be blank: invalid identifier"),
		},
		{
			"invalid sequence",
			func() {
				req = &types.QueryPacketAcknowledgementRequest{
					ChannelId: ibctesting.FirstChannelID,
					Sequence:  0,
				}
			},
			status.Error(codes.InvalidArgument, "packet sequence cannot be 0"),
		},
		{
			"channel not found",
			func() {
				req = &types.QueryPacketAcknowledgementRequest{
					ChannelId: "channel-141",
					Sequence:  1,
				}
			},
			status.Error(codes.NotFound, fmt.Sprintf("%s: channel not found", "channel-141")),
		},
		{
			"acknowledgement not found",
			func() {
				path := ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				req = &types.QueryPacketAcknowledgementRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequence:  1,
				}
			},
			status.Error(codes.NotFound, "packet acknowledgement hash not found"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			tc.malleate()

			queryServer := keeper.NewQueryServer(suite.chainA.GetSimApp().IBCKeeper.ChannelKeeperV2)
			res, err := queryServer.PacketAcknowledgement(suite.chainA.GetContext(), req)

			expPass := tc.expError == nil
			if expPass {
				suite.Require().NoError(err)
				suite.Require().NotNil(res)
				suite.Require().Equal(expAcknowledgement, res.Acknowledgement)
			} else {
				suite.Require().ErrorIs(err, tc.expError)
				suite.Require().Nil(res)
			}
		})
	}
}

func (suite *KeeperTestSuite) TestQueryPacketReceipt() {
	var (
		expReceipt bool
		path       *ibctesting.Path
		req        *types.QueryPacketReceiptRequest
	)

	testCases := []struct {
		msg      string
		malleate func()
		expError error
	}{
		{
			"success with receipt",
			func() {
				path = ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetPacketReceipt(suite.chainA.GetContext(), path.EndpointA.ChannelID, 1)

				expReceipt = true
				req = &types.QueryPacketReceiptRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequence:  1,
				}
			},
			nil,
		},
		{
			"success with no receipt",
			func() {
				path = ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				expReceipt = false
				req = &types.QueryPacketReceiptRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequence:  1,
				}
			},
			nil,
		},
		{
			"empty request",
			func() {
				req = nil
			},
			status.Error(codes.InvalidArgument, "empty request"),
		},
		{
			"invalid channel ID",
			func() {
				req = &types.QueryPacketReceiptRequest{
					ChannelId: "",
					Sequence:  1,
				}
			},
			status.Error(codes.InvalidArgument, "identifier cannot be blank: invalid identifier"),
		},
		{
			"invalid sequence",
			func() {
				req = &types.QueryPacketReceiptRequest{
					ChannelId: ibctesting.FirstChannelID,
					Sequence:  0,
				}
			},
			status.Error(codes.InvalidArgument, "packet sequence cannot be 0"),
		},
		{
			"channel not found",
			func() {
				req = &types.QueryPacketReceiptRequest{
					ChannelId: "channel-141",
					Sequence:  1,
				}
			},
			status.Error(codes.NotFound, fmt.Sprintf("%s: channel not found", "channel-141")),
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			tc.malleate()

			queryServer := keeper.NewQueryServer(suite.chainA.GetSimApp().IBCKeeper.ChannelKeeperV2)
			res, err := queryServer.PacketReceipt(suite.chainA.GetContext(), req)

			expPass := tc.expError == nil
			if expPass {
				suite.Require().NoError(err)
				suite.Require().NotNil(res)
				suite.Require().Equal(expReceipt, res.Received)
			} else {
				suite.Require().ErrorIs(err, tc.expError)
				suite.Require().Nil(res)
			}
		})
	}
}

func (suite *KeeperTestSuite) TestQueryNextSequenceSend() {
	var (
		req    *types.QueryNextSequenceSendRequest
		expSeq uint64
	)

	testCases := []struct {
		msg      string
		malleate func()
		expError error
	}{
		{
			"success",
			func() {
				path := ibctesting.NewPath(suite.chainA, suite.chainB)
				path.Setup()

				expSeq = 42
				seq := uint64(42)
				suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetNextSequenceSend(suite.chainA.GetContext(), path.EndpointA.ChannelID, seq)
				req = types.NewQueryNextSequenceSendRequest(path.EndpointA.ChannelID)
			},
			nil,
		},
		{
			"req is nil",
			func() {
				req = nil
			},
			status.Error(codes.InvalidArgument, "empty request"),
		},
		{
			"invalid channel ID",
			func() {
				req = types.NewQueryNextSequenceSendRequest("")
			},
			status.Error(codes.InvalidArgument, "identifier cannot be blank: invalid identifier"),
		},
		{
			"sequence send not found",
			func() {
				req = types.NewQueryNextSequenceSendRequest(ibctesting.FirstChannelID)
			},
			status.Error(codes.NotFound, fmt.Sprintf("channel-id %s: sequence send not found", ibctesting.FirstChannelID)),
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			tc.malleate()
			ctx := suite.chainA.GetContext()

			queryServer := keeper.NewQueryServer(suite.chainA.App.GetIBCKeeper().ChannelKeeperV2)
			res, err := queryServer.NextSequenceSend(ctx, req)

			expPass := tc.expError == nil
			if expPass {
				suite.Require().NoError(err)
				suite.Require().NotNil(res)
				suite.Require().Equal(expSeq, res.NextSequenceSend)
			} else {
				suite.Require().ErrorIs(err, tc.expError)
				suite.Require().Nil(res)
			}
		})
	}
}

func (suite *KeeperTestSuite) TestQueryUnreceivedPackets() {
	var (
		expSeq []uint64
		path   *ibctesting.Path
		req    *types.QueryUnreceivedPacketsRequest
	)

	testCases := []struct {
		msg      string
		malleate func()
		expError error
	}{
		{
			"empty request",
			func() {
				req = nil
			},
			status.Error(codes.InvalidArgument, "empty request"),
		},
		{
			"invalid channel ID",
			func() {
				req = &types.QueryUnreceivedPacketsRequest{
					ChannelId: "",
				}
			},
			status.Error(codes.InvalidArgument, "identifier cannot be blank: invalid identifier"),
		},
		{
			"invalid seq",
			func() {
				path := ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				req = &types.QueryUnreceivedPacketsRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequences: []uint64{0},
				}
			},
			status.Error(codes.InvalidArgument, "packet sequence 0 cannot be 0"),
		},
		{
			"channel not found",
			func() {
				req = &types.QueryUnreceivedPacketsRequest{
					ChannelId: "invalid-channel-id",
				}
			},
			status.Error(codes.NotFound, fmt.Sprintf("%s: channel not found", "invalid-channel-id")),
		},
		{
			"basic success empty packet commitments",
			func() {
				path = ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				expSeq = []uint64(nil)
				req = &types.QueryUnreceivedPacketsRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequences: []uint64{},
				}
			},
			nil,
		},
		{
			"basic success unreceived packet commitments",
			func() {
				path = ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				// no ack exists

				expSeq = []uint64{1}
				req = &types.QueryUnreceivedPacketsRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequences: []uint64{1},
				}
			},
			nil,
		},
		{
			"basic success unreceived packet commitments, nothing to relay",
			func() {
				path = ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()

				suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetPacketReceipt(suite.chainA.GetContext(), path.EndpointA.ChannelID, 1)

				expSeq = []uint64(nil)
				req = &types.QueryUnreceivedPacketsRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequences: []uint64{1},
				}
			},
			nil,
		},
		{
			"success multiple unreceived packet commitments",
			func() {
				path = ibctesting.NewPath(suite.chainA, suite.chainB)
				path.SetupV2()
				expSeq = []uint64(nil) // reset
				packetCommitments := []uint64{}

				// set packet receipt for every other sequence
				for seq := uint64(1); seq < 10; seq++ {
					packetCommitments = append(packetCommitments, seq)

					if seq%2 == 0 {
						suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetPacketReceipt(suite.chainA.GetContext(), path.EndpointA.ChannelID, seq)
					} else {
						expSeq = append(expSeq, seq)
					}
				}

				req = &types.QueryUnreceivedPacketsRequest{
					ChannelId: path.EndpointA.ChannelID,
					Sequences: packetCommitments,
				}
			},
			nil,
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset

			tc.malleate()
			ctx := suite.chainA.GetContext()

			queryServer := keeper.NewQueryServer(suite.chainA.App.GetIBCKeeper().ChannelKeeperV2)
			res, err := queryServer.UnreceivedPackets(ctx, req)

			expPass := tc.expError == nil
			if expPass {
				suite.Require().NoError(err)
				suite.Require().NotNil(res)
				suite.Require().Equal(expSeq, res.Sequences)
			} else {
				suite.Require().ErrorIs(err, tc.expError)
				suite.Require().Error(err)
			}
		})
	}
}

func (suite *KeeperTestSuite) TestQueryUnreceivedAcks() {
	var (
		path   *ibctesting.Path
		req    *types.QueryUnreceivedAcksRequest
		expSeq = []uint64{}
	)

	testCases := []struct {
		msg      string
		malleate func()
		expError error
	}{
		{
			"success",
			func() {
				expSeq = []uint64(nil)
				req = &types.QueryUnreceivedAcksRequest{
					ChannelId:          path.EndpointA.ChannelID,
					PacketAckSequences: []uint64{1},
				}
			},
			nil,
		},
		{
			"success: single unreceived packet ack",
			func() {
				suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetPacketCommitment(suite.chainA.GetContext(), path.EndpointA.ChannelID, 1, []byte("commitment"))

				expSeq = []uint64{1}
				req = &types.QueryUnreceivedAcksRequest{
					ChannelId:          path.EndpointA.ChannelID,
					PacketAckSequences: []uint64{1},
				}
			},
			nil,
		},
		{
			"success: multiple unreceived packet acknowledgements",
			func() {
				expSeq = []uint64{} // reset
				packetAcks := []uint64{}

				// set packet commitment for every other sequence
				for seq := uint64(1); seq < 10; seq++ {
					packetAcks = append(packetAcks, seq)

					if seq%2 == 0 {
						suite.chainA.App.GetIBCKeeper().ChannelKeeperV2.SetPacketCommitment(suite.chainA.GetContext(), path.EndpointA.ChannelID, seq, []byte("commitement"))
						expSeq = append(expSeq, seq)
					}
				}

				req = &types.QueryUnreceivedAcksRequest{
					ChannelId:          path.EndpointA.ChannelID,
					PacketAckSequences: packetAcks,
				}
			},
			nil,
		},
		{
			"empty request",
			func() {
				req = nil
			},
			status.Error(codes.InvalidArgument, "empty request"),
		},
		{
			"invalid channel ID",
			func() {
				req = &types.QueryUnreceivedAcksRequest{
					ChannelId: "",
				}
			},
			status.Error(codes.InvalidArgument, "identifier cannot be blank: invalid identifier"),
		},
		{
			"channel not found",
			func() {
				req = &types.QueryUnreceivedAcksRequest{
					ChannelId: "test-channel-id",
				}
			},
			status.Error(codes.NotFound, fmt.Sprintf("%s: channel not found", "test-channel-id")),
		},
		{
			"invalid seq",
			func() {
				req = &types.QueryUnreceivedAcksRequest{
					ChannelId:          path.EndpointA.ChannelID,
					PacketAckSequences: []uint64{0},
				}
			},
			status.Error(codes.InvalidArgument, "packet sequence cannot be 0"),
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(fmt.Sprintf("Case %s", tc.msg), func() {
			suite.SetupTest() // reset
			path = ibctesting.NewPath(suite.chainA, suite.chainB)
			path.SetupV2()

			tc.malleate()
			ctx := suite.chainA.GetContext()

			queryServer := keeper.NewQueryServer(suite.chainA.App.GetIBCKeeper().ChannelKeeperV2)
			res, err := queryServer.UnreceivedAcks(ctx, req)

			expPass := tc.expError == nil
			if expPass {
				suite.Require().NoError(err)
				suite.Require().NotNil(res)
				suite.Require().Equal(expSeq, res.Sequences)
			} else {
				suite.Require().ErrorIs(err, tc.expError)
				suite.Require().Nil(res)
			}
		})
	}
}
package types_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	wasmtesting "github.com/cosmos/ibc-go/modules/light-clients/08-wasm/testing"
	"github.com/cosmos/ibc-go/modules/light-clients/08-wasm/types"
	ibcerrors "github.com/cosmos/ibc-go/v8/modules/core/errors"
	ibctesting "github.com/cosmos/ibc-go/v8/testing"
)

func TestMsgStoreCodeValidateBasic(t *testing.T) {
	signer := sdk.AccAddress(ibctesting.TestAccAddress).String()
	testCases := []struct {
		name   string
		msg    *types.MsgStoreCode
		expErr error
	}{
		{
			"success: valid signer address, valid length code",
			types.NewMsgStoreCode(signer, wasmtesting.Code),
			nil,
		},
		{
			"failure: code is empty",
			types.NewMsgStoreCode(signer, []byte("")),
			types.ErrWasmEmptyCode,
		},
		{
			"failure: code is too large",
			types.NewMsgStoreCode(signer, make([]byte, types.MaxWasmSize+1)),
			types.ErrWasmCodeTooLarge,
		},
		{
			"failure: signer is invalid",
			types.NewMsgStoreCode("invalid", wasmtesting.Code),
			ibcerrors.ErrInvalidAddress,
		},
	}

	for _, tc := range testCases {
		tc := tc

		err := tc.msg.ValidateBasic()
		expPass := tc.expErr == nil
		if expPass {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

func (suite *TypesTestSuite) TestMsgStoreCodeGetSigners() {
	testCases := []struct {
		name    string
		address sdk.AccAddress
		expPass bool
	}{
		{"success: valid address", sdk.AccAddress(ibctesting.TestAccAddress), true},
		{"failure: nil address", nil, false},
	}

	for _, tc := range testCases {
		tc := tc
		suite.Run(tc.name, func() {
			suite.SetupWasmWithMockVM()

			address := tc.address
			msg := types.NewMsgStoreCode(address.String(), wasmtesting.Code)

			signers, _, err := GetSimApp(suite.chainA).AppCodec().GetMsgV1Signers(msg)
			if tc.expPass {
				suite.Require().NoError(err)
				suite.Require().Equal(address.Bytes(), signers[0])
			} else {
				suite.Require().Error(err)
			}
		})
	}
}
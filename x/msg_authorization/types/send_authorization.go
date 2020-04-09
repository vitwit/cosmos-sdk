package types

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/bank"
	abci "github.com/tendermint/tendermint/abci/types"
)

func (authorization SendAuthorization) MsgType() string {
	return bank.MsgSend{}.Type()
}

func (authorization SendAuthorization) Accept(msg sdk.Msg, block abci.Header) (allow bool, updated Authorization, delete bool) {
	switch msg := msg.(type) {
	case bank.MsgSend:
		limitLeft, isNegative := authorization.SpendLimit.SafeSub(msg.Amount)
		if isNegative {
			return false, Authorization{}, false
		}
		if limitLeft.IsZero() {
			return true, Authorization{}, true
		}

		return true, Authorization{Sum: &Authorization_SendAuthorization{SendAuthorization: &SendAuthorization{SpendLimit: limitLeft}}}, false
	}
	return false, Authorization{}, false
}

package ante

import (
	"strings"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authztypes "github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

const (
	AllowedRecipients = "allowed_recipients"
	MaxAmount         = "max_amount"
)

type AuthzDecorator struct {
	azk AuthzKeeper
	ak  AccountKeeper
}

func NewAuthzDecorator(azk AuthzKeeper, ak AccountKeeper) AuthzDecorator {
	return AuthzDecorator{
		azk: azk,
		ak:  ak,
	}
}

// AuthzDecorator checks the authorization message grants for some rules.
func (azd AuthzDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	sigTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return ctx, errorsmod.Wrap(sdkerrors.ErrTxDecode, "invalid tx type")
	}

	signers, err := sigTx.GetSigners()
	if err != nil {
		return ctx, err
	}

	grantee := signers[0]

	msgs := tx.GetMsgs()
	for _, msg := range msgs {
		// Check if the message is an authorization message
		if authzMsg, ok := msg.(*authztypes.MsgExec); ok {

			msgs, err := authzMsg.GetMessages()
			if err != nil {
				return ctx, err
			}

			for _, innerMsg := range msgs {
				switch innerMsgConverted := innerMsg.(type) {
				case *banktypes.MsgSend:
					isRulesBroken, err := azd.handleSendAuthzRules(ctx, innerMsgConverted, grantee)
					if isRulesBroken {
						return ctx, err
					}
				}
			}
		}
	}

	// Continue with the transaction if all checks pass
	return next(ctx, tx, simulate)
}

// handleCheckSendAuthzRules returns true if the rules are voilated
func (azd AuthzDecorator) handleSendAuthzRules(ctx sdk.Context, msg *banktypes.MsgSend, grantee []byte) (bool, error) {

	granter, err := azd.ak.AddressCodec().StringToBytes(msg.FromAddress)
	if err != nil {
		return true, err
	}

	_, rules := azd.azk.GetAuthzWithRules(ctx, grantee, granter, sdk.MsgTypeURL(&banktypes.MsgSend{}))
	if rules != nil {
		if allowedAddrs, ok := rules[AllowedRecipients]; ok {
			allowedAddrsValue := allowedAddrs.(string)
			allowedAddrs := strings.Split(allowedAddrsValue, ",")
			isAllowed := false
			for _, allowedRecipient := range allowedAddrs {
				if msg.ToAddress == allowedRecipient {
					isAllowed = true
					break
				}
			}

			if !isAllowed {
				return true, errorsmod.Wrap(sdkerrors.ErrTxDecode, "Recipient is not in the allowed list of the grant")
			}
		}

		if spendLimitInterface, ok := rules[MaxAmount]; ok {
			spendLimit := spendLimitInterface.(string)
			limit, err := sdk.ParseCoinsNormalized(spendLimit)
			if err != nil {
				return true, err
			}
			if !limit.IsAllGTE(msg.Amount) {
				return true, errorsmod.Wrap(sdkerrors.ErrTxDecode, "Amount exceeds the max_amount limit set by the granter")
			}
		}
	}

	return false, nil
}

// func checkGenericAuthzRules(_ *authztypes.MsgGrant, authz *authztypes.GenericAuthorization, genericRules map[string]string) bool {
// 	if msgsStr, ok := genericRules["blockedMessages"]; ok {
// 		msgs := strings.Split(msgsStr, ",")
// 		for _, v := range msgs {
// 			if v == authz.Msg {
// 				return true
// 			}
// 		}
// 	}

// 	return false
// }

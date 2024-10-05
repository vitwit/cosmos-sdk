package ante

import (
	"fmt"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authztypes "github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	govv1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	stakingv1beta1 "github.com/cosmos/cosmos-sdk/x/staking/types"

	errorsmod "cosmossdk.io/errors"
)

type AuthzDecorator struct {
	azk       AuthzKeeper
	ak        AccountKeeper
	govKeeper GovKeeper
}

func NewAuthzDecorator(azk AuthzKeeper, ak AccountKeeper, govKeeper GovKeeper) AuthzDecorator {
	return AuthzDecorator{
		azk:       azk,
		ak:        ak,
		govKeeper: govKeeper,
	}
}

// AnteHandle checks the authorization message grants for some rules.
func (azd AuthzDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	// Ensure the transaction can be verified for signatures
	sigTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return ctx, errorsmod.Wrap(sdkerrors.ErrTxDecode, "invalid tx type")
	}

	// Get the signers of the transaction
	signers, err := sigTx.GetSigners()
	if err != nil {
		return ctx, err
	}

	// Assume the first signer is the grantee
	grantee := signers[0]

	// Get the messages in the transaction
	msgs := tx.GetMsgs()
	for _, msg := range msgs {
		// Check if the message is an authorization message
		authzMsg, ok := msg.(*authztypes.MsgExec)
		if !ok {
			continue
		}

		// Get the inner messages of the authorization message
		authzMsgs, err := authzMsg.GetMessages()
		if err != nil {
			return ctx, err
		}

		// Handle each inner message based on its type
		for _, innerMsg := range authzMsgs {
			switch innerMsg1 := innerMsg.(type) {
			case *banktypes.MsgSend:
				if err := azd.handleSendAuthzRules(ctx, innerMsg1, grantee); err != nil {
					return ctx, err
				}
			case *stakingv1beta1.MsgDelegate:
				if err := azd.handleStakeAuthzRules(ctx, innerMsg1, grantee); err != nil {
					return ctx, err
				}
			case *govv1.MsgVote:
				if err := azd.handleProposalAuthzRules(ctx, innerMsg1, grantee); err != nil {
					return ctx, err
				}

			default:
				fmt.Printf("Unhandled inner message type: %T\n", innerMsg)
			}
		}
	}

	// Continue with the next AnteHandler if all checks pass
	return next(ctx, tx, simulate)
}

// handleSendAuthzRules checks if a MsgSend transaction is authorized based on the rules set by the granter.
func (azd AuthzDecorator) handleSendAuthzRules(ctx sdk.Context, msg *banktypes.MsgSend, grantee []byte) error {
	// Convert the sender's address to bytes
	granter, err := azd.ak.AddressCodec().StringToBytes(msg.FromAddress)
	if err != nil {
		return err
	}

	// Retrieve authorization rules
	_, rules := azd.azk.GetAuthzWithRules(ctx, grantee, granter, sdk.MsgTypeURL(&banktypes.MsgSend{}))

	// Initialize maps for quick lookup
	allowedRecipients := make(map[string]struct{})
	var maxAmount sdk.Coins

	// Populate maps with rule values
	for _, rule := range rules {
		switch rule.Key {
		case authztypes.AllowedRecipients:
			for _, recipient := range rule.Values {
				allowedRecipients[recipient] = struct{}{}
			}
		case authztypes.MaxAmount:
			maxAmount, err = sdk.ParseCoinsNormalized(strings.Join(rule.Values, ","))
			if err != nil {
				return err
			}
		}
	}

	// Check if recipient is allowed
	if len(allowedRecipients) > 0 {
		if _, isAllowed := allowedRecipients[msg.ToAddress]; !isAllowed {
			return errorsmod.Wrap(sdkerrors.ErrTxDecode, "Recipient is not in the allowed list of the grant")
		}
	}

	// Check if the amount does not exceed the maximum allowed
	if maxAmount != nil {
		if !maxAmount.IsAllGTE(msg.Amount) {
			return errorsmod.Wrap(sdkerrors.ErrTxDecode, "Amount exceeds the max_amount limit set by the granter")
		}
	}

	return nil
}

// handleStakeAuthzRules checks if a MsgDelegate transaction is authorized based on the rules set by the granter.
func (azd AuthzDecorator) handleStakeAuthzRules(ctx sdk.Context, msg *stakingv1beta1.MsgDelegate, grantee []byte) error {
	// Convert the delegator's address to bytes
	granter, err := azd.ak.AddressCodec().StringToBytes(msg.DelegatorAddress)
	if err != nil {
		return err
	}

	// Retrieve authorization rules
	_, rules := azd.azk.GetAuthzWithRules(ctx, grantee, granter, sdk.MsgTypeURL(&stakingv1beta1.MsgDelegate{}))

	// Initialize maps for quick lookup
	allowedValidators := make(map[string]struct{})
	var maxStakeAmount sdk.Coins

	// Populate maps with rule values
	for _, rule := range rules {
		switch rule.Key {
		case authztypes.AllowedStakeValidators:
			for _, validator := range rule.Values {
				allowedValidators[validator] = struct{}{}
			}
		case authztypes.AllowedMaxStakeAmount:
			maxStakeAmount, err = sdk.ParseCoinsNormalized(strings.Join(rule.Values, ","))
			if err != nil {
				return err
			}
		}
	}

	// Check if validator is allowed
	if len(allowedValidators) > 0 {
		if _, isAllowed := allowedValidators[msg.ValidatorAddress]; !isAllowed {
			return errorsmod.Wrap(sdkerrors.ErrTxDecode, "Validator is not in the allowed validators of the grant")
		}
	}

	// Check if the stake amount does not exceed the maximum allowed
	if maxStakeAmount != nil {
		amount, err := sdk.ParseCoinNormalized(msg.Amount.String())
		if err != nil {
			return err
		}
		if !maxStakeAmount.IsAllGTE(sdk.NewCoins(amount)) {
			return errorsmod.Wrap(sdkerrors.ErrTxDecode, "Amount exceeds the max_amount limit set by the granter")
		}
	}

	return nil
}

// handleProposalAuthzRules checks if a MsgVote transaction is authorized based on the rules set by the granter.
func (azd AuthzDecorator) handleProposalAuthzRules(ctx sdk.Context, msg *govv1.MsgVote, grantee []byte) error {
	// Convert the voter's address to bytes
	granter, err := azd.ak.AddressCodec().StringToBytes(msg.Voter)
	if err != nil {
		return err
	}

	// Retrieve the proposal by ID
	proposal, err := azd.govKeeper.GetProposalById(ctx, msg.ProposalId)
	if err != nil {
		return err
	}

	// Retrieve authorization rules
	_, rules := azd.azk.GetAuthzWithRules(ctx, grantee, granter, sdk.MsgTypeURL(&govv1.MsgVote{}))
	if len(rules) == 0 {
		return nil
	}

	// Initialize a map for quick lookup of allowed proposal types
	allowedProposalTypes := make(map[string]struct{})

	// Populate map with rule values
	for _, rule := range rules {
		if rule.Key == authztypes.AllowedProposalTypes {
			for _, allowedProposalType := range rule.Values {
				allowedProposalTypes[allowedProposalType] = struct{}{}
			}
		}
	}

	// Check if any of the proposal messages' types are allowed
	for _, msg := range proposal.GetMessages() {
		if _, exists := allowedProposalTypes[msg.GetTypeUrl()]; exists {
			return nil // Proposal type is allowed
		}
	}

	return errorsmod.Wrap(sdkerrors.ErrTxDecode, "Voter is not allowed to vote on the proposal")
}

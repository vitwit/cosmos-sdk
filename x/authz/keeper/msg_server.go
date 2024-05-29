package keeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	errorsmod "cosmossdk.io/errors"

	bankv1beta1 "cosmossdk.io/api/cosmos/bank/v1beta1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/authz"
	staking "github.com/cosmos/cosmos-sdk/x/staking/types"
)

var _ authz.MsgServer = Keeper{}

// Grant implements the MsgServer.Grant method to create a new grant.
func (k Keeper) Grant(goCtx context.Context, msg *authz.MsgGrant) (*authz.MsgGrantResponse, error) {
	if strings.EqualFold(msg.Grantee, msg.Granter) {
		return nil, authz.ErrGranteeIsGranter
	}

	grantee, err := k.authKeeper.AddressCodec().StringToBytes(msg.Grantee)
	if err != nil {
		return nil, sdkerrors.ErrInvalidAddress.Wrapf("invalid grantee address: %s", err)
	}

	granter, err := k.authKeeper.AddressCodec().StringToBytes(msg.Granter)
	if err != nil {
		return nil, sdkerrors.ErrInvalidAddress.Wrapf("invalid granter address: %s", err)
	}

	if err := msg.Grant.ValidateBasic(); err != nil {
		return nil, err
	}

	// create the account if it is not in account state
	ctx := sdk.UnwrapSDKContext(goCtx)
	granteeAcc := k.authKeeper.GetAccount(ctx, grantee)
	if granteeAcc == nil {
		granteeAcc = k.authKeeper.NewAccountWithAddress(ctx, grantee)
		k.authKeeper.SetAccount(ctx, granteeAcc)
	}

	authorization, err := msg.GetAuthorization()
	if err != nil {
		return nil, err
	}

	t := authorization.MsgTypeURL()
	if k.router.HandlerByTypeURL(t) == nil {
		return nil, sdkerrors.ErrInvalidType.Wrapf("%s doesn't exist.", t)
	}

	var rules []*authz.Rule
	if msg.Rules != nil {
		var err error
		rules, err = k.VerifyAndBuildRules(goCtx, msg.Grant.Authorization.GetTypeUrl(), msg.Rules)
		if err != nil {
			return nil, err
		}
	}

	err = k.SaveGrant(ctx, grantee, granter, authorization, msg.Grant.Expiration, rules)
	if err != nil {
		return nil, err
	}

	return &authz.MsgGrantResponse{}, nil
}

// VerifyTheRules checks the keys of rules provided are allowed
func (k Keeper) VerifyAndBuildRules(goCtx context.Context, msg string, rulesBytes []byte) ([]*authz.Rule, error) {
	var rulesJson authz.AppAuthzRules
	err := json.Unmarshal(rulesBytes, &rulesJson)
	if err != nil {
		return nil, err
	}

	if err := validateRules(rulesJson); err != nil {
		return nil, err
	}

	registeredRules, err := k.GetAuthzRulesKeys(goCtx)
	if err != nil {
		return nil, err
	}

	var values []string
	for _, v := range registeredRules.Keys {
		if v.Key == msg {
			values = v.Values
			break
		}
	}

	if err := checkStructKeys(rulesJson, values); err != nil {
		return nil, err
	}

	var rules []*authz.Rule
	switch msg {
	case sdk.MsgTypeURL(&bankv1beta1.MsgSend{}):
		rules = []*authz.Rule{
			{Key: authz.AllowedRecipients, Values: rulesJson.AllowedRecipients},
			{Key: authz.MaxAmount, Values: rulesJson.MaxAmount},
		}

	case sdk.MsgTypeURL(&staking.MsgDelegate{}):
		rules = []*authz.Rule{
			{Key: authz.AllowedStakeValidators, Values: rulesJson.AllowedStakeValidators},
			{Key: authz.AllowedMaxStakeAmount, Values: rulesJson.AllowedMaxStakeAmount},
		}
	}

	return rules, nil
}

func checkStructKeys(s interface{}, allowedKeys []string) error {
	v := reflect.ValueOf(s)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("expected a struct, but got %s", v.Kind())
	}

	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !isAllowedKey(field.Name, allowedKeys) {
			return fmt.Errorf("field %s is not allowed", field.Name)
		}
	}
	return nil
}

func isAllowedKey(key string, allowedKeys []string) bool {
	for _, allowedKey := range allowedKeys {
		if key == allowedKey {
			return true
		}
	}
	return false
}

func validateRules(rules authz.AppAuthzRules) error {
	for _, addr := range rules.AllowedRecipients {
		if _, err := sdk.AccAddressFromBech32(addr); err != nil {
			return err
		}
	}

	coins, err := sdk.ParseCoinsNormalized(strings.Join(rules.MaxAmount, ","))
	if err != nil {
		return err
	}

	if err := coins.Sort().Validate(); err != nil {
		return err
	}

	for _, valAddr := range rules.AllowedStakeValidators {
		if _, err := sdk.ValAddressFromBech32(valAddr); err != nil {
			return err
		}
	}

	maxStake, err := sdk.ParseCoinsNormalized(strings.Join(rules.AllowedMaxStakeAmount, ","))
	if err != nil {
		return err
	}

	if err := maxStake.Sort().Validate(); err != nil {
		return err
	}

	return nil
}

// Revoke implements the MsgServer.Revoke method.
func (k Keeper) Revoke(goCtx context.Context, msg *authz.MsgRevoke) (*authz.MsgRevokeResponse, error) {
	if strings.EqualFold(msg.Grantee, msg.Granter) {
		return nil, authz.ErrGranteeIsGranter
	}

	grantee, err := k.authKeeper.AddressCodec().StringToBytes(msg.Grantee)
	if err != nil {
		return nil, sdkerrors.ErrInvalidAddress.Wrapf("invalid grantee address: %s", err)
	}

	granter, err := k.authKeeper.AddressCodec().StringToBytes(msg.Granter)
	if err != nil {
		return nil, sdkerrors.ErrInvalidAddress.Wrapf("invalid granter address: %s", err)
	}

	if msg.MsgTypeUrl == "" {
		return nil, sdkerrors.ErrInvalidRequest.Wrap("missing msg method name")
	}

	ctx := sdk.UnwrapSDKContext(goCtx)
	if err = k.DeleteGrant(ctx, grantee, granter, msg.MsgTypeUrl); err != nil {
		return nil, err
	}

	return &authz.MsgRevokeResponse{}, nil
}

// Exec implements the MsgServer.Exec method.
func (k Keeper) Exec(goCtx context.Context, msg *authz.MsgExec) (*authz.MsgExecResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	if msg.Grantee == "" {
		return nil, errors.New("empty address string is not allowed")
	}

	grantee, err := k.authKeeper.AddressCodec().StringToBytes(msg.Grantee)
	if err != nil {
		return nil, sdkerrors.ErrInvalidAddress.Wrapf("invalid grantee address: %s", err)
	}

	if len(msg.Msgs) == 0 {
		return nil, sdkerrors.ErrInvalidRequest.Wrapf("messages cannot be empty")
	}

	msgs, err := msg.GetMessages()
	if err != nil {
		return nil, err
	}

	if err := validateMsgs(msgs); err != nil {
		return nil, err
	}

	results, err := k.DispatchActions(ctx, grantee, msgs)
	if err != nil {
		return nil, err
	}

	return &authz.MsgExecResponse{Results: results}, nil
}

func validateMsgs(msgs []sdk.Msg) error {
	for i, msg := range msgs {
		m, ok := msg.(sdk.HasValidateBasic)
		if !ok {
			continue
		}

		if err := m.ValidateBasic(); err != nil {
			return errorsmod.Wrapf(err, "msg %d", i)
		}
	}

	return nil
}

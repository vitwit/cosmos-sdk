// nolint
// autogenerated code using github.com/rigelrozanski/multitool
// aliases generated for the following subdirectories:
// ALIASGEN: github.com/cosmos/cosmos-sdk/x/msg_authorization/internal/types/
// ALIASGEN: github.com/cosmos/cosmos-sdk/x/msg_authorization/internal/keeper/
package msg_authorization

import (
	"github.com/cosmos/cosmos-sdk/x/msg_authorization/internal/keeper"
	"github.com/cosmos/cosmos-sdk/x/msg_authorization/internal/types"
)

const (
	ModuleName   = types.ModuleName
	StoreKey     = types.StoreKey
	RouterKey    = types.RouterKey
	QuerierRoute = types.QuerierRoute
)

var (
	// functions aliases
	RegisterCodec             = types.RegisterCodec
	ErrInvalidGranter         = types.ErrInvalidGranter
	ErrInvalidGrantee         = types.ErrInvalidGrantee
	ErrInvalidExpirationTime  = types.ErrInvalidExpirationTime
	NewMsgGrantAuthorization  = types.NewMsgGrantAuthorization
	NewMsgRevokeAuthorization = types.NewMsgRevokeAuthorization
	NewMsgExecAuthorized      = types.NewMsgExecAuthorized
	NewKeeper                 = keeper.NewKeeper

	// variable aliases
	ModuleCdc = types.ModuleCdc
)

type (
	Authorization          = types.Authorization
	SendAuthorization      = types.SendAuthorization
	AuthorizationGrant     = types.AuthorizationGrant
	GenericAuthorization   = types.GenericAuthorization
	MsgGrantAuthorization  = types.MsgGrantAuthorization
	MsgRevokeAuthorization = types.MsgRevokeAuthorization
	MsgExecAuthorized      = types.MsgExecAuthorized
	Keeper                 = keeper.Keeper
)

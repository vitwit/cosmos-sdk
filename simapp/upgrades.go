package simapp

import (
	"context"

	storetypes "cosmossdk.io/store/types"
	circuittypes "cosmossdk.io/x/circuit/types"
	upgradetypes "cosmossdk.io/x/upgrade/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// UpgradeName defines the on-chain upgrade name for the sample SimApp upgrade
// from v047 to v050.
//
// NOTE: This upgrade defines a reference implementation of what an upgrade
// could look like when an application is migrating from Cosmos SDK version
// v0.47.x to v0.50.x.
const UpgradeName = "v047-to-v050"

func (app SimApp) RegisterUpgradeHandlers() {
	app.UpgradeKeeper.SetUpgradeHandler(
		UpgradeName,
		func(ctx context.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
			return app.ModuleManager.RunMigrations(ctx, app.Configurator(), fromVM)
		},
	)

	app.UpgradeKeeper.SetUpgradeHandler(
		"v2",
		func(ctx context.Context, plan upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
			app.AuthzKeeper.SetAuthzRulesKeys(ctx, &authz.AllowedGrantRulesKeys{
				Keys: []*authz.Rule{
					&authz.Rule{Key: sdk.MsgTypeURL(&banktypes.MsgSend{}), Values: []string{
						authz.MaxAmount, authz.AllowedRecipients,
					}},
					&authz.Rule{Key: sdk.MsgTypeURL(&stakingtypes.MsgDelegate{}), Values: []string{
						authz.AllowedStakeValidators, authz.AllowedMaxStakeAmount,
					}},
				},
			})

			return app.ModuleManager.RunMigrations(ctx, app.Configurator(), fromVM)
		},
	)

	upgradeInfo, err := app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
	if err != nil {
		panic(err)
	}

	if upgradeInfo.Name == UpgradeName && !app.UpgradeKeeper.IsSkipHeight(upgradeInfo.Height) {
		storeUpgrades := storetypes.StoreUpgrades{
			Added: []string{
				circuittypes.ModuleName,
			},
		}

		// configure store loader that checks if version == upgradeHeight and applies store upgrades
		app.SetStoreLoader(upgradetypes.UpgradeStoreLoader(upgradeInfo.Height, &storeUpgrades))
	}
}

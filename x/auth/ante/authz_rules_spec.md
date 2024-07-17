# Description

Problem: 
The existing authorization (authz) module lacks the flexibility to grant permissions (authz grants) for various types of messages along with specific conditions or rules. This limitation constrains users from customizing their transaction behavior based on specific needs or strategies.

## Specific Examples of Limitations:
Swapping Reward Tokens:
 - Currently, users cannot set a rule to swap their reward tokens or any other tokens for another token with a specified limit.
Sending Tokens to Selected Addresses:
 - Users are unable to authorize sending tokens to a pre-defined or selected address, restricting the ability to control where tokens are transferred.
Staking Tokens with Limitations:
 - The module does not allow users to grant permission to stake tokens with certain limits or to stake only with selected validators. This limits the user's control over staking decisions.

## PR diff:
This PR adds a feature which an authz can be granted with some rules, 
for example:
 - if a staker wants to stake some portion of rewards he can do that by allowing max stake amount
 - if he wants to stake only to selected validators
 - swap some portion of rewards to another token or liquid staked token 
 - also we can add rules to every message before granting. 
 
Changes:
updated the ante handlers flow to check in the message is executing the authz message and any rules need to be checked before processing the message. if the message is not reaching the rules then it will eventually fail.

added an extra ante handler:
```
// handleCheckSendAuthzRules returns true if the rules are voilated
func (azd AuthzDecorator) handleSendAuthzRules(ctx sdk.Context, msg *banktypes.MsgSend, grantee []byte) error {
	granter, err := azd.ak.AddressCodec().StringToBytes(msg.FromAddress)
	if err != nil {
		return err
	}

	_, rules := azd.azk.GetAuthzWithRules(ctx, grantee, granter, sdk.MsgTypeURL(&banktypes.MsgSend{}))
	for _, rule := range rules {
		if rule.Key == authztypes.AllowedRecipients {
			isAllowed := false
			for _, allowedRecipient := range rule.Values {
				if msg.ToAddress == allowedRecipient {
					isAllowed = true
					break
				}
			}

			if !isAllowed {
				return errorsmod.Wrap(sdkerrors.ErrTxDecode, "Recipient is not in the allowed list of the grant")
			}
		}

		if rule.Key == authztypes.MaxAmount {
			limit, err := sdk.ParseCoinsNormalized(strings.Join(rule.Values, ","))
			if err != nil {
				return err
			}
			if !limit.IsAllGTE(msg.Amount) {
				return errorsmod.Wrap(sdkerrors.ErrTxDecode, "Amount exceeds the max_amount limit set by the granter")
			}
		}

	}

	return nil
}
``` 
the above snippet checks the rules for `MsgSend` likewise we can add checks to every messages.
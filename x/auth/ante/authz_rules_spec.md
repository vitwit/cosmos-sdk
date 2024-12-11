# Status

DRAFT

# Context 

The current authorization (authz) module lacks the flexibility needed to grant permissions (authz grants) for various types of messages along with 
specific conditions or rules. This limitation prevents users from customizing their transaction behavior according to specific needs or strategies.	To address this issue, we propose enhancing the authz module to support more granular permissions and conditional rules, allowing for greater
customization and control over transaction authorization.

## Specific Examples of Limitations

Managing Reward Tokens:

 - At present, users are able to restake their tokens via authz. But it can do more. Currently users are unable to establish rules for swapping their 	
reward tokens as a strategy as it requires IBCTransfer or PacketForward msgs access. It's not secure to give this grant currently as the recipient address can be anything and grantee can behave maliciously. But if there's a way to restrict recipient address to match with granter's address, this problem is solved. This functionality is necessary to enable users to automate and customize their token management strategies effectively.

 - Users currently cannot authorize sending tokens to a pre-defined or selected address. This restriction limits their ability to control and automate the  
transfer of tokens to specific recipients, thereby reducing the efficiency and flexibility of their token management strategies. For example, if an organization wants to authorize an accountant to process salaries every month, the current system's limitations prevent this. Implementing an authz grant to recurrently allow a user to send a specified amount to certain accounts would solve this issue. This feature would automate salary payments, ensuring timely and accurate transactions while reducing administrative overhead.

Managing Proposals: 

 - Currently authz module does not allow for granular permissions, meaning that users cannot be restricted to vote only on certain types of proposals. This 
limitation can lead to less informed voting decisions as users may vote on proposals outside their area of expertise. for ex: param change proposal or software upgrade proposals both are different type of messages.

Proposed Enhancement:
The enhanced authz module will allow the delegation of voting permissions on a per-proposal-type basis. This ensures that voters only vote on proposals they are knowledgeable about, leading to more informed and effective governance decisions.

# Use Case: Delegating Voting Permissions Based on Proposal Types

 - To grant specific voting permissions to different groups of people based on their expertise, ensuring they vote only on proposals relevant to their 
knowledge.

## Let's take 2 types of Proposals:
### Types of Proposals
1. **Parameter Change Proposals**:
   - These proposals involve changes to the network's parameters, such as block size, transaction fees, or other configurable parameters.

2. **Software Upgrade Proposals**:
   - These proposals involve upgrading the blockchain software to a new version, which might include new features, security patches, or performance improvements.

### Implementation Steps

1. **Identify Expertise of Voters**:
   - Determine the areas of expertise for different groups of voters. For instance, some voters may have deep knowledge of network parameters, while others may be experts in blockchain software development.

2. **Define Authz Grants**:
   - Create specific authz grants that allow voters to vote only on the proposals relevant to their expertise.
   
   **Example Grants**:
   - Grant A: Authorization to vote on Parameter Change Proposals.
   - Grant B: Authorization to vote on Software Upgrade Proposals.

3. **Assign Authz Grants**:
   - Assign these grants to the appropriate groups of voters based on their expertise.
   
   **Example Assignments**:
   - Group 1: Experts in network parameters receive Grant A.
   - Group 2: Experts in software development receive Grant B.

4. **Enforce Voting Permissions**:
   - Ensure that the voting system checks the authz grants before allowing a user to vote on a proposal. If a user tries to vote on a proposal type for which they do not have the appropriate grant, the system will deny the vote.

## Detailed Example

### Scenario
- **Group 1**: Network administrators who have in-depth knowledge of how changes to parameters like block size or transaction fees impact the network.
- **Group 2**: Software engineers who are well-versed in the technical aspects of software upgrades and new feature implementations.

### Steps

1. **Grant Creation**:
   - **Grant A**: Allows voting on Parameter Change Proposals.
   - **Grant B**: Allows voting on Software Upgrade Proposals.

2. **Assigning Grants**:
   - **Group 1**: Assigned Grant A.
   - **Group 2**: Assigned Grant B.

3. **Voting Process**:
   - When a Parameter Change Proposal is submitted:
     - Only members of Group 1 are allowed to vote. If a member of Group 2 attempts to vote, the system checks their authz and denies the vote.
   
   - When a Software Upgrade Proposal is submitted:
     - Only members of Group 2 are allowed to vote. If a member of Group 1 attempts to vote, the system checks their authz and denies the vote.

## Benefits

1. **Informed Voting**:
   - By restricting voting permissions based on expertise, the voting process becomes more informed and effective, as only knowledgeable individuals vote on relevant proposals.

2. **Enhanced Security**:
   - Reduces the risk of uninformed or malicious votes affecting critical decisions.

3. **Efficient Governance**:
   - Streamlines the governance process by ensuring that proposals are evaluated by the most qualified individuals, leading to better decision-making and more robust governance outcomes.

By implementing these enhancements, the governance process becomes more structured and reliable, with decisions being made by those best equipped to understand the implications of the proposals. This approach ensures a higher quality of governance and more effective management of the blockchain network.

# Pull Request: New Ante Handler for Authorization Rules

## Introduction

This PR introduces several key enhancements to the authorization (authz) system, aimed at providing more flexibility and control for app developers and users.

## Key Changes

1. **New Ante Handler**:

   - A new ante handler has been introduced to help app developers check authorization grants along with the specified rules. This allows for more granular control and ensures that all transactions comply with the defined rules before they are processed.

2. **Updated Authz Grant Proto**:

   - The `authz grant proto` has been updated to include the capability to add rules to the grants. When granting authorization, developers can now specify conditions based on the type of message. If no rules are specified, the grant will function as a basic grant without any additional conditions.

3. **Customization for App Developers**:

   - App developers need to edit the `authz_rules_ante.go` file to add more rules based on different message types. This file serves as the central point for defining and enforcing custom rules for various message types within the authorization framework.

## Sample Code Snippet

Below is a sample snippet illustrating how the new ante handler processes messages and checks authorization rules:

```go
for _, msg := range msgs {
    // Check if the message is an authorization message
    if authzMsg, ok := msg.(*authztypes.MsgExec); ok {

        authzMsgs, err := authzMsg.GetMessages()
        if err != nil {
            return ctx, err
        }

        for _, innerMsg := range authzMsgs {
            switch innerMsgConverted := innerMsg.(type) {
            case *banktypes.MsgSend:
                err := azd.handleSendAuthzRules(ctx, innerMsgConverted, grantee)
                if err != nil {
                    return ctx, err
                }
			case *govtypes.MsgVote:
                err := azd.handleVote(ctx, innerMsgConverted, grantee)
                if err != nil {
                    return ctx, err
                }
            case *stakingv1beta1.MsgDelegate:
                // handle delegate message
            }
        }
    }
}

// handleCheckSendAuthzRules returns true if the rules are voilated
func (azd AuthzDecorator) handleVote(ctx sdk.Context, msg *govtypes.MsgVote, grantee []byte) error {

	_, rules := azd.azk.GetAuthzWithRules(ctx, grantee, granter, sdk.MsgTypeURL(&govtypes.MsgVote{}))

	proposal, err := azd.govKeeper.GetProposal(msg.ProposalId)
	propMsgs := proposal.GetMessages()
	if rules == nil {
		return nil
	}

	for _, msg := range propMsgs {
		for _, rule := range rules {
			if rule.AllowedMessage != msg.GetTypeUrl() {
				return return errorsmod.Wrap(sdkerrors.ErrTxDecode, "Voter is not allowed vote on this message")
			}
		}
	}

	return nil
}

// handleCheckSendAuthzRules returns true if the rules are voilated
func (azd AuthzDecorator) handleSendAuthzRules(ctx sdk.Context, msg *banktypes.MsgSend, grantee []byte) error {
	
	_, rules := azd.azk.GetAuthzWithRules(ctx, grantee, granter, sdk.MsgTypeURL(&banktypes.MsgSend{}))
	for _, rule := range rules {

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

# Conclusion

This Spec significantly enhances the authorization system by introducing a new ante handler for checking rules, updating the authz grant proto to support conditional grants, and providing a mechanism for developers to add custom rules. These changes ensure that transactions are processed according to the defined conditions, improving the security and flexibility of the authorization framework.
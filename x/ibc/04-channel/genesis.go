package channel

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis initializes the ibc channel submodule's state from a provided genesis
// state.
func InitGenesis(ctx sdk.Context, k Keeper, gs GenesisState) {
	for _, channel := range gs.Channels {
		k.SetChannel(ctx, channel)
	}
	for _, ack := range gs.Acknowledgements {
		k.SetPacketAcknowledgement(ctx, ack.PortID, ack.ChannelID, ack.Sequence, ack.Ack)
	}
	for _, commitment := range gs.Commitments {
		k.SetPacketCommitment(ctx, commitment.PortID, commitment.ChannelID, commitment.Sequence, commitment.Hash)
	}
	for _, ss := range gs.SendSequences {
		k.SetNextSequenceSend(ctx, ss.PortID, ss.ChannelID, ss.Sequence)
	}
	for _, rs := range gs.RecvSequences {
		k.SetNextSequenceRecv(ctx, rs.PortID, rs.ChannelID, rs.Sequence)
	}
}

// ExportGenesis returns the ibc channel submodule's exported genesis.
func ExportGenesis(ctx sdk.Context, k Keeper) GenesisState {
	return GenesisState{
		Channels:         k.GetAllChannels(ctx),
		Acknowledgements: k.GetAllPacketAcks(ctx),
		Commitments:      k.GetAllPacketCommitments(ctx),
		SendSequences:    k.GetAllPacketSendSeqs(ctx),
		RecvSequences:    k.GetAllPacketRecvSeqs(ctx),
	}
}

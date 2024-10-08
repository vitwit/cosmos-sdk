// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cosmos/accounts/defaults/base/v1/base.proto

package v1

import (
	fmt "fmt"
	proto "github.com/cosmos/gogoproto/proto"
	any "github.com/cosmos/gogoproto/types/any"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// MsgInit is used to initialize a base account.
type MsgInit struct {
	// pub_key defines a pubkey for the account arbitrary encapsulated.
	PubKey *any.Any `protobuf:"bytes,1,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
}

func (m *MsgInit) Reset()         { *m = MsgInit{} }
func (m *MsgInit) String() string { return proto.CompactTextString(m) }
func (*MsgInit) ProtoMessage()    {}
func (*MsgInit) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c860870b5ed6dc2, []int{0}
}
func (m *MsgInit) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MsgInit) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MsgInit.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MsgInit) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MsgInit.Merge(m, src)
}
func (m *MsgInit) XXX_Size() int {
	return m.Size()
}
func (m *MsgInit) XXX_DiscardUnknown() {
	xxx_messageInfo_MsgInit.DiscardUnknown(m)
}

var xxx_messageInfo_MsgInit proto.InternalMessageInfo

func (m *MsgInit) GetPubKey() *any.Any {
	if m != nil {
		return m.PubKey
	}
	return nil
}

// MsgInitResponse is the response returned after base account initialization.
// This is empty.
type MsgInitResponse struct {
}

func (m *MsgInitResponse) Reset()         { *m = MsgInitResponse{} }
func (m *MsgInitResponse) String() string { return proto.CompactTextString(m) }
func (*MsgInitResponse) ProtoMessage()    {}
func (*MsgInitResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c860870b5ed6dc2, []int{1}
}
func (m *MsgInitResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MsgInitResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MsgInitResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MsgInitResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MsgInitResponse.Merge(m, src)
}
func (m *MsgInitResponse) XXX_Size() int {
	return m.Size()
}
func (m *MsgInitResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MsgInitResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MsgInitResponse proto.InternalMessageInfo

// MsgSwapPubKey is used to change the pubkey for the account.
type MsgSwapPubKey struct {
	// new_pub_key defines the secp256k1 pubkey to swap the account to.
	NewPubKey *any.Any `protobuf:"bytes,1,opt,name=new_pub_key,json=newPubKey,proto3" json:"new_pub_key,omitempty"`
}

func (m *MsgSwapPubKey) Reset()         { *m = MsgSwapPubKey{} }
func (m *MsgSwapPubKey) String() string { return proto.CompactTextString(m) }
func (*MsgSwapPubKey) ProtoMessage()    {}
func (*MsgSwapPubKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c860870b5ed6dc2, []int{2}
}
func (m *MsgSwapPubKey) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MsgSwapPubKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MsgSwapPubKey.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MsgSwapPubKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MsgSwapPubKey.Merge(m, src)
}
func (m *MsgSwapPubKey) XXX_Size() int {
	return m.Size()
}
func (m *MsgSwapPubKey) XXX_DiscardUnknown() {
	xxx_messageInfo_MsgSwapPubKey.DiscardUnknown(m)
}

var xxx_messageInfo_MsgSwapPubKey proto.InternalMessageInfo

func (m *MsgSwapPubKey) GetNewPubKey() *any.Any {
	if m != nil {
		return m.NewPubKey
	}
	return nil
}

// MsgSwapPubKeyResponse is the response for the MsgSwapPubKey message.
// This is empty.
type MsgSwapPubKeyResponse struct {
}

func (m *MsgSwapPubKeyResponse) Reset()         { *m = MsgSwapPubKeyResponse{} }
func (m *MsgSwapPubKeyResponse) String() string { return proto.CompactTextString(m) }
func (*MsgSwapPubKeyResponse) ProtoMessage()    {}
func (*MsgSwapPubKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c860870b5ed6dc2, []int{3}
}
func (m *MsgSwapPubKeyResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *MsgSwapPubKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_MsgSwapPubKeyResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *MsgSwapPubKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MsgSwapPubKeyResponse.Merge(m, src)
}
func (m *MsgSwapPubKeyResponse) XXX_Size() int {
	return m.Size()
}
func (m *MsgSwapPubKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MsgSwapPubKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MsgSwapPubKeyResponse proto.InternalMessageInfo

// QuerySequence is the request for the account sequence.
type QuerySequence struct {
}

func (m *QuerySequence) Reset()         { *m = QuerySequence{} }
func (m *QuerySequence) String() string { return proto.CompactTextString(m) }
func (*QuerySequence) ProtoMessage()    {}
func (*QuerySequence) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c860870b5ed6dc2, []int{4}
}
func (m *QuerySequence) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QuerySequence) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QuerySequence.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QuerySequence) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QuerySequence.Merge(m, src)
}
func (m *QuerySequence) XXX_Size() int {
	return m.Size()
}
func (m *QuerySequence) XXX_DiscardUnknown() {
	xxx_messageInfo_QuerySequence.DiscardUnknown(m)
}

var xxx_messageInfo_QuerySequence proto.InternalMessageInfo

// QuerySequenceResponse returns the sequence of the account.
type QuerySequenceResponse struct {
	// sequence is the current sequence of the account.
	Sequence uint64 `protobuf:"varint,1,opt,name=sequence,proto3" json:"sequence,omitempty"`
}

func (m *QuerySequenceResponse) Reset()         { *m = QuerySequenceResponse{} }
func (m *QuerySequenceResponse) String() string { return proto.CompactTextString(m) }
func (*QuerySequenceResponse) ProtoMessage()    {}
func (*QuerySequenceResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c860870b5ed6dc2, []int{5}
}
func (m *QuerySequenceResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QuerySequenceResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QuerySequenceResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QuerySequenceResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QuerySequenceResponse.Merge(m, src)
}
func (m *QuerySequenceResponse) XXX_Size() int {
	return m.Size()
}
func (m *QuerySequenceResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QuerySequenceResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QuerySequenceResponse proto.InternalMessageInfo

func (m *QuerySequenceResponse) GetSequence() uint64 {
	if m != nil {
		return m.Sequence
	}
	return 0
}

// QueryPubKey is the request used to query the pubkey of an account.
type QueryPubKey struct {
}

func (m *QueryPubKey) Reset()         { *m = QueryPubKey{} }
func (m *QueryPubKey) String() string { return proto.CompactTextString(m) }
func (*QueryPubKey) ProtoMessage()    {}
func (*QueryPubKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c860870b5ed6dc2, []int{6}
}
func (m *QueryPubKey) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryPubKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryPubKey.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryPubKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryPubKey.Merge(m, src)
}
func (m *QueryPubKey) XXX_Size() int {
	return m.Size()
}
func (m *QueryPubKey) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryPubKey.DiscardUnknown(m)
}

var xxx_messageInfo_QueryPubKey proto.InternalMessageInfo

// QueryPubKeyResponse is the response returned when a QueryPubKey message is sent.
type QueryPubKeyResponse struct {
	PubKey *any.Any `protobuf:"bytes,1,opt,name=pub_key,json=pubKey,proto3" json:"pub_key,omitempty"`
}

func (m *QueryPubKeyResponse) Reset()         { *m = QueryPubKeyResponse{} }
func (m *QueryPubKeyResponse) String() string { return proto.CompactTextString(m) }
func (*QueryPubKeyResponse) ProtoMessage()    {}
func (*QueryPubKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_7c860870b5ed6dc2, []int{7}
}
func (m *QueryPubKeyResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryPubKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryPubKeyResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryPubKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryPubKeyResponse.Merge(m, src)
}
func (m *QueryPubKeyResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryPubKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryPubKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryPubKeyResponse proto.InternalMessageInfo

func (m *QueryPubKeyResponse) GetPubKey() *any.Any {
	if m != nil {
		return m.PubKey
	}
	return nil
}

func init() {
	proto.RegisterType((*MsgInit)(nil), "cosmos.accounts.defaults.base.v1.MsgInit")
	proto.RegisterType((*MsgInitResponse)(nil), "cosmos.accounts.defaults.base.v1.MsgInitResponse")
	proto.RegisterType((*MsgSwapPubKey)(nil), "cosmos.accounts.defaults.base.v1.MsgSwapPubKey")
	proto.RegisterType((*MsgSwapPubKeyResponse)(nil), "cosmos.accounts.defaults.base.v1.MsgSwapPubKeyResponse")
	proto.RegisterType((*QuerySequence)(nil), "cosmos.accounts.defaults.base.v1.QuerySequence")
	proto.RegisterType((*QuerySequenceResponse)(nil), "cosmos.accounts.defaults.base.v1.QuerySequenceResponse")
	proto.RegisterType((*QueryPubKey)(nil), "cosmos.accounts.defaults.base.v1.QueryPubKey")
	proto.RegisterType((*QueryPubKeyResponse)(nil), "cosmos.accounts.defaults.base.v1.QueryPubKeyResponse")
}

func init() {
	proto.RegisterFile("cosmos/accounts/defaults/base/v1/base.proto", fileDescriptor_7c860870b5ed6dc2)
}

var fileDescriptor_7c860870b5ed6dc2 = []byte{
	// 303 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x91, 0xcf, 0x4a, 0xc3, 0x40,
	0x10, 0xc6, 0x1b, 0x90, 0x56, 0xa7, 0x94, 0x62, 0xb4, 0xa8, 0x3d, 0x2c, 0x65, 0x4f, 0x05, 0x71,
	0x97, 0x5a, 0x0f, 0x5e, 0x2d, 0x7a, 0x10, 0x29, 0x68, 0x7a, 0xf3, 0x52, 0x92, 0x74, 0x1a, 0x4a,
	0xeb, 0x6e, 0xec, 0x66, 0x1b, 0xf3, 0x16, 0x3e, 0x96, 0xc7, 0x1e, 0x3d, 0x4a, 0xf2, 0x22, 0xc2,
	0xe6, 0x0f, 0xf6, 0x20, 0xe8, 0x69, 0x99, 0xe1, 0xf7, 0xfb, 0x06, 0xf6, 0x83, 0x73, 0x5f, 0xaa,
	0x17, 0xa9, 0xb8, 0xeb, 0xfb, 0x52, 0x8b, 0x48, 0xf1, 0x19, 0xce, 0x5d, 0xbd, 0x8a, 0x14, 0xf7,
	0x5c, 0x85, 0x7c, 0x33, 0x30, 0x2f, 0x0b, 0xd7, 0x32, 0x92, 0x76, 0x2f, 0x87, 0x59, 0x09, 0xb3,
	0x12, 0x66, 0x06, 0xda, 0x0c, 0xba, 0x67, 0x81, 0x94, 0xc1, 0x0a, 0xb9, 0xe1, 0x3d, 0x3d, 0xe7,
	0xae, 0x48, 0x72, 0x99, 0x5e, 0x43, 0x63, 0xac, 0x82, 0x7b, 0xb1, 0x88, 0xec, 0x0b, 0x68, 0x84,
	0xda, 0x9b, 0x2e, 0x31, 0x39, 0xb5, 0x7a, 0x56, 0xbf, 0x79, 0x79, 0xcc, 0x72, 0x8f, 0x95, 0x1e,
	0xbb, 0x11, 0x89, 0x53, 0x0f, 0xb5, 0xf7, 0x80, 0x09, 0x3d, 0x84, 0x76, 0x61, 0x3a, 0xa8, 0x42,
	0x29, 0x14, 0xd2, 0x3b, 0x68, 0x8d, 0x55, 0x30, 0x89, 0xdd, 0xf0, 0xd1, 0x30, 0xf6, 0x15, 0x34,
	0x05, 0xc6, 0xd3, 0xbf, 0xc4, 0x1e, 0x08, 0x8c, 0x73, 0x8b, 0x9e, 0x40, 0x67, 0x27, 0xa6, 0xca,
	0x6f, 0x43, 0xeb, 0x49, 0xe3, 0x3a, 0x99, 0xe0, 0xab, 0x46, 0xe1, 0x23, 0x1d, 0x42, 0x67, 0x67,
	0x51, 0x92, 0x76, 0x17, 0xf6, 0x55, 0xb1, 0x33, 0x57, 0xf7, 0x9c, 0x6a, 0xa6, 0x2d, 0x68, 0x1a,
	0xa9, 0xb8, 0x76, 0x0b, 0x47, 0x3f, 0xc6, 0x2a, 0xe1, 0x7f, 0xbf, 0x31, 0x1a, 0x7d, 0xa4, 0xc4,
	0xda, 0xa6, 0xc4, 0xfa, 0x4a, 0x89, 0xf5, 0x9e, 0x91, 0xda, 0x36, 0x23, 0xb5, 0xcf, 0x8c, 0xd4,
	0x9e, 0xfb, 0x79, 0x3d, 0x6a, 0xb6, 0x64, 0x0b, 0xc9, 0xdf, 0x7e, 0xef, 0xd4, 0xab, 0x9b, 0xe4,
	0xe1, 0x77, 0x00, 0x00, 0x00, 0xff, 0xff, 0x8f, 0xe1, 0xb2, 0xd8, 0xfe, 0x01, 0x00, 0x00,
}

func (m *MsgInit) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MsgInit) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MsgInit) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.PubKey != nil {
		{
			size, err := m.PubKey.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintBase(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *MsgInitResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MsgInitResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MsgInitResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	return len(dAtA) - i, nil
}

func (m *MsgSwapPubKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MsgSwapPubKey) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MsgSwapPubKey) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.NewPubKey != nil {
		{
			size, err := m.NewPubKey.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintBase(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *MsgSwapPubKeyResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MsgSwapPubKeyResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *MsgSwapPubKeyResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	return len(dAtA) - i, nil
}

func (m *QuerySequence) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QuerySequence) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QuerySequence) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	return len(dAtA) - i, nil
}

func (m *QuerySequenceResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QuerySequenceResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QuerySequenceResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Sequence != 0 {
		i = encodeVarintBase(dAtA, i, uint64(m.Sequence))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *QueryPubKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryPubKey) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryPubKey) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	return len(dAtA) - i, nil
}

func (m *QueryPubKeyResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryPubKeyResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryPubKeyResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.PubKey != nil {
		{
			size, err := m.PubKey.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintBase(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintBase(dAtA []byte, offset int, v uint64) int {
	offset -= sovBase(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *MsgInit) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.PubKey != nil {
		l = m.PubKey.Size()
		n += 1 + l + sovBase(uint64(l))
	}
	return n
}

func (m *MsgInitResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	return n
}

func (m *MsgSwapPubKey) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.NewPubKey != nil {
		l = m.NewPubKey.Size()
		n += 1 + l + sovBase(uint64(l))
	}
	return n
}

func (m *MsgSwapPubKeyResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	return n
}

func (m *QuerySequence) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	return n
}

func (m *QuerySequenceResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Sequence != 0 {
		n += 1 + sovBase(uint64(m.Sequence))
	}
	return n
}

func (m *QueryPubKey) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	return n
}

func (m *QueryPubKeyResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.PubKey != nil {
		l = m.PubKey.Size()
		n += 1 + l + sovBase(uint64(l))
	}
	return n
}

func sovBase(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozBase(x uint64) (n int) {
	return sovBase(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *MsgInit) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowBase
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MsgInit: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MsgInit: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PubKey", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowBase
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthBase
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthBase
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.PubKey == nil {
				m.PubKey = &any.Any{}
			}
			if err := m.PubKey.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipBase(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthBase
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *MsgInitResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowBase
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MsgInitResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MsgInitResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipBase(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthBase
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *MsgSwapPubKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowBase
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MsgSwapPubKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MsgSwapPubKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field NewPubKey", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowBase
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthBase
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthBase
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.NewPubKey == nil {
				m.NewPubKey = &any.Any{}
			}
			if err := m.NewPubKey.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipBase(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthBase
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *MsgSwapPubKeyResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowBase
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MsgSwapPubKeyResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MsgSwapPubKeyResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipBase(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthBase
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QuerySequence) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowBase
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QuerySequence: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QuerySequence: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipBase(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthBase
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QuerySequenceResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowBase
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QuerySequenceResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QuerySequenceResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Sequence", wireType)
			}
			m.Sequence = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowBase
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Sequence |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipBase(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthBase
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryPubKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowBase
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryPubKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryPubKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		default:
			iNdEx = preIndex
			skippy, err := skipBase(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthBase
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryPubKeyResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowBase
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryPubKeyResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryPubKeyResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PubKey", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowBase
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthBase
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthBase
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.PubKey == nil {
				m.PubKey = &any.Any{}
			}
			if err := m.PubKey.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipBase(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthBase
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipBase(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowBase
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowBase
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowBase
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthBase
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupBase
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthBase
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthBase        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowBase          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupBase = fmt.Errorf("proto: unexpected end of group")
)

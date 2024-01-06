//
// This protobuf file contains the definition of the public API endpoints as
// well as messages. All client implementations should use this reference
// protobuf to implement a compatible drand client.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.20.3
// source: drand/api.proto

package drand

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// PublicRandRequest requests a public random value that has been generated in a
// unbiasable way and verifiable.
type PublicRandRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// round uniquely identifies a beacon. If round == 0 (or unspecified), then
	// the response will contain the last.
	Round    uint64    `protobuf:"varint,1,opt,name=round,proto3" json:"round,omitempty"`
	Metadata *Metadata `protobuf:"bytes,2,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *PublicRandRequest) Reset() {
	*x = PublicRandRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_drand_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublicRandRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicRandRequest) ProtoMessage() {}

func (x *PublicRandRequest) ProtoReflect() protoreflect.Message {
	mi := &file_drand_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicRandRequest.ProtoReflect.Descriptor instead.
func (*PublicRandRequest) Descriptor() ([]byte, []int) {
	return file_drand_api_proto_rawDescGZIP(), []int{0}
}

func (x *PublicRandRequest) GetRound() uint64 {
	if x != nil {
		return x.Round
	}
	return 0
}

func (x *PublicRandRequest) GetMetadata() *Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

// PublicRandResponse holds a signature which is the random value. It can be
// verified thanks to the distributed public key of the nodes that have ran the
// DKG protocol and is unbiasable. The randomness can be verified using the BLS
// verification routine with the message "round || previous_rand".
type PublicRandResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Round             uint64 `protobuf:"varint,1,opt,name=round,proto3" json:"round,omitempty"`
	Signature         []byte `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
	PreviousSignature []byte `protobuf:"bytes,3,opt,name=previous_signature,json=previousSignature,proto3" json:"previous_signature,omitempty"`
	// randomness is simply there to demonstrate - it is the hash of the
	// signature. It should be computed locally.
	//
	// Deprecated: Marked as deprecated in drand/api.proto.
	Randomness []byte    `protobuf:"bytes,4,opt,name=randomness,proto3" json:"randomness,omitempty"`
	Metadata   *Metadata `protobuf:"bytes,5,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *PublicRandResponse) Reset() {
	*x = PublicRandResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_drand_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublicRandResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicRandResponse) ProtoMessage() {}

func (x *PublicRandResponse) ProtoReflect() protoreflect.Message {
	mi := &file_drand_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicRandResponse.ProtoReflect.Descriptor instead.
func (*PublicRandResponse) Descriptor() ([]byte, []int) {
	return file_drand_api_proto_rawDescGZIP(), []int{1}
}

func (x *PublicRandResponse) GetRound() uint64 {
	if x != nil {
		return x.Round
	}
	return 0
}

func (x *PublicRandResponse) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *PublicRandResponse) GetPreviousSignature() []byte {
	if x != nil {
		return x.PreviousSignature
	}
	return nil
}

// Deprecated: Marked as deprecated in drand/api.proto.
func (x *PublicRandResponse) GetRandomness() []byte {
	if x != nil {
		return x.Randomness
	}
	return nil
}

func (x *PublicRandResponse) GetMetadata() *Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

type HomeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metadata *Metadata `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *HomeRequest) Reset() {
	*x = HomeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_drand_api_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HomeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HomeRequest) ProtoMessage() {}

func (x *HomeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_drand_api_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HomeRequest.ProtoReflect.Descriptor instead.
func (*HomeRequest) Descriptor() ([]byte, []int) {
	return file_drand_api_proto_rawDescGZIP(), []int{2}
}

func (x *HomeRequest) GetMetadata() *Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

type HomeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status   string    `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	Metadata *Metadata `protobuf:"bytes,2,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *HomeResponse) Reset() {
	*x = HomeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_drand_api_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HomeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HomeResponse) ProtoMessage() {}

func (x *HomeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_drand_api_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HomeResponse.ProtoReflect.Descriptor instead.
func (*HomeResponse) Descriptor() ([]byte, []int) {
	return file_drand_api_proto_rawDescGZIP(), []int{3}
}

func (x *HomeResponse) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

func (x *HomeResponse) GetMetadata() *Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

var File_drand_api_proto protoreflect.FileDescriptor

var file_drand_api_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2f, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x05, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x1a, 0x12, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2f,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x56, 0x0a, 0x11,
	0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x14, 0x0a, 0x05, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x05, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x12, 0x2b, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64,
	0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x64, 0x72, 0x61, 0x6e,
	0x64, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x22, 0xc8, 0x01, 0x0a, 0x12, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x52,
	0x61, 0x6e, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x72,
	0x6f, 0x75, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x72, 0x6f, 0x75, 0x6e,
	0x64, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12,
	0x2d, 0x0a, 0x12, 0x70, 0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x11, 0x70, 0x72, 0x65,
	0x76, 0x69, 0x6f, 0x75, 0x73, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x22,
	0x0a, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x6e, 0x65, 0x73, 0x73, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0c, 0x42, 0x02, 0x18, 0x01, 0x52, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x6e, 0x65,
	0x73, 0x73, 0x12, 0x2b, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2e, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x22,
	0x3a, 0x0a, 0x0b, 0x48, 0x6f, 0x6d, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2b,
	0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0f, 0x2e, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x22, 0x53, 0x0a, 0x0c, 0x48,
	0x6f, 0x6d, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x12, 0x2b, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2e, 0x4d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x32, 0x85, 0x02, 0x0a, 0x06, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x12, 0x41, 0x0a, 0x0a, 0x50,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x52, 0x61, 0x6e, 0x64, 0x12, 0x18, 0x2e, 0x64, 0x72, 0x61, 0x6e,
	0x64, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2e, 0x50, 0x75, 0x62, 0x6c,
	0x69, 0x63, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x49,
	0x0a, 0x10, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x52, 0x61, 0x6e, 0x64, 0x53, 0x74, 0x72, 0x65,
	0x61, 0x6d, 0x12, 0x18, 0x2e, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x64,
	0x72, 0x61, 0x6e, 0x64, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x52, 0x61, 0x6e, 0x64, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x3c, 0x0a, 0x09, 0x43, 0x68, 0x61,
	0x69, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x17, 0x2e, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2e, 0x43,
	0x68, 0x61, 0x69, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x16, 0x2e, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2e, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x6e, 0x66,
	0x6f, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x2f, 0x0a, 0x04, 0x48, 0x6f, 0x6d, 0x65, 0x12,
	0x12, 0x2e, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2e, 0x48, 0x6f, 0x6d, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2e, 0x48, 0x6f, 0x6d, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x27, 0x5a, 0x25, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64, 0x72, 0x61, 0x6e, 0x64, 0x2f, 0x64, 0x72, 0x61,
	0x6e, 0x64, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x72, 0x61, 0x6e,
	0x64, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_drand_api_proto_rawDescOnce sync.Once
	file_drand_api_proto_rawDescData = file_drand_api_proto_rawDesc
)

func file_drand_api_proto_rawDescGZIP() []byte {
	file_drand_api_proto_rawDescOnce.Do(func() {
		file_drand_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_drand_api_proto_rawDescData)
	})
	return file_drand_api_proto_rawDescData
}

var file_drand_api_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_drand_api_proto_goTypes = []interface{}{
	(*PublicRandRequest)(nil),  // 0: drand.PublicRandRequest
	(*PublicRandResponse)(nil), // 1: drand.PublicRandResponse
	(*HomeRequest)(nil),        // 2: drand.HomeRequest
	(*HomeResponse)(nil),       // 3: drand.HomeResponse
	(*Metadata)(nil),           // 4: drand.Metadata
	(*ChainInfoRequest)(nil),   // 5: drand.ChainInfoRequest
	(*ChainInfoPacket)(nil),    // 6: drand.ChainInfoPacket
}
var file_drand_api_proto_depIdxs = []int32{
	4, // 0: drand.PublicRandRequest.metadata:type_name -> drand.Metadata
	4, // 1: drand.PublicRandResponse.metadata:type_name -> drand.Metadata
	4, // 2: drand.HomeRequest.metadata:type_name -> drand.Metadata
	4, // 3: drand.HomeResponse.metadata:type_name -> drand.Metadata
	0, // 4: drand.Public.PublicRand:input_type -> drand.PublicRandRequest
	0, // 5: drand.Public.PublicRandStream:input_type -> drand.PublicRandRequest
	5, // 6: drand.Public.ChainInfo:input_type -> drand.ChainInfoRequest
	2, // 7: drand.Public.Home:input_type -> drand.HomeRequest
	1, // 8: drand.Public.PublicRand:output_type -> drand.PublicRandResponse
	1, // 9: drand.Public.PublicRandStream:output_type -> drand.PublicRandResponse
	6, // 10: drand.Public.ChainInfo:output_type -> drand.ChainInfoPacket
	3, // 11: drand.Public.Home:output_type -> drand.HomeResponse
	8, // [8:12] is the sub-list for method output_type
	4, // [4:8] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_drand_api_proto_init() }
func file_drand_api_proto_init() {
	if File_drand_api_proto != nil {
		return
	}
	file_drand_common_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_drand_api_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublicRandRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_drand_api_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublicRandResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_drand_api_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HomeRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_drand_api_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HomeResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_drand_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_drand_api_proto_goTypes,
		DependencyIndexes: file_drand_api_proto_depIdxs,
		MessageInfos:      file_drand_api_proto_msgTypes,
	}.Build()
	File_drand_api_proto = out.File
	file_drand_api_proto_rawDesc = nil
	file_drand_api_proto_goTypes = nil
	file_drand_api_proto_depIdxs = nil
}

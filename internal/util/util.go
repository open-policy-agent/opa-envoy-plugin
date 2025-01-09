package util

import (
	"os"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// ReadProtoSet - Reads protobuf files from disk
func ReadProtoSet(path string) (*protoregistry.Files, error) {
	protoSet, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fileSet descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(protoSet, &fileSet); err != nil {
		return nil, err
	}
	return protodesc.NewFiles(&fileSet)
}

package util

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

//ReadProtoSet - Reads protobuf files from disk
func ReadProtoSet(path string) (*protoregistry.Files, error) {
	protoSet, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fileSet descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(protoSet, &fileSet); err != nil {
		return nil, err
	}
	return protodesc.NewFiles(&fileSet)
}

//UUID4 Generates a new universally unique identifier
func UUID4() (string, error) {
	bs := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, bs)
	if n != len(bs) || err != nil {
		return "", err
	}
	bs[8] = bs[8]&^0xc0 | 0x80
	bs[6] = bs[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", bs[0:4], bs[4:6], bs[6:8], bs[8:10], bs[10:]), nil
}

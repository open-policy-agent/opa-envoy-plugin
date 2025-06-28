package envoyauth

import (
	"google.golang.org/protobuf/reflect/protoreflect"
)

type valueResolver func(protoreflect.Value) any

func messageResolver(v protoreflect.Value) any {
	return protomap(v.Message())
}

func interfaceResolver(v protoreflect.Value) any {
	return v.Interface()
}

func chooseResolver(k protoreflect.Kind) valueResolver {
	if k == protoreflect.MessageKind {
		return messageResolver
	}
	return interfaceResolver
}

// protomap converts protobuf message into map[string]any type using json names.
func protomap(msg protoreflect.Message) map[string]any {
	v := msg.Interface()
	// handle structpb.Struct
	if mapper, ok := v.(interface{ AsMap() map[string]any }); ok {
		return mapper.AsMap()
	}

	result := make(map[string]any, msg.Descriptor().Fields().Len())

	msg.Range(func(fd protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		name := fd.JSONName()

		switch {
		case fd.IsMap():
			mapValue := value.Map()
			mapResult := make(map[string]any, mapValue.Len())
			valResolver := chooseResolver(fd.MapValue().Kind())
			mapValue.Range(func(key protoreflect.MapKey, val protoreflect.Value) bool {
				mapResult[key.String()] = valResolver(val)
				return true
			})
			result[name] = mapResult
		case fd.IsList():
			list := value.List()
			listResult := make([]any, list.Len())
			valResolver := chooseResolver(fd.Kind())
			for i := range list.Len() {
				listResult[i] = valResolver(list.Get(i))
			}
			result[name] = listResult
		case fd.Kind() == protoreflect.MessageKind:
			result[name] = protomap(value.Message())
		default:
			result[name] = value.Interface()
		}

		return true
	})

	return result
}

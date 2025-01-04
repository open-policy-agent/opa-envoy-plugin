package envoyauth

import (
	"google.golang.org/protobuf/reflect/protoreflect"
)

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
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				mapValue.Range(func(key protoreflect.MapKey, val protoreflect.Value) bool {
					mapResult[key.String()] = protomap(val.Message())
					return true
				})
			} else {
				mapValue.Range(func(key protoreflect.MapKey, val protoreflect.Value) bool {
					mapResult[key.String()] = val.Interface()
					return true
				})
			}
			result[name] = mapResult

		case fd.IsList():
			list := value.List()
			listResult := make([]any, list.Len())
			for i := 0; i < list.Len(); i++ {
				elem := list.Get(i)
				if fd.Kind() == protoreflect.MessageKind {
					listResult[i] = protomap(elem.Message())
				} else {
					listResult[i] = elem.Interface()
				}
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

package envoy.authz

default allow = false

allow {
  # for test.KitchenSink/Ping, we don't require anything
  input.parsed_path = ["test.KitchenSink", "Ping"]
}

allow {
  input.parsed_path = ["test.KitchenSink", "Exchange"]
  input.parsed_body = {
    "neededNumA": 1.23,
    "neededNumB": 1.23,
    "opaqueId": "asdf",
    "person": {
      "id": "123",
      "name": "alice",
      "parent": {
        "id": "122",
        "name": "bob"
      }
    },
    "state": "AWAITING_INPUT",
    "wk": {
      "bigId": "101",
      "bigInt": "2",
      "bool": true,
      "bytes": "AAAA",
      "double": 0.12,
      "float": 0.12,
      "list": [
        "zero",
        "one",
        "infinity"
      ],
      "neat": {
        "@type": "googleapis.com/google.protobuf.StringValue",
        "value": "Hithere"
      },
      "now": "2020-12-02T09:48:42.118723Z",
      "object": {
        "foo": "bar"
      },
      "period": "30s",
      "smallId": 100,
      "smallInt": 1,
      "string": "abcd",
      "value": "string"
    }
  }
}


package ext_proc

# Default response is an empty object
default response = {}

# Immediate response with custom status code, body, and headers
response = {
    "immediate_response": {
        "status": 403,
        "body": "Access Denied",
        "headers": [
            {"key": "Content-Type", "value": "text/plain"},
            {"key": "X-Immediate-Response", "value": "True"}
        ],
        "grpc_status": 7,  # PERMISSION_DENIED
        "details": "Unauthorized access attempt"
    }
} {
    input.path == "/forbidden"
}

# Add headers to the request or response
response = {
    "headers_to_add": [
        {
            "key": "X-Added-Header",
            "value": "HeaderValue",
            "header_append_action": "OVERWRITE_IF_EXISTS_OR_ADD"
        }
    ]
} {
    input.path == "/add-headers"
}

# Remove headers from the request or response
response = {
    "headers_to_remove": [
        "X-Remove-Header",
        "X-Another-Header"
    ]
} {
    input.path == "/remove-headers"
}

# Replace the body of the request or response
response = {
    "body": "This is the new body content"
} {
    input.request_type == "request_body"
    input.path == "/replace-body"
}

# Provide dynamic metadata
response = {
    "dynamic_metadata": {
        "my_extension": {
            "user_id": input.headers["x-user-id"],
            "session_id": input.headers["x-session-id"]
        }
    }
} {
    input.path == "/dynamic-metadata"
}

# Combine header mutation and body replacement
response = {
    "headers_to_add": [
        {
            "key": "X-Combined-Header",
            "value": "CombinedValue"
        }
    ],
    "body": "Combined response with headers and body changes"
} {
    input.path == "/combined"
}

# Handle request trailers
response = {
    "trailers_to_add": [
        {
            "key": "X-Trailer-Added",
            "value": "TrailerValue"
        }
    ]
} {
    input.request_type == "request_trailers"
    input.path == "/modify-trailers"
}

# Handle response headers
response = {
    "headers_to_add": [
        {
            "key": "X-Response-Header",
            "value": "ResponseHeaderValue"
        }
    ]
} {
    input.request_type == "response_headers"
    input.path == "/modify-response-headers"
}

# Deny all other requests by default with an immediate response
response = {
    "immediate_response": {
        "status": 403,
        "body": "Default Deny",
        "headers": [
            {"key": "Content-Type", "value": "text/plain"},
            {"key": "X-Default-Deny", "value": "True"}
        ]
    }
} {
    not allowed_paths[input.path]
}

allowed_paths = {
    "/forbidden",
    "/add-headers",
    "/remove-headers",
    "/replace-body",
    "/dynamic-metadata",
    "/combined",
    "/modify-trailers",
    "/modify-response-headers"
}

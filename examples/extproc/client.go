package main

import (
	"context"
	"flag"
	"io"
	"log"
	"time"

	base "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:9292", "Address of the ext_proc server")
	testCase := flag.String("test_case", "add_headers", "Test case to run")
	flag.Parse()

	conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Set a context with timeout for the stream
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := ext_proc_v3.NewExternalProcessorClient(conn)
	stream, err := client.Process(ctx)
	if err != nil {
		log.Fatalf("Failed to create stream: %v", err)
	}

	// Construct the ProcessingRequest message based on the test case
	var request *ext_proc_v3.ProcessingRequest

	switch *testCase {
	case "forbidden":
		// Test Immediate Response
		request = &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_proc_v3.HttpHeaders{
					Headers: &base.HeaderMap{
						Headers: []*base.HeaderValue{
							{Key: ":method", Value: "GET"},
							{Key: ":path", Value: "/forbidden"},
						},
					},
				},
			},
		}
	case "add_headers":
		// Test Header Mutation - Add Headers
		request = &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_proc_v3.HttpHeaders{
					Headers: &base.HeaderMap{
						Headers: []*base.HeaderValue{
							{Key: ":method", Value: "GET"},
							{Key: ":path", Value: "/add-headers"},
						},
					},
				},
			},
		}
	case "remove_headers":
		// Test Header Mutation - Remove Headers
		request = &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_proc_v3.HttpHeaders{
					Headers: &base.HeaderMap{
						Headers: []*base.HeaderValue{
							{Key: ":method", Value: "GET"},
							{Key: ":path", Value: "/remove-headers"},
							{Key: "X-Remove-Header", Value: "ValueToRemove"},
							{Key: "X-Another-Header", Value: "AnotherValue"},
						},
					},
				},
			},
		}
	case "replace_body":
		requestHeaders := &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_proc_v3.HttpHeaders{
					Headers: &base.HeaderMap{
						Headers: []*base.HeaderValue{
							{Key: ":method", Value: "POST"},
							{Key: ":path", Value: "/replace-body"},
							{Key: "content-type", Value: "application/json"}, // Added Content-Type
						},
					},
				},
			},
		}
		if err := stream.Send(requestHeaders); err != nil {
			log.Fatalf("Failed to send request headers: %v", err)
		}
		log.Println("Sent RequestHeaders")
		receiveResponse(stream)

		// Now send RequestBody
		jsonBody := `{"key": "value"}`
		log.Printf("Sending RequestBody: %s", jsonBody) // Log the body being sent
		request = &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_RequestBody{
				RequestBody: &ext_proc_v3.HttpBody{
					Body:        []byte(jsonBody), // JSON body
					EndOfStream: true,
				},
			},
		}
		if err := stream.Send(request); err != nil {
			log.Fatalf("Failed to send request body: %v", err)
		}
		log.Println("Sent RequestBody")
		receiveResponse(stream)
	case "dynamic_metadata":
		// Test Dynamic Metadata
		request = &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_proc_v3.HttpHeaders{
					Headers: &base.HeaderMap{
						Headers: []*base.HeaderValue{
							{Key: ":method", Value: "GET"},
							{Key: ":path", Value: "/dynamic-metadata"},
							{Key: "x-user-id", Value: "12345"},
							{Key: "x-session-id", Value: "abcde-12345"},
						},
					},
				},
			},
		}
	case "combined":
		// Test Combined Header and Body Mutation
		request = &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_proc_v3.HttpHeaders{
					Headers: &base.HeaderMap{
						Headers: []*base.HeaderValue{
							{Key: ":method", Value: "POST"},
							{Key: ":path", Value: "/combined"},
						},
					},
				},
			},
		}
	case "modify_trailers":
		// Test Request Trailers
		// Send RequestHeaders first
		requestHeaders := &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_RequestHeaders{
				RequestHeaders: &ext_proc_v3.HttpHeaders{
					Headers: &base.HeaderMap{
						Headers: []*base.HeaderValue{
							{Key: ":method", Value: "GET"},
							{Key: ":path", Value: "/modify-trailers"},
						},
					},
				},
			},
		}
		if err := stream.Send(requestHeaders); err != nil {
			log.Fatalf("Failed to send request headers: %v", err)
		}
		receiveResponse(stream)

		// Now send RequestTrailers
		request = &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_RequestTrailers{
				RequestTrailers: &ext_proc_v3.HttpTrailers{
					Trailers: &base.HeaderMap{
						Headers: []*base.HeaderValue{
							{Key: "original-trailer", Value: "original-value"},
						},
					},
				},
			},
		}
	case "modify_response_headers":
		// Test Response Headers
		request = &ext_proc_v3.ProcessingRequest{
			Request: &ext_proc_v3.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &ext_proc_v3.HttpHeaders{
					Headers: &base.HeaderMap{
						Headers: []*base.HeaderValue{
							{Key: ":status", Value: "200"},
							{Key: "Content-Type", Value: "text/plain"},
							{Key: ":path", Value: "/modify-response-headers"},
						},
					},
				},
			},
		}
	default:
		log.Fatalf("Unknown test case: %s", *testCase)
	}

	// Send the ProcessingRequest message
	if err := stream.Send(request); err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}

	receiveResponse(stream)

	// Close the stream
	if err := stream.CloseSend(); err != nil {
		log.Fatalf("Failed to close stream: %v", err)
	}
}

func receiveResponse(stream ext_proc_v3.ExternalProcessor_ProcessClient) {
	// Set a timeout context for receiving the response
	recvCtx, recvCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer recvCancel()

	responseCh := make(chan *ext_proc_v3.ProcessingResponse)
	errCh := make(chan error)

	go func() {
		response, err := stream.Recv()
		if err != nil {
			errCh <- err
		} else {
			responseCh <- response
		}
	}()

	select {
	case <-recvCtx.Done():
		log.Printf("No response received within timeout (possible observability mode)")
	case err := <-errCh:
		if err == io.EOF {
			log.Printf("Stream closed by server")
		} else if err == context.DeadlineExceeded {
			log.Printf("No response received (possible observability mode)")
		} else {
			log.Fatalf("Failed to receive response: %v", err)
		}
	case response := <-responseCh:
		processResponse(response)
	}
}

func processResponse(response *ext_proc_v3.ProcessingResponse) {
	if response == nil {
		log.Println("Received empty response")
		return
	}

	switch res := response.Response.(type) {
	case *ext_proc_v3.ProcessingResponse_RequestHeaders:
		log.Printf("Received RequestHeaders response")
		if res.RequestHeaders != nil && res.RequestHeaders.Response != nil {
			mutations := res.RequestHeaders.Response.HeaderMutation
			if mutations != nil {
				for _, setHeader := range mutations.SetHeaders {
					header := setHeader.GetHeader()
					log.Printf("Header to add: %s: %s", header.GetKey(), header.GetValue())
				}
				for _, removeHeader := range mutations.RemoveHeaders {
					log.Printf("Header to remove: %s", removeHeader)
				}
			}
			if res.RequestHeaders.Response.BodyMutation != nil {
				bodyMutation := res.RequestHeaders.Response.BodyMutation
				if body, ok := bodyMutation.Mutation.(*ext_proc_v3.BodyMutation_Body); ok {
					log.Printf("Body to replace: %s", string(body.Body))
				}
			}
		}
	case *ext_proc_v3.ProcessingResponse_RequestBody:
		log.Printf("Received RequestBody response")
		if res.RequestBody != nil && res.RequestBody.Response != nil {
			if res.RequestBody.Response.BodyMutation != nil {
				bodyMutation := res.RequestBody.Response.BodyMutation
				if body, ok := bodyMutation.Mutation.(*ext_proc_v3.BodyMutation_Body); ok {
					log.Printf("Body to replace: %s", string(body.Body))
				}
			}
		}
	case *ext_proc_v3.ProcessingResponse_RequestTrailers:
		log.Printf("Received RequestTrailers response")
		if res.RequestTrailers != nil {
			mutations := res.RequestTrailers.HeaderMutation
			if mutations != nil {
				for _, setHeader := range mutations.SetHeaders {
					header := setHeader.GetHeader()
					log.Printf("Trailer to add: %s: %s", header.GetKey(), header.GetValue())
				}
				for _, removeHeader := range mutations.RemoveHeaders {
					log.Printf("Trailer to remove: %s", removeHeader)
				}
			}
		}
	case *ext_proc_v3.ProcessingResponse_ResponseHeaders:
		log.Printf("Received ResponseHeaders response")
		if res.ResponseHeaders != nil && res.ResponseHeaders.Response != nil {
			mutations := res.ResponseHeaders.Response.HeaderMutation
			if mutations != nil {
				for _, setHeader := range mutations.SetHeaders {
					header := setHeader.GetHeader()
					log.Printf("Response header to add: %s: %s", header.GetKey(), header.GetValue())
				}
				for _, removeHeader := range mutations.RemoveHeaders {
					log.Printf("Response header to remove: %s", removeHeader)
				}
			}
			if res.ResponseHeaders.Response.BodyMutation != nil {
				bodyMutation := res.ResponseHeaders.Response.BodyMutation
				if body, ok := bodyMutation.Mutation.(*ext_proc_v3.BodyMutation_Body); ok {
					log.Printf("Response body to replace: %s", string(body.Body))
				}
			}
		}
	case *ext_proc_v3.ProcessingResponse_ImmediateResponse:
		log.Printf("Received ImmediateResponse")
		immediateResponse := res.ImmediateResponse
		if immediateResponse != nil {
			status := immediateResponse.Status
			if status != nil {
				statusCode := int32(status.Code)
				log.Printf("Immediate response status: %d", statusCode)
			} else {
				log.Printf("Immediate response status: nil")
			}
			body := immediateResponse.Body
			log.Printf("Immediate response body: %s", string(body))
			if immediateResponse.Headers != nil {
				for _, setHeader := range immediateResponse.Headers.SetHeaders {
					header := setHeader.GetHeader()
					log.Printf("Immediate response header: %s: %s", header.GetKey(), header.GetValue())
				}
			}
		}
	default:
		log.Printf("Received unknown response type: %v", response)
	}

	// Handle DynamicMetadata if present
	if response.DynamicMetadata != nil {
		log.Printf("Received Dynamic Metadata:")
		for k, v := range response.DynamicMetadata.Fields {
			log.Printf("  %s: %v", k, v)
		}
	}
}

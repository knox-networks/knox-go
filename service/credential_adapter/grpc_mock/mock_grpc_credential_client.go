// Code generated by MockGen. DO NOT EDIT.
// Source: go.buf.build/grpc/go/knox-networks/credential-adapter/adapter_api/v1 (interfaces: AdapterServiceClient)

// Package grpc_mock is a generated GoMock package.
package grpc_mock

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	adapter_apiv1 "go.buf.build/grpc/go/knox-networks/credential-adapter/adapter_api/v1"
	grpc "google.golang.org/grpc"
)

// MockAdapterServiceClient is a mock of AdapterServiceClient interface.
type MockAdapterServiceClient struct {
	ctrl     *gomock.Controller
	recorder *MockAdapterServiceClientMockRecorder
}

// MockAdapterServiceClientMockRecorder is the mock recorder for MockAdapterServiceClient.
type MockAdapterServiceClientMockRecorder struct {
	mock *MockAdapterServiceClient
}

// NewMockAdapterServiceClient creates a new mock instance.
func NewMockAdapterServiceClient(ctrl *gomock.Controller) *MockAdapterServiceClient {
	mock := &MockAdapterServiceClient{ctrl: ctrl}
	mock.recorder = &MockAdapterServiceClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAdapterServiceClient) EXPECT() *MockAdapterServiceClientMockRecorder {
	return m.recorder
}

// CreateIssuanceChallenge mocks base method.
func (m *MockAdapterServiceClient) CreateIssuanceChallenge(arg0 context.Context, arg1 *adapter_apiv1.CreateIssuanceChallengeRequest, arg2 ...grpc.CallOption) (*adapter_apiv1.CreateIssuanceChallengeResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateIssuanceChallenge", varargs...)
	ret0, _ := ret[0].(*adapter_apiv1.CreateIssuanceChallengeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateIssuanceChallenge indicates an expected call of CreateIssuanceChallenge.
func (mr *MockAdapterServiceClientMockRecorder) CreateIssuanceChallenge(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateIssuanceChallenge", reflect.TypeOf((*MockAdapterServiceClient)(nil).CreateIssuanceChallenge), varargs...)
}

// CreatePresentationChallenge mocks base method.
func (m *MockAdapterServiceClient) CreatePresentationChallenge(arg0 context.Context, arg1 *adapter_apiv1.CreatePresentationChallengeRequest, arg2 ...grpc.CallOption) (*adapter_apiv1.CreatePresentationChallengeResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreatePresentationChallenge", varargs...)
	ret0, _ := ret[0].(*adapter_apiv1.CreatePresentationChallengeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreatePresentationChallenge indicates an expected call of CreatePresentationChallenge.
func (mr *MockAdapterServiceClientMockRecorder) CreatePresentationChallenge(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePresentationChallenge", reflect.TypeOf((*MockAdapterServiceClient)(nil).CreatePresentationChallenge), varargs...)
}

// IssueVerifiableCredential mocks base method.
func (m *MockAdapterServiceClient) IssueVerifiableCredential(arg0 context.Context, arg1 *adapter_apiv1.IssueVerifiableCredentialRequest, arg2 ...grpc.CallOption) (*adapter_apiv1.IssueVerifiableCredentialResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "IssueVerifiableCredential", varargs...)
	ret0, _ := ret[0].(*adapter_apiv1.IssueVerifiableCredentialResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IssueVerifiableCredential indicates an expected call of IssueVerifiableCredential.
func (mr *MockAdapterServiceClientMockRecorder) IssueVerifiableCredential(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IssueVerifiableCredential", reflect.TypeOf((*MockAdapterServiceClient)(nil).IssueVerifiableCredential), varargs...)
}

// PresentVerifiableCredential mocks base method.
func (m *MockAdapterServiceClient) PresentVerifiableCredential(arg0 context.Context, arg1 *adapter_apiv1.PresentVerifiableCredentialRequest, arg2 ...grpc.CallOption) (*adapter_apiv1.PresentVerifiableCredentialResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "PresentVerifiableCredential", varargs...)
	ret0, _ := ret[0].(*adapter_apiv1.PresentVerifiableCredentialResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PresentVerifiableCredential indicates an expected call of PresentVerifiableCredential.
func (mr *MockAdapterServiceClientMockRecorder) PresentVerifiableCredential(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PresentVerifiableCredential", reflect.TypeOf((*MockAdapterServiceClient)(nil).PresentVerifiableCredential), varargs...)
}

// WaitForCompletion mocks base method.
func (m *MockAdapterServiceClient) WaitForCompletion(arg0 context.Context, arg1 *adapter_apiv1.WaitForCompletionRequest, arg2 ...grpc.CallOption) (adapter_apiv1.AdapterService_WaitForCompletionClient, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "WaitForCompletion", varargs...)
	ret0, _ := ret[0].(adapter_apiv1.AdapterService_WaitForCompletionClient)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WaitForCompletion indicates an expected call of WaitForCompletion.
func (mr *MockAdapterServiceClientMockRecorder) WaitForCompletion(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WaitForCompletion", reflect.TypeOf((*MockAdapterServiceClient)(nil).WaitForCompletion), varargs...)
}

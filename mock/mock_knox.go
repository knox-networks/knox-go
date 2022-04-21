// Code generated by MockGen. DO NOT EDIT.
// Source: knox.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	knox "github.com/knox-networks/knox-go"
	credential_adapter "github.com/knox-networks/knox-go/credential_adapter"
)

// MockKnoxClient is a mock of KnoxClient interface.
type MockKnoxClient struct {
	ctrl     *gomock.Controller
	recorder *MockKnoxClientMockRecorder
}

// MockKnoxClientMockRecorder is the mock recorder for MockKnoxClient.
type MockKnoxClientMockRecorder struct {
	mock *MockKnoxClient
}

// NewMockKnoxClient creates a new mock instance.
func NewMockKnoxClient(ctrl *gomock.Controller) *MockKnoxClient {
	mock := &MockKnoxClient{ctrl: ctrl}
	mock.recorder = &MockKnoxClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockKnoxClient) EXPECT() *MockKnoxClientMockRecorder {
	return m.recorder
}

// GenerateIdentity mocks base method.
func (m *MockKnoxClient) GenerateIdentity(arg0 knox.GenerateIdentityParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateIdentity", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// GenerateIdentity indicates an expected call of GenerateIdentity.
func (mr *MockKnoxClientMockRecorder) GenerateIdentity(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateIdentity", reflect.TypeOf((*MockKnoxClient)(nil).GenerateIdentity), arg0)
}

// RegisterIdentity mocks base method.
func (m *MockKnoxClient) RegisterIdentity(arg0 knox.RegisterIdentityParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterIdentity", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RegisterIdentity indicates an expected call of RegisterIdentity.
func (mr *MockKnoxClientMockRecorder) RegisterIdentity(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterIdentity", reflect.TypeOf((*MockKnoxClient)(nil).RegisterIdentity), arg0)
}

// RequestCredential mocks base method.
func (m *MockKnoxClient) RequestCredential(arg0 knox.RequestCredentialParams) (credential_adapter.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestCredential", arg0)
	ret0, _ := ret[0].(credential_adapter.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RequestCredential indicates an expected call of RequestCredential.
func (mr *MockKnoxClientMockRecorder) RequestCredential(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestCredential", reflect.TypeOf((*MockKnoxClient)(nil).RequestCredential), arg0)
}

// RequestPresentation mocks base method.
func (m *MockKnoxClient) RequestPresentation(arg0 knox.RequestPresentationParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RequestPresentation", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RequestPresentation indicates an expected call of RequestPresentation.
func (mr *MockKnoxClientMockRecorder) RequestPresentation(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RequestPresentation", reflect.TypeOf((*MockKnoxClient)(nil).RequestPresentation), arg0)
}

// SharePresentation mocks base method.
func (m *MockKnoxClient) SharePresentation(arg0 knox.SharePresentationParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SharePresentation", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SharePresentation indicates an expected call of SharePresentation.
func (mr *MockKnoxClientMockRecorder) SharePresentation(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SharePresentation", reflect.TypeOf((*MockKnoxClient)(nil).SharePresentation), arg0)
}

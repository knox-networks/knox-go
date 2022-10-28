// Code generated by MockGen. DO NOT EDIT.
// Source: ./service/auth_client/auth_client.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	model "github.com/knox-networks/knox-go/model"
	auth_client "github.com/knox-networks/knox-go/service/auth_client"
)

// MockStreamClient is a mock of StreamClient interface.
type MockStreamClient struct {
	ctrl     *gomock.Controller
	recorder *MockStreamClientMockRecorder
}

// MockStreamClientMockRecorder is the mock recorder for MockStreamClient.
type MockStreamClientMockRecorder struct {
	mock *MockStreamClient
}

// NewMockStreamClient creates a new mock instance.
func NewMockStreamClient(ctrl *gomock.Controller) *MockStreamClient {
	mock := &MockStreamClient{ctrl: ctrl}
	mock.recorder = &MockStreamClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStreamClient) EXPECT() *MockStreamClientMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockStreamClient) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockStreamClientMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockStreamClient)(nil).Close))
}

// WaitForCompletion mocks base method.
func (m *MockStreamClient) WaitForCompletion() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WaitForCompletion")
	ret0, _ := ret[0].(error)
	return ret0
}

// WaitForCompletion indicates an expected call of WaitForCompletion.
func (mr *MockStreamClientMockRecorder) WaitForCompletion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WaitForCompletion", reflect.TypeOf((*MockStreamClient)(nil).WaitForCompletion))
}

// MockAuthClient is a mock of AuthClient interface.
type MockAuthClient struct {
	ctrl     *gomock.Controller
	recorder *MockAuthClientMockRecorder
}

// MockAuthClientMockRecorder is the mock recorder for MockAuthClient.
type MockAuthClientMockRecorder struct {
	mock *MockAuthClient
}

// NewMockAuthClient creates a new mock instance.
func NewMockAuthClient(ctrl *gomock.Controller) *MockAuthClient {
	mock := &MockAuthClient{ctrl: ctrl}
	mock.recorder = &MockAuthClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthClient) EXPECT() *MockAuthClientMockRecorder {
	return m.recorder
}

// AuthenticateWithDid mocks base method.
func (m *MockAuthClient) AuthenticateWithDid(did, nonce string, signature []byte) (*model.AuthToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticateWithDid", did, nonce, signature)
	ret0, _ := ret[0].(*model.AuthToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateWithDid indicates an expected call of AuthenticateWithDid.
func (mr *MockAuthClientMockRecorder) AuthenticateWithDid(did, nonce, signature interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateWithDid", reflect.TypeOf((*MockAuthClient)(nil).AuthenticateWithDid), did, nonce, signature)
}

// AuthenticateWithPassword mocks base method.
func (m *MockAuthClient) AuthenticateWithPassword(email, password string) (*model.AuthToken, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthenticateWithPassword", email, password)
	ret0, _ := ret[0].(*model.AuthToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthenticateWithPassword indicates an expected call of AuthenticateWithPassword.
func (mr *MockAuthClientMockRecorder) AuthenticateWithPassword(email, password interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthenticateWithPassword", reflect.TypeOf((*MockAuthClient)(nil).AuthenticateWithPassword), email, password)
}

// AuthnWithDidRegister mocks base method.
func (m *MockAuthClient) AuthnWithDidRegister(did, nonce string, enc []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthnWithDidRegister", did, nonce, enc)
	ret0, _ := ret[0].(error)
	return ret0
}

// AuthnWithDidRegister indicates an expected call of AuthnWithDidRegister.
func (mr *MockAuthClientMockRecorder) AuthnWithDidRegister(did, nonce, enc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthnWithDidRegister", reflect.TypeOf((*MockAuthClient)(nil).AuthnWithDidRegister), did, nonce, enc)
}

// Close mocks base method.
func (m *MockAuthClient) Close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close")
}

// Close indicates an expected call of Close.
func (mr *MockAuthClientMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockAuthClient)(nil).Close))
}

// CreateDidAuthenticationChallenge mocks base method.
func (m *MockAuthClient) CreateDidAuthenticationChallenge(did string) (*auth_client.DidAuthenticationChallenge, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateDidAuthenticationChallenge", did)
	ret0, _ := ret[0].(*auth_client.DidAuthenticationChallenge)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateDidAuthenticationChallenge indicates an expected call of CreateDidAuthenticationChallenge.
func (mr *MockAuthClientMockRecorder) CreateDidAuthenticationChallenge(did interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateDidAuthenticationChallenge", reflect.TypeOf((*MockAuthClient)(nil).CreateDidAuthenticationChallenge), did)
}

// CreateDidRegistrationChallenge mocks base method.
func (m *MockAuthClient) CreateDidRegistrationChallenge(auth_token string) (*auth_client.DidRegistrationChallenge, auth_client.StreamClient, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateDidRegistrationChallenge", auth_token)
	ret0, _ := ret[0].(*auth_client.DidRegistrationChallenge)
	ret1, _ := ret[1].(auth_client.StreamClient)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateDidRegistrationChallenge indicates an expected call of CreateDidRegistrationChallenge.
func (mr *MockAuthClientMockRecorder) CreateDidRegistrationChallenge(auth_token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateDidRegistrationChallenge", reflect.TypeOf((*MockAuthClient)(nil).CreateDidRegistrationChallenge), auth_token)
}

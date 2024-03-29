// Code generated by MockGen. DO NOT EDIT.
// Source: ./service/credential_adapter/credential_adapter.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	credential_adapter "github.com/knox-networks/knox-go/service/credential_adapter"
)

// MockCredentialAdapterClient is a mock of CredentialAdapterClient interface.
type MockCredentialAdapterClient struct {
	ctrl     *gomock.Controller
	recorder *MockCredentialAdapterClientMockRecorder
}

// MockCredentialAdapterClientMockRecorder is the mock recorder for MockCredentialAdapterClient.
type MockCredentialAdapterClientMockRecorder struct {
	mock *MockCredentialAdapterClient
}

// NewMockCredentialAdapterClient creates a new mock instance.
func NewMockCredentialAdapterClient(ctrl *gomock.Controller) *MockCredentialAdapterClient {
	mock := &MockCredentialAdapterClient{ctrl: ctrl}
	mock.recorder = &MockCredentialAdapterClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCredentialAdapterClient) EXPECT() *MockCredentialAdapterClientMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockCredentialAdapterClient) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockCredentialAdapterClientMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockCredentialAdapterClient)(nil).Close))
}

// CreateIssuanceChallenge mocks base method.
func (m *MockCredentialAdapterClient) CreateIssuanceChallenge(cred_type, did, auth_token string) (credential_adapter.IssuanceChallenge, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateIssuanceChallenge", cred_type, did, auth_token)
	ret0, _ := ret[0].(credential_adapter.IssuanceChallenge)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateIssuanceChallenge indicates an expected call of CreateIssuanceChallenge.
func (mr *MockCredentialAdapterClientMockRecorder) CreateIssuanceChallenge(cred_type, did, auth_token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateIssuanceChallenge", reflect.TypeOf((*MockCredentialAdapterClient)(nil).CreateIssuanceChallenge), cred_type, did, auth_token)
}

// CreatePresentationChallenge mocks base method.
func (m *MockCredentialAdapterClient) CreatePresentationChallenge(credTypes []string) (*credential_adapter.PresentationChallenge, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePresentationChallenge", credTypes)
	ret0, _ := ret[0].(*credential_adapter.PresentationChallenge)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreatePresentationChallenge indicates an expected call of CreatePresentationChallenge.
func (mr *MockCredentialAdapterClientMockRecorder) CreatePresentationChallenge(credTypes interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePresentationChallenge", reflect.TypeOf((*MockCredentialAdapterClient)(nil).CreatePresentationChallenge), credTypes)
}

// IssueVerifiableCredential mocks base method.
func (m *MockCredentialAdapterClient) IssueVerifiableCredential(cred_type, did, nonce string, signature []byte, auth_token string) (credential_adapter.VerifiableCredential, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IssueVerifiableCredential", cred_type, did, nonce, signature, auth_token)
	ret0, _ := ret[0].(credential_adapter.VerifiableCredential)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IssueVerifiableCredential indicates an expected call of IssueVerifiableCredential.
func (mr *MockCredentialAdapterClientMockRecorder) IssueVerifiableCredential(cred_type, did, nonce, signature, auth_token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IssueVerifiableCredential", reflect.TypeOf((*MockCredentialAdapterClient)(nil).IssueVerifiableCredential), cred_type, did, nonce, signature, auth_token)
}

// PresentVerifiableCredential mocks base method.
func (m *MockCredentialAdapterClient) PresentVerifiableCredential(vp map[string]interface{}, did, nonce string, signature []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PresentVerifiableCredential", vp, did, nonce, signature)
	ret0, _ := ret[0].(error)
	return ret0
}

// PresentVerifiableCredential indicates an expected call of PresentVerifiableCredential.
func (mr *MockCredentialAdapterClientMockRecorder) PresentVerifiableCredential(vp, did, nonce, signature interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PresentVerifiableCredential", reflect.TypeOf((*MockCredentialAdapterClient)(nil).PresentVerifiableCredential), vp, did, nonce, signature)
}

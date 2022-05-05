// Code generated by MockGen. DO NOT EDIT.
// Source: ./identity/identity.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	crypto "github.com/knox-networks/knox-go/helpers/crypto"
	model "github.com/knox-networks/knox-go/model"
	params "github.com/knox-networks/knox-go/params"
)

// MockIdentityClient is a mock of IdentityClient interface.
type MockIdentityClient struct {
	ctrl     *gomock.Controller
	recorder *MockIdentityClientMockRecorder
}

// MockIdentityClientMockRecorder is the mock recorder for MockIdentityClient.
type MockIdentityClientMockRecorder struct {
	mock *MockIdentityClient
}

// NewMockIdentityClient creates a new mock instance.
func NewMockIdentityClient(ctrl *gomock.Controller) *MockIdentityClient {
	mock := &MockIdentityClient{ctrl: ctrl}
	mock.recorder = &MockIdentityClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIdentityClient) EXPECT() *MockIdentityClientMockRecorder {
	return m.recorder
}

// Generate mocks base method.
func (m *MockIdentityClient) Generate(params *params.GenerateIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Generate", params)
	ret0, _ := ret[0].(*model.DidDocument)
	ret1, _ := ret[1].(*crypto.KeyPairs)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Generate indicates an expected call of Generate.
func (mr *MockIdentityClientMockRecorder) Generate(params interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Generate", reflect.TypeOf((*MockIdentityClient)(nil).Generate), params)
}

// Recover mocks base method.
func (m *MockIdentityClient) Recover(p *params.RecoverIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Recover", p)
	ret0, _ := ret[0].(*model.DidDocument)
	ret1, _ := ret[1].(*crypto.KeyPairs)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Recover indicates an expected call of Recover.
func (mr *MockIdentityClientMockRecorder) Recover(p interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Recover", reflect.TypeOf((*MockIdentityClient)(nil).Recover), p)
}

// Register mocks base method.
func (m *MockIdentityClient) Register(p *params.RegisterIdentityParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Register", p)
	ret0, _ := ret[0].(error)
	return ret0
}

// Register indicates an expected call of Register.
func (mr *MockIdentityClientMockRecorder) Register(p interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Register", reflect.TypeOf((*MockIdentityClient)(nil).Register), p)
}

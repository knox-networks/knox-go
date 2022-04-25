// Code generated by MockGen. DO NOT EDIT.
// Source: ./identity/identity.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
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

// GenerateIdentity mocks base method.
func (m *MockIdentityClient) GenerateIdentity(params params.GenerateIdentityParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateIdentity", params)
	ret0, _ := ret[0].(error)
	return ret0
}

// GenerateIdentity indicates an expected call of GenerateIdentity.
func (mr *MockIdentityClientMockRecorder) GenerateIdentity(params interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateIdentity", reflect.TypeOf((*MockIdentityClient)(nil).GenerateIdentity), params)
}

// RegisterIdentity mocks base method.
func (m *MockIdentityClient) RegisterIdentity(p params.RegisterIdentityParams) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterIdentity", p)
	ret0, _ := ret[0].(error)
	return ret0
}

// RegisterIdentity indicates an expected call of RegisterIdentity.
func (mr *MockIdentityClientMockRecorder) RegisterIdentity(p interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterIdentity", reflect.TypeOf((*MockIdentityClient)(nil).RegisterIdentity), p)
}

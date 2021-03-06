// Code generated by MockGen. DO NOT EDIT.
// Source: ./service/registry_client/registry_client.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockRegistryClient is a mock of RegistryClient interface.
type MockRegistryClient struct {
	ctrl     *gomock.Controller
	recorder *MockRegistryClientMockRecorder
}

// MockRegistryClientMockRecorder is the mock recorder for MockRegistryClient.
type MockRegistryClientMockRecorder struct {
	mock *MockRegistryClient
}

// NewMockRegistryClient creates a new mock instance.
func NewMockRegistryClient(ctrl *gomock.Controller) *MockRegistryClient {
	mock := &MockRegistryClient{ctrl: ctrl}
	mock.recorder = &MockRegistryClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRegistryClient) EXPECT() *MockRegistryClientMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockRegistryClient) Close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close")
}

// Close indicates an expected call of Close.
func (mr *MockRegistryClientMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRegistryClient)(nil).Close))
}

// Create mocks base method.
func (m *MockRegistryClient) Create(did string, doc []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", did, doc)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockRegistryClientMockRecorder) Create(did, doc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockRegistryClient)(nil).Create), did, doc)
}

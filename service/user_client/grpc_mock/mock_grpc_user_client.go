// Code generated by MockGen. DO NOT EDIT.
// Source: go.buf.build/grpc/go/knox-networks/user-mgmt/user_api/v1 (interfaces: UserApiService_CreateRegisterWalletChallengeClient,UserApiServiceClient,UserApiService_CreateAuthnBrowserWithWalletChallengeClient)

// Package grpc_mock is a generated GoMock package.
package grpc_mock

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	user_apiv1 "go.buf.build/grpc/go/knox-networks/user-mgmt/user_api/v1"
	grpc "google.golang.org/grpc"
	metadata "google.golang.org/grpc/metadata"
)

// MockUserApiService_CreateRegisterWalletChallengeClient is a mock of UserApiService_CreateRegisterWalletChallengeClient interface.
type MockUserApiService_CreateRegisterWalletChallengeClient struct {
	ctrl     *gomock.Controller
	recorder *MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder
}

// MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder is the mock recorder for MockUserApiService_CreateRegisterWalletChallengeClient.
type MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder struct {
	mock *MockUserApiService_CreateRegisterWalletChallengeClient
}

// NewMockUserApiService_CreateRegisterWalletChallengeClient creates a new mock instance.
func NewMockUserApiService_CreateRegisterWalletChallengeClient(ctrl *gomock.Controller) *MockUserApiService_CreateRegisterWalletChallengeClient {
	mock := &MockUserApiService_CreateRegisterWalletChallengeClient{ctrl: ctrl}
	mock.recorder = &MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserApiService_CreateRegisterWalletChallengeClient) EXPECT() *MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder {
	return m.recorder
}

// CloseSend mocks base method.
func (m *MockUserApiService_CreateRegisterWalletChallengeClient) CloseSend() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseSend")
	ret0, _ := ret[0].(error)
	return ret0
}

// CloseSend indicates an expected call of CloseSend.
func (mr *MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder) CloseSend() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseSend", reflect.TypeOf((*MockUserApiService_CreateRegisterWalletChallengeClient)(nil).CloseSend))
}

// Context mocks base method.
func (m *MockUserApiService_CreateRegisterWalletChallengeClient) Context() context.Context {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context.
func (mr *MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder) Context() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockUserApiService_CreateRegisterWalletChallengeClient)(nil).Context))
}

// Header mocks base method.
func (m *MockUserApiService_CreateRegisterWalletChallengeClient) Header() (metadata.MD, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Header")
	ret0, _ := ret[0].(metadata.MD)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Header indicates an expected call of Header.
func (mr *MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder) Header() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Header", reflect.TypeOf((*MockUserApiService_CreateRegisterWalletChallengeClient)(nil).Header))
}

// Recv mocks base method.
func (m *MockUserApiService_CreateRegisterWalletChallengeClient) Recv() (*user_apiv1.CreateRegisterWalletChallengeResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Recv")
	ret0, _ := ret[0].(*user_apiv1.CreateRegisterWalletChallengeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Recv indicates an expected call of Recv.
func (mr *MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder) Recv() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Recv", reflect.TypeOf((*MockUserApiService_CreateRegisterWalletChallengeClient)(nil).Recv))
}

// RecvMsg mocks base method.
func (m *MockUserApiService_CreateRegisterWalletChallengeClient) RecvMsg(arg0 interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RecvMsg", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RecvMsg indicates an expected call of RecvMsg.
func (mr *MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder) RecvMsg(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecvMsg", reflect.TypeOf((*MockUserApiService_CreateRegisterWalletChallengeClient)(nil).RecvMsg), arg0)
}

// SendMsg mocks base method.
func (m *MockUserApiService_CreateRegisterWalletChallengeClient) SendMsg(arg0 interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendMsg", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendMsg indicates an expected call of SendMsg.
func (mr *MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder) SendMsg(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMsg", reflect.TypeOf((*MockUserApiService_CreateRegisterWalletChallengeClient)(nil).SendMsg), arg0)
}

// Trailer mocks base method.
func (m *MockUserApiService_CreateRegisterWalletChallengeClient) Trailer() metadata.MD {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trailer")
	ret0, _ := ret[0].(metadata.MD)
	return ret0
}

// Trailer indicates an expected call of Trailer.
func (mr *MockUserApiService_CreateRegisterWalletChallengeClientMockRecorder) Trailer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trailer", reflect.TypeOf((*MockUserApiService_CreateRegisterWalletChallengeClient)(nil).Trailer))
}

// MockUserApiServiceClient is a mock of UserApiServiceClient interface.
type MockUserApiServiceClient struct {
	ctrl     *gomock.Controller
	recorder *MockUserApiServiceClientMockRecorder
}

// MockUserApiServiceClientMockRecorder is the mock recorder for MockUserApiServiceClient.
type MockUserApiServiceClientMockRecorder struct {
	mock *MockUserApiServiceClient
}

// NewMockUserApiServiceClient creates a new mock instance.
func NewMockUserApiServiceClient(ctrl *gomock.Controller) *MockUserApiServiceClient {
	mock := &MockUserApiServiceClient{ctrl: ctrl}
	mock.recorder = &MockUserApiServiceClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserApiServiceClient) EXPECT() *MockUserApiServiceClientMockRecorder {
	return m.recorder
}

// AssociateWallet mocks base method.
func (m *MockUserApiServiceClient) AssociateWallet(arg0 context.Context, arg1 *user_apiv1.AssociateWalletRequest, arg2 ...grpc.CallOption) (*user_apiv1.AssociateWalletResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AssociateWallet", varargs...)
	ret0, _ := ret[0].(*user_apiv1.AssociateWalletResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AssociateWallet indicates an expected call of AssociateWallet.
func (mr *MockUserApiServiceClientMockRecorder) AssociateWallet(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AssociateWallet", reflect.TypeOf((*MockUserApiServiceClient)(nil).AssociateWallet), varargs...)
}

// AuthnBrowserWithWallet mocks base method.
func (m *MockUserApiServiceClient) AuthnBrowserWithWallet(arg0 context.Context, arg1 *user_apiv1.AuthnBrowserWithWalletRequest, arg2 ...grpc.CallOption) (*user_apiv1.AuthnBrowserWithWalletResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AuthnBrowserWithWallet", varargs...)
	ret0, _ := ret[0].(*user_apiv1.AuthnBrowserWithWalletResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthnBrowserWithWallet indicates an expected call of AuthnBrowserWithWallet.
func (mr *MockUserApiServiceClientMockRecorder) AuthnBrowserWithWallet(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthnBrowserWithWallet", reflect.TypeOf((*MockUserApiServiceClient)(nil).AuthnBrowserWithWallet), varargs...)
}

// AuthnWallet mocks base method.
func (m *MockUserApiServiceClient) AuthnWallet(arg0 context.Context, arg1 *user_apiv1.AuthnWalletRequest, arg2 ...grpc.CallOption) (*user_apiv1.AuthnWalletResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AuthnWallet", varargs...)
	ret0, _ := ret[0].(*user_apiv1.AuthnWalletResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthnWallet indicates an expected call of AuthnWallet.
func (mr *MockUserApiServiceClientMockRecorder) AuthnWallet(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthnWallet", reflect.TypeOf((*MockUserApiServiceClient)(nil).AuthnWallet), varargs...)
}

// AuthnWithPassword mocks base method.
func (m *MockUserApiServiceClient) AuthnWithPassword(arg0 context.Context, arg1 *user_apiv1.AuthnWithPasswordRequest, arg2 ...grpc.CallOption) (*user_apiv1.AuthnWithPasswordResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AuthnWithPassword", varargs...)
	ret0, _ := ret[0].(*user_apiv1.AuthnWithPasswordResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthnWithPassword indicates an expected call of AuthnWithPassword.
func (mr *MockUserApiServiceClientMockRecorder) AuthnWithPassword(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthnWithPassword", reflect.TypeOf((*MockUserApiServiceClient)(nil).AuthnWithPassword), varargs...)
}

// AuthnWithProvider mocks base method.
func (m *MockUserApiServiceClient) AuthnWithProvider(arg0 context.Context, arg1 *user_apiv1.AuthnWithProviderRequest, arg2 ...grpc.CallOption) (*user_apiv1.AuthnWithProviderResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "AuthnWithProvider", varargs...)
	ret0, _ := ret[0].(*user_apiv1.AuthnWithProviderResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthnWithProvider indicates an expected call of AuthnWithProvider.
func (mr *MockUserApiServiceClientMockRecorder) AuthnWithProvider(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthnWithProvider", reflect.TypeOf((*MockUserApiServiceClient)(nil).AuthnWithProvider), varargs...)
}

// ConfirmUser mocks base method.
func (m *MockUserApiServiceClient) ConfirmUser(arg0 context.Context, arg1 *user_apiv1.ConfirmUserRequest, arg2 ...grpc.CallOption) (*user_apiv1.ConfirmUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ConfirmUser", varargs...)
	ret0, _ := ret[0].(*user_apiv1.ConfirmUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ConfirmUser indicates an expected call of ConfirmUser.
func (mr *MockUserApiServiceClientMockRecorder) ConfirmUser(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConfirmUser", reflect.TypeOf((*MockUserApiServiceClient)(nil).ConfirmUser), varargs...)
}

// CreateAuthnBrowserWithWalletChallenge mocks base method.
func (m *MockUserApiServiceClient) CreateAuthnBrowserWithWalletChallenge(arg0 context.Context, arg1 *user_apiv1.CreateAuthnBrowserWithWalletChallengeRequest, arg2 ...grpc.CallOption) (user_apiv1.UserApiService_CreateAuthnBrowserWithWalletChallengeClient, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateAuthnBrowserWithWalletChallenge", varargs...)
	ret0, _ := ret[0].(user_apiv1.UserApiService_CreateAuthnBrowserWithWalletChallengeClient)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAuthnBrowserWithWalletChallenge indicates an expected call of CreateAuthnBrowserWithWalletChallenge.
func (mr *MockUserApiServiceClientMockRecorder) CreateAuthnBrowserWithWalletChallenge(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAuthnBrowserWithWalletChallenge", reflect.TypeOf((*MockUserApiServiceClient)(nil).CreateAuthnBrowserWithWalletChallenge), varargs...)
}

// CreateAuthnWalletChallenge mocks base method.
func (m *MockUserApiServiceClient) CreateAuthnWalletChallenge(arg0 context.Context, arg1 *user_apiv1.CreateAuthnWalletChallengeRequest, arg2 ...grpc.CallOption) (*user_apiv1.CreateAuthnWalletChallengeResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateAuthnWalletChallenge", varargs...)
	ret0, _ := ret[0].(*user_apiv1.CreateAuthnWalletChallengeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAuthnWalletChallenge indicates an expected call of CreateAuthnWalletChallenge.
func (mr *MockUserApiServiceClientMockRecorder) CreateAuthnWalletChallenge(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAuthnWalletChallenge", reflect.TypeOf((*MockUserApiServiceClient)(nil).CreateAuthnWalletChallenge), varargs...)
}

// CreateRegisterWalletChallenge mocks base method.
func (m *MockUserApiServiceClient) CreateRegisterWalletChallenge(arg0 context.Context, arg1 *user_apiv1.CreateRegisterWalletChallengeRequest, arg2 ...grpc.CallOption) (user_apiv1.UserApiService_CreateRegisterWalletChallengeClient, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "CreateRegisterWalletChallenge", varargs...)
	ret0, _ := ret[0].(user_apiv1.UserApiService_CreateRegisterWalletChallengeClient)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateRegisterWalletChallenge indicates an expected call of CreateRegisterWalletChallenge.
func (mr *MockUserApiServiceClientMockRecorder) CreateRegisterWalletChallenge(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateRegisterWalletChallenge", reflect.TypeOf((*MockUserApiServiceClient)(nil).CreateRegisterWalletChallenge), varargs...)
}

// DissociateWallet mocks base method.
func (m *MockUserApiServiceClient) DissociateWallet(arg0 context.Context, arg1 *user_apiv1.DissociateWalletRequest, arg2 ...grpc.CallOption) (*user_apiv1.DissociateWalletResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DissociateWallet", varargs...)
	ret0, _ := ret[0].(*user_apiv1.DissociateWalletResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DissociateWallet indicates an expected call of DissociateWallet.
func (mr *MockUserApiServiceClientMockRecorder) DissociateWallet(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DissociateWallet", reflect.TypeOf((*MockUserApiServiceClient)(nil).DissociateWallet), varargs...)
}

// FindByEmail mocks base method.
func (m *MockUserApiServiceClient) FindByEmail(arg0 context.Context, arg1 *user_apiv1.FindByEmailRequest, arg2 ...grpc.CallOption) (*user_apiv1.FindByEmailResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "FindByEmail", varargs...)
	ret0, _ := ret[0].(*user_apiv1.FindByEmailResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindByEmail indicates an expected call of FindByEmail.
func (mr *MockUserApiServiceClientMockRecorder) FindByEmail(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindByEmail", reflect.TypeOf((*MockUserApiServiceClient)(nil).FindByEmail), varargs...)
}

// FindByID mocks base method.
func (m *MockUserApiServiceClient) FindByID(arg0 context.Context, arg1 *user_apiv1.FindByIDRequest, arg2 ...grpc.CallOption) (*user_apiv1.FindByIDResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "FindByID", varargs...)
	ret0, _ := ret[0].(*user_apiv1.FindByIDResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// FindByID indicates an expected call of FindByID.
func (mr *MockUserApiServiceClientMockRecorder) FindByID(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FindByID", reflect.TypeOf((*MockUserApiServiceClient)(nil).FindByID), varargs...)
}

// GetAppSettings mocks base method.
func (m *MockUserApiServiceClient) GetAppSettings(arg0 context.Context, arg1 *user_apiv1.GetAppSettingsRequest, arg2 ...grpc.CallOption) (*user_apiv1.GetAppSettingsResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetAppSettings", varargs...)
	ret0, _ := ret[0].(*user_apiv1.GetAppSettingsResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAppSettings indicates an expected call of GetAppSettings.
func (mr *MockUserApiServiceClientMockRecorder) GetAppSettings(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAppSettings", reflect.TypeOf((*MockUserApiServiceClient)(nil).GetAppSettings), varargs...)
}

// GetMe mocks base method.
func (m *MockUserApiServiceClient) GetMe(arg0 context.Context, arg1 *user_apiv1.GetMeRequest, arg2 ...grpc.CallOption) (*user_apiv1.GetMeResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetMe", varargs...)
	ret0, _ := ret[0].(*user_apiv1.GetMeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMe indicates an expected call of GetMe.
func (mr *MockUserApiServiceClientMockRecorder) GetMe(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMe", reflect.TypeOf((*MockUserApiServiceClient)(nil).GetMe), varargs...)
}

// GetUserByDID mocks base method.
func (m *MockUserApiServiceClient) GetUserByDID(arg0 context.Context, arg1 *user_apiv1.GetUserByDIDRequest, arg2 ...grpc.CallOption) (*user_apiv1.GetUserByDIDResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUserByDID", varargs...)
	ret0, _ := ret[0].(*user_apiv1.GetUserByDIDResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByDID indicates an expected call of GetUserByDID.
func (mr *MockUserApiServiceClientMockRecorder) GetUserByDID(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByDID", reflect.TypeOf((*MockUserApiServiceClient)(nil).GetUserByDID), varargs...)
}

// HandleOIDCCallback mocks base method.
func (m *MockUserApiServiceClient) HandleOIDCCallback(arg0 context.Context, arg1 *user_apiv1.HandleOIDCCallbackRequest, arg2 ...grpc.CallOption) (*user_apiv1.HandleOIDCCallbackResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "HandleOIDCCallback", varargs...)
	ret0, _ := ret[0].(*user_apiv1.HandleOIDCCallbackResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HandleOIDCCallback indicates an expected call of HandleOIDCCallback.
func (mr *MockUserApiServiceClientMockRecorder) HandleOIDCCallback(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleOIDCCallback", reflect.TypeOf((*MockUserApiServiceClient)(nil).HandleOIDCCallback), varargs...)
}

// HandleSAMLCallback mocks base method.
func (m *MockUserApiServiceClient) HandleSAMLCallback(arg0 context.Context, arg1 *user_apiv1.HandleSAMLCallbackRequest, arg2 ...grpc.CallOption) (*user_apiv1.HandleSAMLCallbackResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "HandleSAMLCallback", varargs...)
	ret0, _ := ret[0].(*user_apiv1.HandleSAMLCallbackResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// HandleSAMLCallback indicates an expected call of HandleSAMLCallback.
func (mr *MockUserApiServiceClientMockRecorder) HandleSAMLCallback(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleSAMLCallback", reflect.TypeOf((*MockUserApiServiceClient)(nil).HandleSAMLCallback), varargs...)
}

// RefreshAccessToken mocks base method.
func (m *MockUserApiServiceClient) RefreshAccessToken(arg0 context.Context, arg1 *user_apiv1.RefreshAccessTokenRequest, arg2 ...grpc.CallOption) (*user_apiv1.RefreshAccessTokenResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "RefreshAccessToken", varargs...)
	ret0, _ := ret[0].(*user_apiv1.RefreshAccessTokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RefreshAccessToken indicates an expected call of RefreshAccessToken.
func (mr *MockUserApiServiceClientMockRecorder) RefreshAccessToken(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RefreshAccessToken", reflect.TypeOf((*MockUserApiServiceClient)(nil).RefreshAccessToken), varargs...)
}

// RegisterUser mocks base method.
func (m *MockUserApiServiceClient) RegisterUser(arg0 context.Context, arg1 *user_apiv1.RegisterUserRequest, arg2 ...grpc.CallOption) (*user_apiv1.RegisterUserResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "RegisterUser", varargs...)
	ret0, _ := ret[0].(*user_apiv1.RegisterUserResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RegisterUser indicates an expected call of RegisterUser.
func (mr *MockUserApiServiceClientMockRecorder) RegisterUser(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterUser", reflect.TypeOf((*MockUserApiServiceClient)(nil).RegisterUser), varargs...)
}

// RegisterWallet mocks base method.
func (m *MockUserApiServiceClient) RegisterWallet(arg0 context.Context, arg1 *user_apiv1.RegisterWalletRequest, arg2 ...grpc.CallOption) (*user_apiv1.RegisterWalletResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "RegisterWallet", varargs...)
	ret0, _ := ret[0].(*user_apiv1.RegisterWalletResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RegisterWallet indicates an expected call of RegisterWallet.
func (mr *MockUserApiServiceClientMockRecorder) RegisterWallet(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterWallet", reflect.TypeOf((*MockUserApiServiceClient)(nil).RegisterWallet), varargs...)
}

// SAMLSPMetadata mocks base method.
func (m *MockUserApiServiceClient) SAMLSPMetadata(arg0 context.Context, arg1 *user_apiv1.SAMLSPMetadataRequest, arg2 ...grpc.CallOption) (*user_apiv1.SAMLSPMetadataResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "SAMLSPMetadata", varargs...)
	ret0, _ := ret[0].(*user_apiv1.SAMLSPMetadataResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SAMLSPMetadata indicates an expected call of SAMLSPMetadata.
func (mr *MockUserApiServiceClientMockRecorder) SAMLSPMetadata(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SAMLSPMetadata", reflect.TypeOf((*MockUserApiServiceClient)(nil).SAMLSPMetadata), varargs...)
}

// MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient is a mock of UserApiService_CreateAuthnBrowserWithWalletChallengeClient interface.
type MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient struct {
	ctrl     *gomock.Controller
	recorder *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder
}

// MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder is the mock recorder for MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient.
type MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder struct {
	mock *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient
}

// NewMockUserApiService_CreateAuthnBrowserWithWalletChallengeClient creates a new mock instance.
func NewMockUserApiService_CreateAuthnBrowserWithWalletChallengeClient(ctrl *gomock.Controller) *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient {
	mock := &MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient{ctrl: ctrl}
	mock.recorder = &MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient) EXPECT() *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder {
	return m.recorder
}

// CloseSend mocks base method.
func (m *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient) CloseSend() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseSend")
	ret0, _ := ret[0].(error)
	return ret0
}

// CloseSend indicates an expected call of CloseSend.
func (mr *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder) CloseSend() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseSend", reflect.TypeOf((*MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient)(nil).CloseSend))
}

// Context mocks base method.
func (m *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient) Context() context.Context {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context.
func (mr *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder) Context() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient)(nil).Context))
}

// Header mocks base method.
func (m *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient) Header() (metadata.MD, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Header")
	ret0, _ := ret[0].(metadata.MD)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Header indicates an expected call of Header.
func (mr *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder) Header() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Header", reflect.TypeOf((*MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient)(nil).Header))
}

// Recv mocks base method.
func (m *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient) Recv() (*user_apiv1.CreateAuthnBrowserWithWalletChallengeResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Recv")
	ret0, _ := ret[0].(*user_apiv1.CreateAuthnBrowserWithWalletChallengeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Recv indicates an expected call of Recv.
func (mr *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder) Recv() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Recv", reflect.TypeOf((*MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient)(nil).Recv))
}

// RecvMsg mocks base method.
func (m *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient) RecvMsg(arg0 interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RecvMsg", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RecvMsg indicates an expected call of RecvMsg.
func (mr *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder) RecvMsg(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecvMsg", reflect.TypeOf((*MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient)(nil).RecvMsg), arg0)
}

// SendMsg mocks base method.
func (m *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient) SendMsg(arg0 interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendMsg", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendMsg indicates an expected call of SendMsg.
func (mr *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder) SendMsg(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMsg", reflect.TypeOf((*MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient)(nil).SendMsg), arg0)
}

// Trailer mocks base method.
func (m *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient) Trailer() metadata.MD {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Trailer")
	ret0, _ := ret[0].(metadata.MD)
	return ret0
}

// Trailer indicates an expected call of Trailer.
func (mr *MockUserApiService_CreateAuthnBrowserWithWalletChallengeClientMockRecorder) Trailer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Trailer", reflect.TypeOf((*MockUserApiService_CreateAuthnBrowserWithWalletChallengeClient)(nil).Trailer))
}

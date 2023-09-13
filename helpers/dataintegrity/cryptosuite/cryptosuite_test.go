package cryptosuite

import (
	"testing"
)

func TestProofPresentation_HasMatchVerificationMethod(t *testing.T) {
	type fields struct {
		Id         string
		Method     interface{}
		PrivateKey PrivateKey
	}
	type args struct {
		vm interface{}
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "true - Ed25519",
			fields: fields{
				Id: "abc",
				Method: Ed25519Signature2020{
					Id:   "abc",
					Type: "Ed25519Signature2020",
				},
			},
			args: args{
				vm: Ed25519VerificationKey2020{
					Id:   "abc",
					Type: "Ed25519VerificationKey2020",
				},
			},
			want: true,
		},
		{
			name: "true - JsonWeb",
			fields: fields{
				Id: "abc",
				Method: JSONWebSignature2020{
					Type: "JSONWebSignature2020",
				},
			},
			args: args{
				vm: JsonWebKey2020{
					Id:   "abc",
					Type: "JsonWebKey2020",
				},
			},
			want: true,
		},
		{
			name: "false - Mismatch",
			fields: fields{
				Id: "abc",
				Method: JSONWebSignature2020{
					Type: "JSONWebSignature2020",
				},
			},
			args: args{
				vm: Ed25519VerificationKey2020{
					Id:   "abc",
					Type: "Ed25519VerificationKey2020",
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ProofPresentation{
				Method:     tt.fields.Method,
				PrivateKey: tt.fields.PrivateKey,
			}
			if got := p.HasMatchVerificationMethod(tt.args.vm); got != tt.want {
				t.Errorf("ProofPresentation.HasMatchVerificationMethod() = %v, want %v", got, tt.want)
			}
		})
	}
}

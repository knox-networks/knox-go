package knox

import "errors"

type RegisterIdentityParams struct {
}

type GenerateIdentityParams struct{}

func (c *knoxClient) RegisterIdentity(params RegisterIdentityParams) error {
	return errors.New("not implemented")
}

func (c *knoxClient) GenerateIdentity(params GenerateIdentityParams) error {
	return errors.New("not implemented")
}

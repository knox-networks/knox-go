package knox

import "errors"

type RegisterIdentityParams struct {
}

type GenerateIdentityParams struct {
}

func (c *KnoxClient) RegisterIdentity(params RegisterIdentityParams) error {
	return errors.New("not implemented")
}

func (c *KnoxClient) GenerateIdentity(params GenerateIdentityParams) error {
	return errors.New("not implemented")
}

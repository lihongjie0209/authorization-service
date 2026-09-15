package routepolicy

type PermissionInput struct {
	Key      string `json:"key" db:"key"`
	Resource string `json:"resource" db:"resource"`
	Action   string `json:"action" db:"action"`
	Scope    string `json:"scope" db:"scope"`
}

type SetInput struct {
	RouteID, Expression, Description, Status string
	ExpectedVersion                          int64
	Permissions                              []PermissionInput
}

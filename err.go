package gopenflow

import (
	"fmt"
)

type SysError struct {
	Err   error
	Stack []byte
}

func (self SysError) Error() string {
	return fmt.Sprintf("SysError with Stack: %s\n%s",
		self.Err,
		string(self.Stack),
	)
}

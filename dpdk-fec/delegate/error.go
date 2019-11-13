package delegate

type delegateError struct {
    s string
}

func (e delegateError) Error() string {
    return e.s
}

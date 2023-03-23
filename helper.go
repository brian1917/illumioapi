package illumioapi

// PtrToVal returns the value of a pointer
// If the pointer is nil, a blank value is returned
func PtrToVal[T any](ptr *T) T {
	if ptr == nil {
		var t T
		return t
	}
	return *ptr
}

// Ptr returns a pointer to any object
func Ptr[T any](v T) *T {
	return &v
}

package illumioapi

func ptrToStr(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

func ptrToSlice[T any](slice *[]T) []T {
	if slice == nil {
		return []T{}
	}
	return *slice
}

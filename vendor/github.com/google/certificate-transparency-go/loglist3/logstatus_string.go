// Code generated by "stringer -type=LogStatus"; DO NOT EDIT.

package loglist3

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[UndefinedLogStatus-0]
	_ = x[PendingLogStatus-1]
	_ = x[QualifiedLogStatus-2]
	_ = x[UsableLogStatus-3]
	_ = x[ReadOnlyLogStatus-4]
	_ = x[RetiredLogStatus-5]
	_ = x[RejectedLogStatus-6]
}

const _LogStatus_name = "UndefinedLogStatusPendingLogStatusQualifiedLogStatusUsableLogStatusReadOnlyLogStatusRetiredLogStatusRejectedLogStatus"

var _LogStatus_index = [...]uint8{0, 18, 34, 52, 67, 84, 100, 117}

func (i LogStatus) String() string {
	if i < 0 || i >= LogStatus(len(_LogStatus_index)-1) {
		return "LogStatus(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _LogStatus_name[_LogStatus_index[i]:_LogStatus_index[i+1]]
}

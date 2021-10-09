// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package limits

import "testing"

func TestGetFileLimit(t *testing.T) {
	if r := GetFileLimit(); r <= 0 {
		t.Errorf("Returned a non-positive limit")
	}
}

/*
Copyright (c) Facebook, Inc. and its affiliates.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package timestamp

import (
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// unix.Cmsghdr size differs depending on platform
var socketControlMessageHeaderOffset = binary.Size(unix.Cmsghdr{})

var timestamping = unix.SO_TIMESTAMP

// Here we have basic HW and SW timestamping support

// byteToTime converts LittleEndian bytes into a timestamp
func byteToTime(data []byte) (time.Time, error) {
	// freebsd supports only SO_TIMESTAMP mode, which returns timeval
	timeval := (*unix.Timeval)(unsafe.Pointer(&data))
	return time.Unix(timeval.Unix()), nil
}

/*
scmDataToTime parses SocketControlMessage Data field into time.Time.
*/
func scmDataToTime(data []byte) (ts time.Time, err error) {
	size := binary.Size(unix.Timeval{})

	ts, err = byteToTime(data[0:size])
	if err != nil {
		return ts, err
	}
	if ts.UnixNano() == 0 {
		return ts, fmt.Errorf("got zero timestamp")
	}

	return ts, nil
}

// socketControlMessageTimestamp is a very optimised version of ParseSocketControlMessage
// https://github.com/golang/go/blob/2ebe77a2fda1ee9ff6fd9a3e08933ad1ebaea039/src/syscall/sockcmsg_unix.go#L40
// which only parses the timestamp message type.
func socketControlMessageTimestamp(b []byte) (time.Time, error) {
	mlen := 0
	for i := 0; i < len(b); i += mlen {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[i]))
		mlen = int(h.Len)

		if h.Level == unix.SOL_SOCKET && int(h.Type) == timestamping {
			return scmDataToTime(b[i+socketControlMessageHeaderOffset : i+mlen])
		}
	}
	return time.Time{}, fmt.Errorf("failed to find timestamp in socket control message")
}

// EnableSWTimestampsRx enables SW RX timestamps on the socket
func EnableSWTimestampsRx(connFd int) error {
	// Allow reading of SW timestamps via socket
	return unix.SetsockoptInt(connFd, unix.SOL_SOCKET, timestamping, 1)
}

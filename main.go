package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// IsFile 	判断是否为文件
//
//	@param path
//	@return bool
func IsFile(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}

	if fi.IsDir() {
		return false
	}

	return true
}

func containsChinese(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// getEthernetData 获取链路层数据
//
//	@param packet
//	@return []byte
func getEthernetData(packet gopacket.Packet) []byte {
	return packet.LinkLayer().LayerContents()
}

// getGtpPayloadData 获取Gtp层负载（gtp隧道报文）或者链路层负载（非gtp报文）
//
//	@param packet
//	@return []byte
func getGtpPayloadData(packet gopacket.Packet) []byte {
	gtpLayer := packet.Layer(layers.LayerTypeGTPv1U)
	if gtpLayer == nil {
		return packet.LinkLayer().LayerPayload()
	}
	return gtpLayer.LayerPayload()
}

// striperGtpPacket 剥离gtp头部信息
//
//	@param packet
//	@param fw
//	@return bool
func striperGtpPacket(packet gopacket.Packet, fw *pcapgo.Writer) bool {
	var buffer []byte
	ethdata := getEthernetData(packet)
	buffer = append(buffer, ethdata...)

	gtpPayload := getGtpPayloadData(packet)
	buffer = append(buffer, gtpPayload...)

	captureInfo := gopacket.CaptureInfo{
		Timestamp:     packet.Metadata().Timestamp,
		CaptureLength: len(buffer),
		Length:        len(buffer),
	}

	err := fw.WritePacket(captureInfo, buffer)
	if err != nil {
		log.Printf("写入失败：%v\n", err)
		return false
	}

	return true
}

// isPcapFile 校验是否为pcap文件，当前只检测支持".pcap"和".pcapng"后缀
//
//	@param name
//	@return bool
func isPcapFile(name string) bool {
	if strings.HasSuffix(name, "pcap") {
		return true
	}

	if strings.HasSuffix(name, "pcapng") {
		return true
	}
	return false
}

var (
	PcapFile   = flag.String("p", "", "pcap报文路径或文件")
	OutputPath = flag.String("o", "./output", "pcap报文生成路径")
)

// striperGtpFile 处理gtp报文
//
//	@param pcapfile	pcap文件路径或文件
//	@param outpath	报文输出路径
func striperGtpFile(pcapfile, outpath string) {
	bn := filepath.Base(pcapfile)
	dn := filepath.Join(outpath, "gtp_striper_"+bn)

	if ispcap := isPcapFile(bn); !ispcap {
		return
	}

	//写文件准备
	f, err := os.Create(dn)
	if err != nil {
		log.Printf("创建文件失败：%v\n", err)
		return
	}
	defer f.Close()
	fw := pcapgo.NewWriter(f)
	fw.WriteFileHeader(65536, layers.LinkTypeEthernet) // new file, must do this.

	//读文件
	handle, err := pcap.OpenOffline(pcapfile)
	if err != nil {
		log.Printf("打开pcap文件失败：%v\n", err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		striperGtpPacket(packet, fw)
	}

	log.Printf("生成pcap报文：%s\n", dn)
}

// prepareEnv 删除旧目录，创建新目录
//
//	@param path
func prepareEnv(path string) {
	os.RemoveAll(path)
	os.Mkdir(path, 0666)
}

func main() {
	flag.Parse()
	if *PcapFile == "" {
		flag.Usage()
		return
	}

	prepareEnv(*OutputPath)

	if ok := IsFile(*PcapFile); ok {
		striperGtpFile(*PcapFile, *OutputPath)
		return
	}

	filepath.WalkDir(*PcapFile, func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("filepath walk failed:%v\n", err)
			return err
		}

		if !d.IsDir() {
			striperGtpFile(dir, *OutputPath)
		}
		return nil
	})
}

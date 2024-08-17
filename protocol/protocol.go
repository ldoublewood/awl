package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/mr-tron/base58"
	"io"

	"github.com/libp2p/go-libp2p/core/protocol"
)

const (
	Version  = "0.3.0"
	basePath = "/awl/" + Version

	AuthMethod         protocol.ID = basePath + "/auth/"
	GetStatusMethod    protocol.ID = basePath + "/status/"
	TunnelPacketMethod protocol.ID = basePath + "/tunnel/"
)

type (
	PeerStatusInfo struct {
		Name                 string
		Declined             bool
		AllowUsingAsExitNode bool
	}
)

func ReceiveStatus(stream io.Reader) (PeerStatusInfo, error) {
	statusInfo := PeerStatusInfo{}
	err := json.NewDecoder(stream).Decode(&statusInfo)
	return statusInfo, err
}

func SendStatus(stream io.Writer, statusInfo PeerStatusInfo) error {
	err := json.NewEncoder(stream).Encode(&statusInfo)
	return err
}

type AuthInfo struct {
	//"v1:" + random string (size: 16, should not contain '|' and '{' and '}')
	Nonce string
	// for request: hmac('{' + my peer ID (base58) + '|' + 'remote peer ID(base58) + '|' + my Nonce + '}')
	// for response: hmac('{' + my peer ID (base58) + '|' + 'remote peer ID(base58) + '|' + my Nonce + '|' + remote Nonce + '}')
	Sign string
}
type AuthPeer struct {
	AuthInfo
	Name string
}

type AuthPeerResponse struct {
	AuthInfo
	Confirmed bool
	Declined  bool
}

func genNonce() (string, error) {
	Head := "v1:"
	nonce := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	nonceBase16 := hex.EncodeToString(nonce)
	return Head + nonceBase16, nil
}
func genHmacSign(message string, key string) (string, error) {
	hash := hmac.New(sha256.New, []byte(key))
	_, err := hash.Write([]byte(message))
	if err != nil {
		return "", err
	}
	hmacSign := hash.Sum(nil)
	hmacString := base58.Encode(hmacSign)
	return hmacString, nil
}

// CheckAuthInfo string is raw message to sign, used for debug
func CheckAuthInfo(authInfo AuthInfo, myPeerId, remotePeerId string, remoteNonce *string, key *string) (bool, string, error) {
	if key == nil {
		//no key (rendezvous), means check pass
		return true, "", nil
	}
	sign, message, errGen := genAuthHmacSign(myPeerId, remotePeerId, authInfo.Nonce, remoteNonce, *key)
	if errGen != nil {
		return false, message, errGen
	}
	return sign == authInfo.Sign, message, nil
}

func GenAuthInfo(myPeerId, remotePeerId string, remoteNonce *string, key *string) (AuthInfo, string, error) {
	if key == nil {
		return AuthInfo{}, "", nil
	}
	nonce, err := genNonce()
	if err != nil {
		return AuthInfo{}, "", err
	}

	sign, message, errGen := genAuthHmacSign(myPeerId, remotePeerId, nonce, remoteNonce, *key)
	if errGen != nil {
		return AuthInfo{}, message, errGen
	}

	return AuthInfo{
		Nonce: nonce,
		Sign:  sign,
	}, message, nil
}

func genAuthHmacSign(myPeerId string, remotePeerId, myNonce string, remoteNonce *string, key string) (string, string, error) {
	var message string
	if remoteNonce == nil {
		message = "{" + myPeerId + "|" + remotePeerId + "|" + myNonce + "}"
	} else {
		message = "{" + myPeerId + "|" + remotePeerId + "|" + myNonce + "|" + *remoteNonce + "}"
	}
	sign, err := genHmacSign(message, key)
	return sign, message, err
}

func ReceiveAuth(stream io.Reader) (AuthPeer, error) {
	authPeer := AuthPeer{}
	err := json.NewDecoder(stream).Decode(&authPeer)
	return authPeer, err
}

func SendAuth(stream io.Writer, authPeer AuthPeer) error {
	err := json.NewEncoder(stream).Encode(&authPeer)
	return err
}

func ReceiveAuthResponse(stream io.Reader) (AuthPeerResponse, error) {
	response := AuthPeerResponse{}
	err := json.NewDecoder(stream).Decode(&response)
	return response, err
}

func SendAuthResponse(stream io.Writer, response AuthPeerResponse) error {
	err := json.NewEncoder(stream).Encode(&response)
	return err
}

func ReadUint64(stream io.Reader) (uint64, error) {
	var data [8]byte
	n, err := io.ReadFull(stream, data[:])
	if err != nil {
		return 0, err
	}
	if n != 8 {
		return 0, fmt.Errorf("invalid uint64 data: %v. read %d instead of 8", data, n)
	}

	value := binary.BigEndian.Uint64(data[:])
	return value, nil
}

func WritePacketToBuf(buf, packet []byte) []byte {
	const lenBytesCount = 8
	binary.BigEndian.PutUint64(buf, uint64(len(packet)))
	n := copy(buf[lenBytesCount:], packet)

	return buf[:lenBytesCount+n]
}
